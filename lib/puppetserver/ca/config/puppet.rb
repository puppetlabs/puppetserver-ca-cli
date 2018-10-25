require 'puppetserver/ca/utils/config'
require 'securerandom'
require 'facter'

module Puppetserver
  module Ca
    module Config
      # Provides an interface for asking for Puppet settings w/o loading
      # Puppet. Includes a simple ini parser that will ignore Puppet's
      # more complicated conventions.
      class Puppet
        # How we convert from various units to seconds.
        TTL_UNITMAP = {
          # 365 days isn't technically a year, but is sufficient for most purposes
          "y" => 365 * 24 * 60 * 60,
          "d" => 24 * 60 * 60,
          "h" => 60 * 60,
          "m" => 60,
          "s" => 1
        }

        # A regex describing valid formats with groups for capturing the value and units
        TTL_FORMAT = /^(\d+)(y|d|h|m|s)?$/

        def self.parse(config_path)
          instance = new(config_path)
          instance.load

          return instance
        end

        attr_reader :errors, :settings

        def initialize(supplied_config_path = nil)
          @using_default_location = !supplied_config_path
          @config_path = supplied_config_path || user_specific_conf_file

          @settings = nil
          @errors = []
        end

        # Return the correct confdir. We check for being root on *nix,
        # else the user path. We do not include a check for running
        # as Adminstrator since non-development scenarios for Puppet Server
        # on Windows are unsupported.
        # Note that Puppet Server runs as the [pe-]puppet user but to
        # start/stop it you must be root.
        def user_specific_conf_dir
          @user_specific_conf_dir ||=
            if Puppetserver::Ca::Utils::Config.running_as_root?
              '/etc/puppetlabs/puppet'
            else
              "#{ENV['HOME']}/.puppetlabs/etc/puppet"
            end
        end

        def user_specific_conf_file
          user_specific_conf_dir + '/puppet.conf'
        end

        def load(cli_overrides = {})
          if explicitly_given_config_file_or_default_config_exists?
            results = parse_text(File.read(@config_path))
          end

          results ||= {}
          results[:main] ||= {}
          results[:master] ||= {}

          overrides = results[:main].merge(results[:master])
          overrides.merge!(cli_overrides)

          @settings = resolve_settings(overrides).freeze
        end

        def default_certname
          @certname ||=
            hostname = Facter.value(:hostname)
            domain = Facter.value(:domain)
            if domain and domain != ''
              fqdn = [hostname, domain].join('.')
            else
              fqdn = hostname
            end
            fqdn.chomp('.')
        end

        # Resolve settings from default values, with any overrides for the
        # specific settings or their dependent settings (ssldir, cadir) taken into account.
        def resolve_settings(overrides = {})
          unresolved_setting = /\$[a-z_]+/

          # Returning the key for unknown keys (rather than nil) is required to
          # keep unknown settings in the string for later verification.
          substitutions = Hash.new {|h, k| k }
          settings = {}

          # Order for base settings here matters!
          # These need to be evaluated before we can construct their dependent
          # defaults below
          base_defaults = [
            [:confdir, user_specific_conf_dir],
            [:ssldir,'$confdir/ssl'],
            [:cadir, '$ssldir/ca'],
            [:certdir, '$ssldir/certs'],
            [:certname, default_certname],
            [:server, 'puppet'],
            [:masterport, '8140'],
            [:privatekeydir, '$ssldir/private_keys'],
            [:publickeydir, '$ssldir/public_keys'],
          ]

          dependent_defaults = {
            :ca_name => 'Puppet CA: $certname',
            :root_ca_name => "Puppet Root CA: #{SecureRandom.hex(7)}",
            :keylength => 4096,
            :cacert => '$cadir/ca_crt.pem',
            :cakey => '$cadir/ca_key.pem',
            :capub => '$cadir/ca_pub.pem',
            :csr_attributes => '$confdir/csr_attributes.yaml',
            :rootkey => '$cadir/root_key.pem',
            :cacrl => '$cadir/ca_crl.pem',
            :serial => '$cadir/serial',
            :cert_inventory => '$cadir/inventory.txt',
            :ca_server => '$server',
            :ca_port => '$masterport',
            :localcacert => '$certdir/ca.pem',
            :hostcrl => '$ssldir/crl.pem',
            :hostcert => '$certdir/$certname.pem',
            :hostprivkey => '$privatekeydir/$certname.pem',
            :hostpubkey => '$publickeydir/$certname.pem',
            :ca_ttl => '15y',
            :certificate_revocation => 'true',
            :signeddir => '$cadir/signed',
          }

          # This loops through the base defaults and gives each setting a
          # default if the value isn't specified in the config file. Default
          # values given may depend upon the value of a previous base setting,
          # thus the creation of the substitution hash.
          base_defaults.each do |setting_name, default_value|
            substitution_name = '$' + setting_name.to_s
            setting_value = overrides.fetch(setting_name, default_value)
            subbed_value = setting_value.sub(unresolved_setting, substitutions)
            settings[setting_name] = substitutions[substitution_name] = subbed_value
          end

          dependent_defaults.each do |setting_name, default_value|
            setting_value = overrides.fetch(setting_name, default_value)
            settings[setting_name] = setting_value
          end

          # If subject-alt-names are provided, we need to add the certname in addition
          overrides[:dns_alt_names] << ',$certname' if overrides[:dns_alt_names]

          # rename dns_alt_names to subject_alt_names now that we support IP alt names
          settings[:subject_alt_names] = overrides.fetch(:dns_alt_names, "")

          # Some special cases where we need to manipulate config settings:
          settings[:ca_ttl] = munge_ttl_setting(settings[:ca_ttl])
          settings[:certificate_revocation] = parse_crl_usage(settings[:certificate_revocation])
          settings[:subject_alt_names] = Puppetserver::Ca::Utils::Config.munge_alt_names(settings[:subject_alt_names])
          settings[:keylength] = settings[:keylength].to_i

          settings.each do |key, value|
            next unless value.is_a? String
            settings[key] = value.gsub(unresolved_setting, substitutions)
            if match = settings[key].match(unresolved_setting)
              @errors << "Could not parse #{match[0]} in #{value}, " +
                         'valid settings to be interpolated are ' +
                         '$ssldir, $certdir, $cadir, $certname, $server, or $masterport'
            end
          end

          return settings
        end

        # Parse an inifile formatted String. Only captures \word character
        # class keys/section names but nearly any character values (excluding
        # leading whitespace) up to one of whitespace, opening curly brace, or
        # hash sign (Our concern being to capture filesystem path values).
        # Put values without a section into :main.
        #
        # Return Hash of Symbol section names with Symbol setting keys and
        # String values.
        def parse_text(text)
          res = {}
          current_section = :main
          text.each_line do |line|
            case line
            when /^\s*\[(\w+)\].*/
              current_section = $1.to_sym
            when /^\s*(\w+)\s*=\s*([^\s{#]+).*$/
              # Using a Hash with a default key breaks RSpec expectations.
              res[current_section] ||= {}
              res[current_section][$1.to_sym] = $2
            end
          end

          res
        end

       private

        def explicitly_given_config_file_or_default_config_exists?
          !@using_default_location || File.exist?(@config_path)
        end

        def run(command)
          %x( #{command} )
        end

        # Convert the value to Numeric, parsing numeric string with units if necessary.
        def munge_ttl_setting(ca_ttl_setting)
          case
          when ca_ttl_setting.is_a?(Numeric)
            if ca_ttl_setting < 0
              @errors << "Invalid negative 'time to live' #{ca_ttl_setting.inspect} - did you mean 'unlimited'?"
            end
            ca_ttl_setting

          when ca_ttl_setting == 'unlimited'
            Float::INFINITY

          when (ca_ttl_setting.is_a?(String) and ca_ttl_setting =~ TTL_FORMAT)
            $1.to_i * TTL_UNITMAP[$2 || 's']
          else
            @errors <<  "Invalid 'time to live' format '#{ca_ttl_setting.inspect}' for parameter: :ca_ttl"
          end
        end

        def parse_crl_usage(setting)
          case setting.to_s
          when 'true', 'chain'
            :chain
          when 'leaf'
            :leaf
          when 'false'
            :ignore
          end
        end
      end
    end
  end
end
