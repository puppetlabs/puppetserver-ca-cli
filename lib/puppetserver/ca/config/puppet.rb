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
        include Puppetserver::Ca::Utils::Config

        def self.parse(config_path)
          instance = new(config_path)
          instance.load

          return instance
        end

        attr_reader :errors, :settings, :valid_settings

        def initialize(supplied_config_path = nil)
          @using_default_location = !supplied_config_path
          @config_path = supplied_config_path || user_specific_conf_file

          @settings = nil
          @errors = []
          @valid_settings = []

          # Order for base settings here matters!
          # These need to be evaluated before we can construct their dependent
          # defaults below
          @base_defaults = [
            [:confdir, user_specific_conf_dir],
            [:ssldir,'$confdir/ssl'],
            [:certdir, '$ssldir/certs'],
            [:certname, default_certname],
            [:server, '$certname'],
            [:masterport, '8140'],
            [:privatekeydir, '$ssldir/private_keys'],
            [:publickeydir, '$ssldir/public_keys'],
          ]
          @dependent_defaults = {
            :keylength => 4096,
            :ca_server => '$server',
            :ca_port => '$masterport',
            :localcacert => '$certdir/ca.pem',
            :hostcrl => '$ssldir/crl.pem',
            :hostcert => '$certdir/$certname.pem',
            :hostprivkey => '$privatekeydir/$certname.pem',
            :hostpubkey => '$publickeydir/$certname.pem',
            :publickeydir => '$ssldir/public_keys',
            :certificate_revocation => 'true',
          }

          @base_defaults.each do |item|
            @valid_settings << item.first
          end
          @valid_settings += @dependent_defaults.keys
          # Puppet calls this dns_alt_names, but we want to call it subject_alt_names,
          # so it has to be added outside of the defaults lists
          @valid_settings << :dns_alt_names
        end

        # Return the correct confdir. We check for being root on *nix,
        # else the user path. We do not include a check for running
        # as Adminstrator since non-development scenarios for Puppet Server
        # on Windows are unsupported.
        # Note that Puppet Server runs as the [pe-]puppet user but to
        # start/stop it you must be root.
        def user_specific_conf_dir
          @user_specific_conf_dir ||=
            if running_as_root?
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

          # This loops through the base defaults and gives each setting a
          # default if the value isn't specified in the config file. Default
          # values given may depend upon the value of a previous base setting,
          # thus the creation of the substitution hash.
          @base_defaults.each do |setting_name, default_value|
            substitution_name = '$' + setting_name.to_s
            setting_value = overrides.fetch(setting_name, default_value)
            subbed_value = setting_value.sub(unresolved_setting, substitutions)
            settings[setting_name] = substitutions[substitution_name] = subbed_value
          end

          @dependent_defaults.each do |setting_name, default_value|
            setting_value = overrides.fetch(setting_name, default_value)
            settings[setting_name] = setting_value
          end

          # rename dns_alt_names to subject_alt_names now that we support IP alt names
          settings[:subject_alt_names] = overrides.fetch(:dns_alt_names, "puppet,$certname")

          # Some special cases where we need to manipulate config settings:
          settings[:certificate_revocation] = parse_crl_usage(settings[:certificate_revocation])
          settings[:subject_alt_names] = munge_alt_names(settings[:subject_alt_names])

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

        def munge_alt_names(names)
          raw_names = names.split(/\s*,\s*/).map(&:strip)
          munged_names = raw_names.map do |name|
            # Prepend the DNS tag if no tag was specified
            if !name.start_with?("IP:") && !name.start_with?("DNS:")
              "DNS:#{name}"
            else
              name
            end
          end.sort.uniq.join(", ")
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
