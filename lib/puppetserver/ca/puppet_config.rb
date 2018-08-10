require 'puppetserver/ca/config_utils'
require 'puppetserver/settings/ttl_setting'
require 'securerandom'
require 'facter'

module Puppetserver
  module Ca
    # Provides an interface for asking for Puppet settings w/o loading
    # Puppet. Includes a simple ini parser that will ignore Puppet's
    # more complicated conventions.
    class PuppetConfig

      include Puppetserver::Ca::ConfigUtils

      def self.parse(config_path = nil)
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
        if running_as_root?
          '/etc/puppetlabs/puppet'
        else
          "#{ENV['HOME']}/.puppetlabs/etc/puppet"
        end
      end

      def user_specific_conf_file
        user_specific_conf_dir + '/puppet.conf'
      end

      def load
        if explicitly_given_config_file_or_default_config_exists?
          results = parse_text(File.read(@config_path))
        end

        @certname = default_certname

        results ||= {}
        results[:main] ||= {}
        results[:master] ||= {}

        overrides = results[:main].merge(results[:master])

        @settings = resolve_settings(overrides).freeze
      end

      def default_certname
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

        confdir = user_specific_conf_dir
        settings[:confdir] = substitutions['$confdir'] = confdir

        ssldir = overrides.fetch(:ssldir, '$confdir/ssl')
        settings[:ssldir] = substitutions['$ssldir'] = ssldir.sub('$confdir', confdir)

        certdir = overrides.fetch(:certdir, '$ssldir/certs')
        settings[:certdir] = substitutions['$certdir'] = certdir.sub(unresolved_setting, substitutions)

        cadir = overrides.fetch(:cadir, '$ssldir/ca')
        settings[:cadir] = substitutions['$cadir'] = cadir.sub(unresolved_setting, substitutions)

        settings[:certname] = substitutions['$certname'] = overrides.fetch(:certname, @certname)

        server = overrides.fetch(:server, '$certname')
        settings[:server] = substitutions['$server'] = server.sub(unresolved_setting, substitutions)

        settings[:masterport] = substitutions['$masterport'] = overrides.fetch(:masterport, '8140')

        settings[:ca_name] =  overrides.fetch(:ca_name, 'Puppet CA: $certname')
        settings[:root_ca_name] = overrides.fetch(:root_ca_name, "Puppet Root CA: #{SecureRandom.hex(7)}")

        unmunged_ca_ttl =  overrides.fetch(:ca_ttl, '15y')
        ttl_setting = Puppetserver::Settings::TTLSetting.new(:ca_ttl, unmunged_ca_ttl)
        if ttl_setting.errors
          ttl_setting.errors.each { |error| @errors << error }
        end

        settings[:ca_ttl] =         ttl_setting.munged_value
        settings[:keylength] =      overrides.fetch(:keylength, 4096)
        settings[:cacert] =         overrides.fetch(:cacert, '$cadir/ca_crt.pem')
        settings[:cakey] =          overrides.fetch(:cakey, '$cadir/ca_key.pem')
        settings[:rootkey] =        overrides.fetch(:rootkey, '$cadir/root_key.pem')
        settings[:cacrl] =          overrides.fetch(:cacrl, '$cadir/ca_crl.pem')
        settings[:serial] =         overrides.fetch(:serial, '$cadir/serial')
        settings[:cert_inventory] = overrides.fetch(:cert_inventory, '$cadir/inventory.txt')
        settings[:ca_server] =      overrides.fetch(:ca_server, '$server')
        settings[:ca_port] =        overrides.fetch(:ca_port, '$masterport')
        settings[:localcacert] =    overrides.fetch(:localcacert, '$certdir/ca.pem')
        settings[:hostcert] =       overrides.fetch(:hostcert, '$certdir/$certname.pem')
        settings[:hostcrl] =        overrides.fetch(:hostcrl, '$ssldir/crl.pem')
        settings[:certificate_revocation] = parse_crl_usage(overrides.fetch(:certificate_revocation, 'true'))

        settings.each_pair do |key, value|
          next unless value.is_a? String

          settings[key] = value.gsub(unresolved_setting, substitutions)

          if match = settings[key].match(unresolved_setting)
            @errors << "Could not parse #{match[0]} in #{value}, " +
                       'valid settings to be interpolated are ' +
                       '$ssldir, $cadir, or $certname'
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
