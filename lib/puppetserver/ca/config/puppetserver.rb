require 'hocon'
require 'puppetserver/ca/utils/config'

module Puppetserver
  module Ca
    # Provides an interface for querying Puppetserver settings w/o loading
    # Puppetserver or any TK config service. Uses the ruby-hocon gem for parsing.
    class PuppetserverConfig

      include Puppetserver::Ca::Utils::Config

      def self.parse(config_path = nil)
        instance = new(config_path)
        instance.load

        return instance
      end

      attr_reader :errors, :settings

      def initialize(supplied_config_path = nil)
        @using_default_location = !supplied_config_path
        @config_path = supplied_config_path || "/etc/puppetlabs/puppetserver/conf.d/ca.conf"

        @settings = nil
        @errors = []
      end

      # Populate this config object with the CA-related settings
      def load
        if explicitly_given_config_file_or_default_config_exists?
          begin
            results = Hocon.load(@config_path)
          rescue Hocon::ConfigError => e
            errors << e.message
          end
        end

        overrides = results || {}
        @settings = supply_defaults(overrides).freeze
      end

      private

      # Return the correct confdir. We check for being root on *nix,
      # else the user path. We do not include a check for running
      # as Adminstrator since non-development scenarios for Puppet Server
      # on Windows are unsupported.
      # Note that Puppet Server runs as the [pe-]puppet user but to
      # start/stop it you must be root.
      def user_specific_ca_dir
        if running_as_root?
          '/etc/puppetlabs/puppetserver/ca'
        else
          "#{ENV['HOME']}/.puppetlabs/etc/puppetserver/ca"
        end
      end

      # Supply defaults for any CA settings not present in the config file
      # @param [Hash] overrides setting names and values loaded from the config file,
      #                         for overriding the defaults
      # @return [Hash] CA-related settings
      def supply_defaults(overrides = {})
        ca_settings = overrides['certificate-authority'] || {}
        settings = {}

        cadir = settings[:cadir] = ca_settings.fetch('cadir', user_specific_ca_dir)

        settings[:cacert] = ca_settings.fetch('cacert', "#{cadir}/ca_crt.pem")
        settings[:cakey] = ca_settings.fetch('cakey', "#{cadir}/ca_key.pem")
        settings[:cacrl] = ca_settings.fetch('cacrl', "#{cadir}/ca_crl.pem")
        settings[:serial] = ca_settings.fetch('serial', "#{cadir}/serial")
        settings[:cert_inventory] = ca_settings.fetch('cert-inventory', "#{cadir}/inventory.txt")

        return settings
      end

      def explicitly_given_config_file_or_default_config_exists?
        !@using_default_location || File.exist?(@config_path)
      end
    end
  end
end
