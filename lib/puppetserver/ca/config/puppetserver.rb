require 'hocon'
require 'securerandom'

require 'puppetserver/ca/utils/config'

module Puppetserver
  module Ca
    module Config
      # Provides an interface for querying Puppetserver settings w/o loading
      # Puppetserver or any TK config service. Uses the ruby-hocon gem for parsing.
      class PuppetServer

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
          puppet_settings = Puppetserver::Ca::Config::Puppet.parse
          ca_settings = overrides['certificate-authority'] || {}
          settings = {}

          cadir = settings[:cadir] = ca_settings.fetch('cadir', user_specific_ca_dir)

          defaults = {
            ca_name: "Puppet CA: #{puppet_settings[:certname]}",
            root_ca_name: "Puppet Root CA: #{SecureRandom.hex(7)}",
          }

          settings[:ca_name] = ca_settings.fetch('ca_name', 'Puppet CA: $certname')
          settings[:cacert] = ca_settings.fetch('cacert', "#{cadir}/ca_crt.pem")
          settings[:cakey] = ca_settings.fetch('cakey', "#{cadir}/ca_key.pem")
          settings[:cacrl] = ca_settings.fetch('cacrl', "#{cadir}/ca_crl.pem")
          settings[:serial] = ca_settings.fetch('serial', "#{cadir}/serial")
          settings[:cert_inventory] = ca_settings.fetch('cert-inventory', "#{cadir}/inventory.txt")
          settings[:root_ca_name] = ca_settings.fetch('root-ca-name', "Puppet Root CA: #{SecureRandom.hex(7)}")
          settings[:rootkey] = ca_settings.fetch('rootkey', "#{cadir}/root_key.pem")

          return settings
        end

        def explicitly_given_config_file_or_default_config_exists?
          !@using_default_location || File.exist?(@config_path)
        end
      end
    end
  end
end
