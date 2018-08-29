require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/config/puppetserver'

module Puppetserver
  module Ca
    module Config
      class Combined

        attr_reader :settings, :errors

        def initialize(puppet_config_path = nil, server_config_path = nil)
          @errors = []
          puppet_settings = Puppet.parse(puppet_config_path)
          @errors << puppet_settings.errors
          server_settings = PuppetServer.parse(puppet_settings.settings, server_config_path)
          @errors << server_settings.errors
          @errors.flatten!

          # Override things in puppet with things in puppetserver
          @settings = puppet_settings.settings.merge(server_settings.settings)
        end
      end
    end
  end
end
