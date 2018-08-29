require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/config/puppetserver'

module Puppetserver
  module Ca
    module Config
      class Combined

        attr_reader :settings, :errors

        def initialize(puppet_config_path: nil,
                       server_config_path: nil,
                       settings_overrides: {})
          @errors = []
          puppet_settings = Puppet.new(puppet_config_path)
          puppet_overrides, server_overrides = split_overrides(settings_overrides, puppet_settings)

          puppet_settings.load(puppet_overrides)
          @errors << puppet_settings.errors
          server_settings = PuppetServer.parse(puppet_settings.settings, server_config_path)
          @errors << server_settings.errors
          @errors.flatten!

          # Override things in puppet with things in puppetserver
          @settings = puppet_settings.settings.merge(server_settings.settings)
          # Override the result with remaining CLI overrides
          @settings.merge!(server_overrides)
        end

        def split_overrides(overrides, puppet_settings)
          puppet_overrides = {}
          server_overrides = {}
          overrides.each do |k, v|
            if puppet_settings.valid_settings.include?(k)
              puppet_overrides[k] = v
            else
              server_overrides[k] = v
            end
          end

          [puppet_overrides, server_overrides]
        end
      end
    end
  end
end
