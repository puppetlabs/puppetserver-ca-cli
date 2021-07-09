require 'optparse'
require 'openssl'
require 'puppetserver/ca/errors'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/utils/config'
require 'puppetserver/ca/x509_loader'

module Puppetserver
  module Ca
    module Action
      class Prune
        include Puppetserver::Ca::Utils

        SUMMARY = "Prune the local CRL on disk to remove any duplicates certificate"
        BANNER = <<-BANNER
Usage:
  puppetserver ca prune [--help]
  puppetserver ca prune [--config]

Description:
  Prune the list of revoked certificates of any duplication within it.

Options:
BANNER

        def initialize(logger)
          @logger = logger
        end

        def self.parser(parsed = {})
          OptionParser.new do |opts|
            opts.banner = BANNER # I will get a banner soon
            opts.on('--help', 'Display this command-specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to the puppet.conf file on disk') do |conf|
              parsed['config'] = conf
            end
          end
        end

        #Checklist:
        # 1. Ensure that everything is offline (Done)
        # 2. Get the path to the CRL (Done)
        # 3. Separate by issuers
        # 4. PRUNE!!!
        # 5. Repack and write it out?
        def run(inputs)
          config_path = inputs['config']


          # Validate the config path.
          if config_path
            errors = FileSystem.validate_file_paths(config_path)
            return 1 if Errors.handle_with_usage(@logger, errors)
          end

          # Validate puppet config setting.
          settings_overrides = {}
          puppet = Config::Puppet.new(config_path)
          puppet.load(settings_overrides)
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          # Validate that we are offline
          return 1 if HttpClient.check_server_online(puppet.settings, @logger)

          # Getting the CRL(s)
          loader = X509Loader.new(puppet.settings[:cacert], puppet.settings[:cakey], puppet.settings[:cacrl])

          revoked_lists_by_issuer = separate_revoke_list(loader.crls)

          # Ready to prune for each issuer!!!!

          return 0
        end

        # Pruning based on the serial number ?
        def prune(revoked_cert_list)
          # TBD
        end

        # Given that our PEM file may have multiple CRLs,
        # I decide to have a hash map where each key is
        # an issuer and its value is the revoked certs list
        def separate_revoke_list(crl_array)
          revoke_hashmap = {}

          crl_array.each do |list|
            revoke_hashmap[list.issuer.to_s] = list.revoked
          end
          return revoke_hashmap
        end

        # I copy and pasted this, might need to change to adapt
        def parse(args)
          results = {}
          parser = self.class.parser(results)
          errors = CliParsing.parse_with_errors(parser, args)
          errors_were_handled = Errors.handle_with_usage(@logger, errors, parser.help)

          if errors_were_handled
            exit_code = 1
          else
            exit_code = nil
          end
          return results, exit_code
        end
      end
    end
  end
end