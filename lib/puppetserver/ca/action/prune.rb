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

        SUMMARY = "Prune the local CRL on disk to remove any duplicated certificates"
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

        # TODO:
        # 1. Ensure that everything is offline (Done)
        # 2. Get the path to the CRL (Done)
        # 3. Prune each issuer revoked list (In progress)
        # 4. Repack the CRL and write it out?

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

          crl_list = loader.crls    # A reference to the CRL list
          prune_per_issuer(crl_list)
          return 0                  # Place holder return value for now
        end

        # Given that we have an array of CRL, each CRL contain a list of revoked
        # certs signed by a specific issuer.  Thus by iterating through each
        # item of the CRL array, we can invoke each item's list of revoked cert.
        # Since it is another array, we will have to iterate through that as well
        # to prune.  Currently pruning by serial number ?
        def prune_per_issuer(crl_list)
          crl_list.each do |list|
            existed_serial_number = Set.new()
            revoked_list = list.revoked

            revoked_list.delete_if do |revoked|
              # Add that serial number to the tracker and evaluate block to false
              if existed_serial_number.add?(revoked.serial)
                false
              else
                # Mark the current array element for removal from the revoked list by evaluate block to true
                # TO-DO: Add in logger debug here for the removed cert
                true
              end
            end
          end
        end

        # I copy and pasted this, might need to change to adapt to future changes
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