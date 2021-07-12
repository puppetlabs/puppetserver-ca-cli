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
        # 4. Addin debug output
        # 5. Repack the CRL and write it out?

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

          crl_list = loader.crls
          prune_per_issuer(crl_list)  # Prune the list
          return 0                  # Place holder return value for now
        end

        # Further note: The class Revoked override the == method.  We could make
        # use of this by using array.uniq method to dedup ?
        def prune_per_issuer(crl_list)
          crl_list.each do |list|
            existed_serial_number = Set.new()
            revoked_list = list.revoked

            revoked_list.delete_if do |revoked|
              if existed_serial_number.add?(revoked.serial)
                false
              else
                debug_output(list, revoked)
                true
              end
            end
            puts "Finished pruning CRL by #{list.issuer.to_s(OpenSSL::X509::Name::RFC2253)}\n"
          end
        end

        # Output for debug
        #  - Name of issuer
        #  - Reason for revocation
        #  - Time of revocation
        def debug_output(curr_crl, curr_revoked_cert)
          issuer_name = curr_crl.issuer.to_s(OpenSSL::X509::Name::RFC2253)
          reason = curr_revoked_cert.extensions.join(', ') # Potentially ugly format.  Need more testing
          time = curr_revoked_cert.time
          @logger.debug("Issuer: #{issuer_name}\nReason for revoke : #{reason}\nTime of revocation: #{time}")  # Sample test
        end

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