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
  Prune the list of revoked certificates of any duplication within it.  This command
  will only prune the CRL issued by Puppet's CA cert.

Options:
BANNER

        def initialize(logger)
          @logger = logger
        end

        def run(inputs)
          config_path = inputs['config']

          # Validate the config path.
          if config_path
            errors = FileSystem.validate_file_paths(config_path)
            return 1 if Errors.handle_with_usage(@logger, errors)
          end

          # Validate puppet config setting.
          puppet = Config::Puppet.new(config_path)
          puppet.load(logger: @logger)
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          # Validate that we are offline
          return 1 if HttpClient.check_server_online(puppet.settings, @logger)

          # Getting the CRL(s)
          loader = X509Loader.new(puppet.settings[:cacert], puppet.settings[:cakey], puppet.settings[:cacrl])

          puppet_crl = loader.crls.select { |crl| crl.verify(loader.key) }
          prune_CRLs(puppet_crl)
          update_pruned_CRL(puppet_crl, loader.key)
          FileSystem.write_file(puppet.settings[:cacrl], loader.crls, 0644)

          @logger.inform("Finished pruning Puppet's CRL")
          return 0
        end

        def prune_CRLs(crl_list)
          crl_list.each do |crl|
            existed_serial_number = Set.new()
            revoked_list = crl.revoked
            @logger.debug("Pruning duplicate entries in CRL for issuer " \
              "#{crl.issuer.to_s(OpenSSL::X509::Name::RFC2253)}") if @logger.debug?

            revoked_list.delete_if do |revoked|
              if existed_serial_number.add?(revoked.serial)
                false
              else
                @logger.debug("Removing duplicate of #{revoked.serial}, " \
                  "revoked on #{revoked.time}\n") if @logger.debug?
                true
              end
            end
            crl.revoked=(revoked_list)
          end
        end

        def update_pruned_CRL(crl_list, pkey)
          crl_list.each do |crl|
            crl.version=(crl.version + 1)
            crl.sign(pkey, OpenSSL::Digest::SHA256.new)
          end
        end

        def self.parser(parsed = {})
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this command-specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to the puppet.conf file on disk') do |conf|
              parsed['config'] = conf
            end
          end
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