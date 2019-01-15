require 'optparse'

require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/errors'
require 'puppetserver/ca/local_certificate_authority'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/utils/signing_digest'

module Puppetserver
  module Ca
    module Action
      class InfraCRL
        include Puppetserver::Ca::Utils

        SUMMARY = "Setup infrastructure CRL based on a node inventory."
        BANNER = <<-BANNER
Usage:
  puppetserver ca infracrl [--help]
  puppetserver ca infracrl [--config PATH]

Description:
  Creates auxiliary files needed to use the infrastructure-only CRL.
  Assumes the existence of an `infra_inventory.txt` file in the CA
  directory listing the certnames of the infrastructure nodes in the
  Puppet installation. Generates the `infra_serials` file and the empty
  CRL to be populated with revoked infrastructure nodes.

  To determine the target location, the default puppet.conf
  is consulted for custom values. If using a custom puppet.conf
  provide it with the --config flag

Options:
BANNER

        def initialize(logger)
          @logger = logger
        end

        def run(input)
          # Validate config_path provided
          config_path = input['config']
          if config_path
            errors = FileSystem.validate_file_paths(config_path)
            return 1 if Errors.handle_with_usage(@logger, errors)
          end

          puppet = Config::Puppet.new(config_path)
          puppet.load
          settings = puppet.settings
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          inventory_file = File.join(settings[:cadir], 'infra_inventory.txt')
          if !File.exist?(inventory_file)
            @logger.err <<-ERR
Please create an inventory file at '#{inventory_file}' with the certnames of your
infrastructure nodes before proceeding with infra CRL setup!"
ERR
            return 1
          end

          serial_file = File.join(settings[:cadir], 'infra_serials')
          infra_crl = File.join(settings[:cadir], 'infra_crl.pem')

          file_errors = check_for_existing_infra_files([serial_file, infra_crl])
          return 1 if Errors.handle_with_usage(@logger, file_errors)

          FileSystem.write_file(serial_file, '', 0644)

          errors = create_infra_crl_chain(settings)
          return 1 if Errors.handle_with_usage(@logger, errors)

          @logger.inform "Infra CRL files created."
          return 0
        end

        def check_for_existing_infra_files(files)
          file_errors = FileSystem.check_for_existing_files(files)
          if !file_errors.empty?
            notice = <<-MSG
If you would really like to reinitialize your infrastructure CRL, please delete
the existing files and run this command again.
MSG
            file_errors << notice
          end
          return file_errors
        end

        def create_infra_crl_chain(settings)
          # Load most secure signing digest we can for cers/crl/csr signing.
          signer = SigningDigest.new
          return signer.errors if signer.errors.any?

          ca = LocalCertificateAuthority.new(signer.digest, settings)
          infra_crl = ca.create_crl_for(ca.cert, ca.key)
          return ca.errors if ca.errors.any?

          # Drop the full leaf CRL from the chain
          crl_chain = ca.crl_chain.drop(1)
          # Add the new clean CRL, that will be populated with infra nodes only
          # as they are revoked
          crl_chain.unshift(infra_crl)
          FileSystem.write_file(File.join(settings[:cadir], 'infra_crl.pem'), crl_chain, 0644)

          []
        end

        def parse(cli_args)
          results = {}
          parser = self.class.parser(results)
          errors = CliParsing.parse_with_errors(parser, cli_args)
          errors_were_handled = Errors.handle_with_usage(@logger, errors, parser.help)
          exit_code = errors_were_handled ? 1 : nil
          return results, exit_code
        end

        def self.parser(parsed = {})
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this setup specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
          end
        end
      end
    end
  end
end
