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
      class GenerateCsr
        include Puppetserver::Ca::Utils

        SUMMARY = 'Generate a CSR for an intermediate signing CA cert'
        BANNER = <<-BANNER
Usage:
  puppetserver ca generate-csr [--help]
  puppetserver ca generate-csr --output-dir PATH [--config PATH] [--ca-name NAME]

Description:
  Setup a root and intermediate signing CA for Puppet Server
  and store generated CA keys, certs, crls, and associated
  master related files on disk.

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

          # Load, resolve, and validate puppet config settings
          settings_overrides = {}
          settings_overrides[:ca_name] = input['ca-name'] unless input['ca-name'].empty?

          puppet = Config::Puppet.new(config_path)
          puppet.load(settings_overrides)
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          # Load most secure signing digest we can for cers/crl/csr signing.
          signer = SigningDigest.new
          return 1 if Errors.handle_with_usage(@logger, signer.errors)

          # Generate intermediate ca and put the results in the specified output directory
          generate_csr(puppet.settings, signer.digest, input['output-dir'])
          return 0
        end

        def generate_csr(settings, signing_digest, dir)
          ca = Puppetserver::Ca::LocalCertificateAuthority.new(signing_digest, settings)

          key, csr = ca.create_intermediate_csr

          write_generated_files(key, csr, dir)
        end

        def write_generated_files(key, csr, dir)
          FileSystem.write_file(File.join(dir, 'ca.key'), key.to_s, 0640)
          FileSystem.write_file(File.join(dir, 'ca.csr'), csr.to_s, 0640)
        end

        def check_for_existing_ssl_files(dir)
          files = [ File.join(dir, 'ca.key'), File.join(dir, 'ca.csr')]
          errors = Puppetserver::Ca::Utils::FileSystem.check_for_existing_files(files)
          if !errors.empty?
            errors << 'Please delete these files if you want to generate a CSR'
          end

          errors
        end

        def parse(cli_args)
          results = {}
          parser = self.class.parser(results)
          errors = CliParsing.parse_with_errors(parser, cli_args)

          if results['output-dir'].nil? || results['output-dir'].empty?
            errors << '    Must specify an output directory to store generated files in'
          elsif !Dir.exist?(results['output-dir'])
            errors << '    Specified output directory must exist'
          else
            errors.concat(check_for_existing_ssl_files(results['output-dir']))
          end

          errors_were_handled = Errors.handle_with_usage(@logger, errors, parser.help)
          exit_code = errors_were_handled ? 1 : nil
          return results, exit_code
        end

        def self.parser(parsed = {})
          parsed['ca-name'] = ''
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this command-specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--output-dir PATH',
                    'Path to directory to store generated key and csr in') do |dir|
              parsed['output-dir'] = dir
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
            opts.on('--ca-name NAME',
                    'Common name to use for the CA signing cert') do |name|
              parsed['ca-name'] = name
            end
          end
        end
      end
    end
  end
end
