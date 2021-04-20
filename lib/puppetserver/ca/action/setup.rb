require 'optparse'

require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/errors'
require 'puppetserver/ca/local_certificate_authority'
require 'puppetserver/ca/utils/config'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/utils/signing_digest'

module Puppetserver
  module Ca
    module Action
      class Setup
        include Puppetserver::Ca::Utils

        SUMMARY = "Setup a self-signed CA chain for Puppet Server"
        BANNER = <<-BANNER
Usage:
  puppetserver ca setup [--help]
  puppetserver ca setup [--config PATH] [--subject-alt-names NAME[,NAME]]
                           [--certname NAME] [--ca-name NAME]

Description:
  Setup a root and intermediate signing CA for Puppet Server
  and store generated CA keys, certs, crls, and associated
  server related files on disk.

  The `--subject-alt-names` flag can be used to add SANs to the
  certificate generated for the Puppet server. Multiple names can be
  listed as a comma separated string. These can be either DNS names or
  IP addresses, differentiated by prefixes: `DNS:foo.bar.com,IP:123.456.789`.
  Names with no prefix will be treated as DNS names.

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
          settings_overrides[:certname] = input['certname'] unless input['certname'].empty?
          settings_overrides[:ca_name] = input['ca-name'] unless input['ca-name'].empty?
          # Since puppet expects the key to be called 'dns_alt_names', we need to use that here
          # to ensure that the overriding works correctly.
          settings_overrides[:dns_alt_names] = input['subject-alt-names'] unless input['subject-alt-names'].empty?

          puppet = Config::Puppet.new(config_path)
          puppet.load(cli_overrides: settings_overrides, logger: @logger)
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          # Load most secure signing digest we can for cers/crl/csr signing.
          signer = SigningDigest.new
          return 1 if Errors.handle_with_usage(@logger, signer.errors)

          # Generate root and intermediate ca and put all the certificates, crls,
          # and keys where they should go.
          errors = generate_pki(puppet.settings, signer.digest)
          return 1 if Errors.handle_with_usage(@logger, errors)

          @logger.inform "Generation succeeded. Find your files in #{puppet.settings[:cadir]}"
          return 0
        end

        def generate_pki(settings, signing_digest)
          ca = Puppetserver::Ca::LocalCertificateAuthority.new(signing_digest, settings)

          root_key, root_cert, root_crl = ca.create_root_cert
          ca.create_intermediate_cert(root_key, root_cert)
          server_key, server_cert = ca.create_server_cert
          return ca.errors if ca.errors.any?

          FileSystem.ensure_dirs([settings[:ssldir],
                                  settings[:cadir],
                                  settings[:certdir],
                                  settings[:privatekeydir],
                                  settings[:publickeydir],
                                  settings[:signeddir]])

          public_files = [
            [settings[:cacert], [ca.cert, root_cert]],
            [settings[:cacrl], [ca.crl, root_crl]],
            [settings[:cadir] + '/infra_crl.pem', [ca.crl, root_crl]],
            [settings[:hostcert], server_cert],
            [settings[:localcacert], [ca.cert, root_cert]],
            [settings[:hostcrl], [ca.crl, root_crl]],
            [settings[:hostpubkey], server_key.public_key],
            [settings[:capub], ca.key.public_key],
            [settings[:cert_inventory], ca.inventory_entry(server_cert)],
            [settings[:cadir] + '/infra_inventory.txt', ''],
            [settings[:cadir] + '/infra_serials', ''],
            [settings[:serial], "002"],
            [File.join(settings[:signeddir], "#{settings[:certname]}.pem"), server_cert],
          ]

          private_files = [
            [settings[:hostprivkey], server_key],
            [settings[:rootkey], root_key],
            [settings[:cakey], ca.key],
          ]

          files_to_check = public_files + private_files
          # We don't want to error if server's keys exist. Certain workflows
          # allow the agent to have already be installed with keys and then
          # upgraded to be a server. The host class will honor keys, if both
          # public and private exist, and error if only one exists - as is
          # previous behavior.
          files_to_check = files_to_check.map(&:first) - [settings[:hostpubkey], settings[:hostprivkey]]
          errors = FileSystem.check_for_existing_files(files_to_check)

          if !errors.empty?
            instructions = <<-ERR
If you would really like to replace your CA, please delete the existing files first.
Note that any certificates that were issued by this CA will become invalid if you
replace it!
ERR
            errors << instructions
            return errors
          end

          public_files.each do |location, content|
            FileSystem.write_file(location, content, 0644)
          end

          private_files.each do |location, content|
            FileSystem.write_file(location, content, 0640)
          end

          Puppetserver::Ca::Utils::Config.symlink_to_old_cadir(settings[:cadir], settings[:confdir])

          return []
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
          parsed['subject-alt-names'] = ''
          parsed['ca-name'] = ''
          parsed['certname'] = ''
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this command-specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
            opts.on('--subject-alt-names NAME[,NAME]',
                    'Subject alternative names for the server cert') do |sans|
              parsed['subject-alt-names'] = sans
            end
            opts.on('--ca-name NAME',
                    'Common name to use for the CA signing cert') do |name|
              parsed['ca-name'] = name
            end
            opts.on('--certname NAME',
                    'Common name to use for the server cert') do |name|
              parsed['certname'] = name
            end
          end
        end
      end
    end
  end
end
