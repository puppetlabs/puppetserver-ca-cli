require 'optparse'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/local_certificate_authority'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/config/puppet'

module Puppetserver
  module Ca
    module Action
      class Generate
        include Puppetserver::Ca::Utils

        SUMMARY = "Generate a root and intermediate signing CA for Puppet Server"
        BANNER = <<-BANNER
Usage:
  puppetserver ca generate [--help]
  puppetserver ca generate [--config PATH] [--subject-alt-names ALTNAME1[,ALTNAME2...]]
                           [--certname NAME] [--ca-name NAME]

Description:
Generate a root and intermediate signing CA for Puppet Server
and store generated CA keys, certs, and crls on disk.

The `--subject-alt-names` flag can be used to add SANs to the
certificate generated for the Puppet master. Multiple names can be
listed as a comma separated string. These can be either DNS names or
IP addresses, differentiated by prefixes: `DNS:foo.bar.com,IP:123.456.789`.
Names with no prefix will be treated as DNS names.

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
            return 1 if CliParsing.handle_errors(@logger, errors)
          end

          # Load, resolve, and validate puppet config settings
          settings_overrides = {}
          settings_overrides[:certname] = input['certname'] unless input['certname'].empty?
          settings_overrides[:ca_name] = input['ca-name'] unless input['ca-name'].empty?
          # Since puppet expects the key to be called 'dns_alt_names', we need to use that here
          # to ensure that the overriding works correctly.
          settings_overrides[:dns_alt_names] = input['subject-alt-names'] unless input['subject-alt-names'].empty?

          puppet = Config::Puppet.new(config_path)
          puppet.load(settings_overrides)
          return 1 if CliParsing.handle_errors(@logger, puppet.errors)

          # Load most secure signing digest we can for cers/crl/csr signing.
          signer = SigningDigest.new
          return 1 if CliParsing.handle_errors(@logger, signer.errors)

          # Generate root and intermediate ca and put all the certificates, crls,
          # and keys where they should go.
          errors = generate_pki(puppet.settings, signer.digest)
          return 1 if CliParsing.handle_errors(@logger, errors)

          @logger.inform "Generation succeeded. Find your files in #{puppet.settings[:cadir]}"
          return 0
        end

        def generate_pki(settings, signing_digest)
          ca = Puppetserver::Ca::LocalCertificateAuthority.new(signing_digest, settings)

          root_key, root_cert, root_crl = ca.create_root_cert
          int_key, int_cert, int_crl = ca.create_intermediate_cert(root_key, root_cert)
          master_key, master_cert = ca.create_master_cert(int_key, int_cert)
          return ca.host.errors if ca.host.errors.any?

          FileSystem.ensure_dirs([settings[:ssldir],
                                  settings[:cadir],
                                  settings[:certdir],
                                  settings[:privatekeydir],
                                  settings[:publickeydir],
                                  settings[:signeddir]])

          public_files = [
            [settings[:cacert], [int_cert, root_cert]],
            [settings[:cacrl], [int_crl, root_crl]],
            [settings[:hostcert], master_cert],
            [settings[:localcacert], [int_cert, root_cert]],
            [settings[:hostcrl], [int_crl, root_crl]],
            [settings[:hostpubkey], master_key.public_key],
            [settings[:capub], int_key.public_key],
            [settings[:cert_inventory], ca.inventory_entry(master_cert)],
            [settings[:serial], "002"],
            [File.join(settings[:signeddir], "#{settings[:certname]}.pem"), master_cert],
          ]

          private_files = [
            [settings[:hostprivkey], master_key],
            [settings[:rootkey], root_key],
            [settings[:cakey], int_key],
          ]

          errors = FileSystem.check_for_existing_files(public_files.map(&:first) + private_files.map(&:first))

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

          return []
        end

        def parse(cli_args)
          results = {}
          parser = self.class.parser(results)
          errors = CliParsing.parse_with_errors(parser, cli_args)
          errors_were_handled = CliParsing.handle_errors(@logger, errors, parser.help)
          exit_code = errors_were_handled ? 1 : nil
          return results, exit_code
        end

        def self.parser(parsed = {})
          parsed['subject-alt-names'] = ''
          parsed['ca-name'] = ''
          parsed['certname'] = ''
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this generate specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
            opts.on('--subject-alt-names NAME1[,NAME2]',
                    'Subject alternative names for the master cert') do |sans|
              parsed['subject-alt-names'] = sans
            end
            opts.on('--ca-name NAME',
                    'Common name to use for the CA signing cert') do |name|
              parsed['ca-name'] = name
            end
            opts.on('--certname NAME',
                    'Common name to use for the master cert') do |name|
              parsed['certname'] = name
            end
          end
        end
      end
    end
  end
end
