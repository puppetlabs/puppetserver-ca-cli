require 'optparse'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/x509_loader'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/local_certificate_authority'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/signing_digest'

module Puppetserver
  module Ca
    module Action
      class Import
        include Puppetserver::Ca::Utils

        SUMMARY = "Import the CA's key, certs, and crls"
        BANNER = <<-BANNER
Usage:
  puppetserver ca import [--help]
  puppetserver ca import [--config PATH] [--certname NAME]
                         [--subject-alt-names ALTNAME1[,ALTNAME2...]]
      --private-key PATH --cert-bundle PATH --crl-chain PATH

Description:
Given a private key, cert bundle, and a crl chain,
validate and import to the Puppet Server CA.

Note that the cert and crl provided for the leaf CA must not
have already issued or revoked any certificates.

To determine the target location the default puppet.conf
is consulted for custom values. If using a custom puppet.conf
provide it with the --config flag

Options:
BANNER

        def initialize(logger)
          @logger = logger
        end

        def run(input)
          bundle_path = input['cert-bundle']
          key_path = input['private-key']
          chain_path = input['crl-chain']
          config_path = input['config']

          files = [bundle_path, key_path, chain_path, config_path].compact

          errors = FileSystem.validate_file_paths(files)
          return 1 if CliParsing.handle_errors(@logger, errors)

          loader = X509Loader.new(bundle_path, key_path, chain_path)
          return 1 if CliParsing.handle_errors(@logger, loader.errors)

          settings_overrides = {}
          settings_overrides[:certname] = input['certname'] unless input['certname'].empty?
          settings_overrides[:dns_alt_names] = input['subject-alt-names'] unless input['subject-alt-names'].empty?

          puppet = Config::Puppet.new(config_path)
          puppet.load(settings_overrides)
          return 1 if CliParsing.handle_errors(@logger, puppet.errors)

          # Load most secure signing digest we can for cers/crl/csr signing.
          signer = SigningDigest.new
          return 1 if CliParsing.handle_errors(@logger, signer.errors)

          errors = import(loader, puppet.settings, signer.digest)
          return 1 if CliParsing.handle_errors(@logger, errors)

          @logger.inform "Import succeeded. Find your files in #{puppet.settings[:cadir]}"
          return 0
        end

        def import(loader, settings, signing_digest)
          ca = Puppetserver::Ca::LocalCertificateAuthority.new(signing_digest, settings)
          master_key, master_cert = ca.create_master_cert(loader.key, loader.certs.first)
          return ca.host.errors if ca.host.errors.any?

          FileSystem.ensure_dirs([settings[:ssldir],
                                  settings[:cadir],
                                  settings[:certdir],
                                  settings[:privatekeydir],
                                  settings[:publickeydir],
                                  settings[:signeddir]])

          public_files = [
            [settings[:cacert], loader.certs],
            [settings[:cacrl], loader.crls],
            [settings[:localcacert], loader.certs],
            [settings[:hostcrl], loader.crls],
            [settings[:hostpubkey], master_key.public_key],
            [settings[:hostcert], master_cert],
            [settings[:cert_inventory], ca.inventory_entry(master_cert)],
            [settings[:serial], "002"],
            [File.join(settings[:signeddir], "#{settings[:certname]}.pem"), master_cert]
          ]

          private_files = [
            [settings[:hostprivkey], master_key],
            [settings[:cakey], loader.key],
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

        def check_flag_usage(results)
          if results['cert-bundle'].nil? || results['private-key'].nil? || results['crl-chain'].nil?
            '    Missing required argument' + "\n" +
            '    --cert-bundle, --private-key, --crl-chain are required'
          end
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = CliParsing.parse_with_errors(parser, args)

          if err = check_flag_usage(results)
            errors << err
          end

          errors_were_handled = CliParsing.handle_errors(@logger, errors, parser.help)

          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end

        def self.parser(parsed = {})
          parsed['certname'] = ''
          parsed['subject-alt-names'] = ''
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this import specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
            opts.on('--private-key KEY', 'Path to PEM encoded key') do |key|
              parsed['private-key'] = key
            end
            opts.on('--cert-bundle BUNDLE', 'Path to PEM encoded bundle') do |bundle|
              parsed['cert-bundle'] = bundle
            end
            opts.on('--crl-chain CHAIN', 'Path to PEM encoded chain') do |chain|
              parsed['crl-chain'] = chain
            end
            opts.on('--certname NAME',
                    'Common name to use for the master cert') do |name|
              parsed['certname'] = name
            end
            opts.on('--subject-alt-names NAME1[,NAME2]',
                    'Subject alternative names for the master cert') do |sans|
              parsed['subject-alt-names'] = sans
            end
          end
        end
      end
    end
  end
end
