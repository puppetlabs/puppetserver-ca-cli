require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/host'
require 'puppetserver/ca/certificate_authority'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/utils/signing_digest'

module Puppetserver
  module Ca
    module Action
      class Create

        include Puppetserver::Ca::Utils

        # Only allow printing ascii characters, excluding /
        VALID_CERTNAME = /\A[ -.0-~]+\Z/
        CERTNAME_BLACKLIST = %w{--all --config}

        SUMMARY = "Create a new certificate signed by the CA"
        BANNER = <<-BANNER
Usage:
  puppetserver ca create [--help]
  puppetserver ca create [--config PATH] [--certname CERTNAME[,ADDLCERTNAME]]
                         [--subject-alt-names ALTNAME1[,ALTNAME2...]]

Description:
Creates a new certificate signed by the intermediate CA
and stores generated keys and certs on disk.

To determine the target location, the default puppet.conf
is consulted for custom values. If using a custom puppet.conf
provide it with the --config flag

Options:
BANNER
        def initialize(logger)
          @logger = logger
        end

        def self.parser(parsed = {})
          parsed['certnames'] = []
          parsed['subject-alt-names'] = ''
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--certname FOO,BAR', Array,
                 'One or more comma separated certnames') do |certs|
              parsed['certnames'] += certs
            end
            opts.on('--help', 'Display this create specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
            opts.on('--subject-alt-names NAME1[,NAME2]',
                    'Subject alternative names for the generated cert') do |sans|
              parsed['subject-alt-names'] = sans
            end
          end
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = CliParsing.parse_with_errors(parser, args)

          if results['certnames'].empty?
            errors << '    At least one certname is required to create'
          else
            results['certnames'].each do |certname|
              if CERTNAME_BLACKLIST.include?(certname)
                errors << "    Cannot manage cert named `#{certname}` from " +
                          "the CLI, if needed use the HTTP API directly"
              end

              if certname.match(/\p{Upper}/)
                errors << "    Certificate names must be lower case"
              end

              unless certname =~ VALID_CERTNAME
                errors << "  Certname #{certname} must not contain unprintable or non-ASCII characters"
              end
            end
          end

          errors_were_handled = CliParsing.handle_errors(@logger, errors, parser.help)

          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end

        def run(input)
          certnames = input['certnames']
          config_path = input['config']

          # Validate config_path provided
          if config_path
            errors = FileSystem.validate_file_paths(config_path)
            return 1 if CliParsing.handle_errors(@logger, errors)
          end

          # Load, resolve, and validate puppet config settings
          settings_overrides = {}
          # Since puppet expects the key to be called 'dns_alt_names', we need to use that here
          # to ensure that the overriding works correctly.
          settings_overrides[:dns_alt_names] = input['subject-alt-names'] unless input['subject-alt-names'].empty?
          puppet = Config::Puppet.new(config_path)
          puppet.load(settings_overrides)
          return 1 if CliParsing.handle_errors(@logger, puppet.errors)

          # Load most secure signing digest we can for csr signing.
          signer = SigningDigest.new
          return 1 if CliParsing.handle_errors(@logger, signer.errors)

          # Generate and save certs and associated keys
          all_passed = generate_certs(certnames, puppet.settings, signer.digest)
          return all_passed ? 0 : 1
        end

        # Create csrs and keys, then submit them to CA, request for the CA to sign
        # them, download the signed certificates from the CA, and finally save
        # the signed certs and associated keys. Returns true if all certs were
        # successfully created and saved.
        def generate_certs(certnames, settings, digest)
          # Make sure we have all the directories where we will be writing files
          FileSystem.ensure_dirs([settings[:ssldir],
                                  settings[:certdir],
                                  settings[:privatekeydir],
                                  settings[:publickeydir]])

          ca = Puppetserver::Ca::CertificateAuthority.new(@logger, settings)

          passed = certnames.map do |certname|
            key, csr = generate_key_csr(certname, settings, digest)
            return false unless csr
            return false unless ca.submit_certificate_request(certname, csr)
            return false unless ca.sign_certs([certname])
            if result = ca.get_certificate(certname)
              save_file(result.body, certname, settings[:certdir], "Certificate")
              save_keys(certname, settings, key)
              true
            else
              false
            end
          end
          passed.all?
        end

        def generate_key_csr(certname, settings, digest)
          host = Puppetserver::Ca::Host.new(digest)
          private_key = host.create_private_key(settings[:keylength])
          extensions = []
          if !settings[:subject_alt_names].empty?
            extensions << host.create_extension("subjectAltName", settings[:subject_alt_names])
          end
          csr = host.create_csr(name: certname, key: private_key, extensions: extensions, csr_attribute_path: settings[:csr_attributes])
          return if CliParsing.handle_errors(@logger, host.errors)

          return private_key, csr
        end

        def save_keys(certname, settings, key)
          public_key = key.public_key
          save_file(key, certname, settings[:privatekeydir], "Private key")
          save_file(public_key, certname, settings[:publickeydir], "Public key")
        end

        def save_file(content, certname, dir, type)
          location = File.join(dir, "#{certname}.pem")
          @logger.warn "#{type} #{certname}.pem already exists, overwriting" if File.exist?(location)
          FileSystem.write_file(location, content, 0640)
          @logger.inform "Successfully saved #{type.downcase} for #{certname} to #{location}"
        end
      end
    end
  end
end
