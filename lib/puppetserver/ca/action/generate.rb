require 'optparse'
require 'openssl'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/host'
require 'puppetserver/ca/utils'
require 'puppetserver/utils/signing_digest'

module Puppetserver
  module Ca
    module Action
      class Generate
        include Puppetserver::Utils

        CA_EXTENSIONS = [
          ["basicConstraints", "CA:TRUE", true],
          ["keyUsage", "keyCertSign, cRLSign", true],
          ["subjectKeyIdentifier", "hash", false],
          ["authorityKeyIdentifier", "keyid:always", false]
        ].freeze

        # Make the certificate valid as of yesterday, because so many people's
        # clocks are out of sync.  This gives one more day of validity than people
        # might expect, but is better than making every person who has a messed up
        # clock fail, and better than having every cert we generate expire a day
        # before the user expected it to when they asked for "one year".
        CERT_VALID_FROM = (Time.now - (60*60*24)).freeze

        SUMMARY = "Generate a root and intermediate signing CA for Puppet Server"
        BANNER = <<-BANNER
Usage:
  puppetserver ca generate [--help]
  puppetserver ca generate [--config PATH]

Description:
Generate a root and intermediate signing CA for Puppet Server
and store generated CA keys, certs, and crls on disk.

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
            errors = FileUtilities.validate_file_paths(config_path)
            return 1 if Utils.handle_errors(@logger, errors)
          end

          # Load, resolve, and validate puppet config settings
          puppet = PuppetConfig.parse(config_path)
          return 1 if Utils.handle_errors(@logger, puppet.errors)

          # Load most secure signing digest we can for cers/crl/csr signing.
          signer = SigningDigest.new
          return 1 if Utils.handle_errors(@logger, signer.errors)

          # Generate root and intermediate ca and put all the certificates, crls,
          # and keys where they should go.
          generate_root_and_intermediate_ca(puppet.settings, signer.digest)

          # Puppet's internal CA expects these file to exist.
          FileUtilities.ensure_file(puppet.settings[:serial], "001", 0640)
          FileUtilities.ensure_file(puppet.settings[:cert_inventory], "", 0640)

          @logger.inform "Generation succeeded. Find your files in #{puppet.settings[:cadir]}"
          return 0
        end

        def generate_root_and_intermediate_ca(settings, signing_digest)
          valid_until = Time.now + settings[:ca_ttl]
          host = Puppetserver::Ca::Host.new(signing_digest)

          root_key = host.create_private_key(settings[:keylength])
          root_cert = self_signed_ca(root_key, settings[:root_ca_name], valid_until, signing_digest)
          root_crl = create_crl_for(root_cert, root_key, valid_until, signing_digest)

          int_key = host.create_private_key(settings[:keylength])
          int_csr = host.create_csr(settings[:ca_name], int_key)
          int_cert = sign_intermediate(root_key, root_cert, int_csr, valid_until, signing_digest)
          int_crl = create_crl_for(int_cert, int_key, valid_until, signing_digest)

          FileUtilities.ensure_dir(settings[:cadir])

          file_properties = [
            [settings[:cacert], [int_cert, root_cert]],
            [settings[:cakey], int_key],
            [settings[:rootkey], root_key],
            [settings[:cacrl], [int_crl, root_crl]]
          ]

          file_properties.each do |location, content|
            @logger.warn "#{location} exists, overwriting" if File.exist?(location)
            FileUtilities.write_file(location, content, 0640)
          end
        end

        def self_signed_ca(key, name, valid_until, signing_digest)
          cert = OpenSSL::X509::Certificate.new

          cert.public_key = key.public_key
          cert.subject = OpenSSL::X509::Name.new([["CN", name]])
          cert.issuer = cert.subject
          cert.version = 2
          cert.serial = 1

          cert.not_before = CERT_VALID_FROM
          cert.not_after  = valid_until

          ef = extension_factory_for(cert, cert)
          CA_EXTENSIONS.each do |ext|
            extension = ef.create_extension(*ext)
            cert.add_extension(extension)
          end

          cert.sign(key, signing_digest)

          cert
        end

        def extension_factory_for(ca, cert = nil)
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.issuer_certificate  = ca
          ef.subject_certificate = cert if cert

          ef
        end

        def create_crl_for(ca_cert, ca_key, valid_until, signing_digest)
          crl = OpenSSL::X509::CRL.new
          crl.version = 1
          crl.issuer = ca_cert.subject

          ef = extension_factory_for(ca_cert)
          crl.add_extension(
            ef.create_extension(["authorityKeyIdentifier", "keyid:always", false]))
          crl.add_extension(
            OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(0)))

          crl.last_update = CERT_VALID_FROM
          crl.next_update = valid_until
          crl.sign(ca_key, signing_digest)

          crl
        end

        def sign_intermediate(ca_key, ca_cert, csr, valid_until, signing_digest)
          cert = OpenSSL::X509::Certificate.new

          cert.public_key = csr.public_key
          cert.subject = csr.subject
          cert.issuer = ca_cert.subject
          cert.version = 2
          cert.serial = 2

          cert.not_before = CERT_VALID_FROM
          cert.not_after = valid_until

          ef = extension_factory_for(ca_cert, cert)
          CA_EXTENSIONS.each do |ext|
            extension = ef.create_extension(*ext)
            cert.add_extension(extension)
          end
          cert.sign(ca_key, signing_digest)

          cert
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = Utils.parse_with_errors(parser, args)

          errors_were_handled = Utils.handle_errors(@logger, errors, parser.help)

          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end

        def self.parser(parsed = {})
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this generate specific help output') do |help|
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