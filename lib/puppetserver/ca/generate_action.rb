require 'optparse'
require 'openssl'
require 'puppetserver/utils/file_utils'
require 'puppetserver/settings/ttl_setting'

module Puppetserver
  module Ca
    class GenerateAction
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
          errors = Puppetserver::Utils::FileUtilities.validate_file_paths(config_path)
          return 1 if log_possible_errors(errors)
        end

        # Load, resolve, and validate puppet config settings
        puppet = PuppetConfig.parse(config_path)
        return 1 if log_possible_errors(puppet.errors)

        # Load most secure signing digest we can for cers/crl/csr signing.
        signing_digest = default_signing_digest
        return 1 unless signing_digest

        # Generate root and intermediate ca and put all the certificates, crls,
        # and keys where they should go.
        generate_root_and_intermediate_ca(puppet.settings, signing_digest)

        # Puppet's internal CA expects these file to exist.
        Puppetserver::Utils::FileUtilities.ensure_file(puppet.settings[:serial], "001", 0640)
        Puppetserver::Utils::FileUtilities.ensure_file(puppet.settings[:cert_inventory], "", 0640)

        @logger.inform "Generation succeeded. Find your files in #{puppet.settings[:cadir]}"
        return 0
      end

      def log_possible_errors(maybe_errors)
        errors = Array(maybe_errors).compact
        unless errors.empty?
          @logger.err "Error:"
          errors.each do |message|
            @logger.err "    #{message}"
          end
          return true
        end
      end

      def generate_root_and_intermediate_ca(settings, signing_digest)
        valid_until = Time.now + settings[:ca_ttl]

        root_key = create_private_key(settings[:keylength])
        root_cert = self_signed_ca(root_key, settings[:root_ca_name], valid_until, signing_digest)
        root_crl = create_crl_for(root_cert, root_key, valid_until, signing_digest)

        int_key = create_private_key(settings[:keylength])
        int_csr = create_csr(int_key, settings[:ca_name], signing_digest)
        int_cert = sign_intermediate(root_key, root_cert, int_csr, valid_until, signing_digest)
        int_crl = create_crl_for(int_cert, int_key, valid_until, signing_digest)

        Puppetserver::Utils::FileUtilities.ensure_dir(settings[:cadir])

        file_properties = [
          [settings[:cacert], [int_cert, root_cert]],
          [settings[:cakey], int_key],
          [settings[:rootkey], root_key],
          [settings[:cacrl], [int_crl, root_crl]]
        ]

        file_properties.each do |location, content|
          @logger.warn "#{location} exists, overwriting" if File.exist?(location)
          Puppetserver::Utils::FileUtilities.write_file(location, content, 0640)
        end
      end

      def create_private_key(length)
        OpenSSL::PKey::RSA.new(length)
      end

      # Attempts several different digests, using the most secure one it can load.
      # Returns nil if no signing digest could be found.
      def default_signing_digest
        if OpenSSL::Digest.const_defined?('SHA256')
          OpenSSL::Digest::SHA256.new
        elsif OpenSSL::Digest.const_defined?('SHA1')
          OpenSSL::Digest::SHA1.new
        elsif OpenSSL::Digest.const_defined?('SHA512')
          OpenSSL::Digest::SHA512.new
        elsif OpenSSL::Digest.const_defined?('SHA384')
          OpenSSL::Digest::SHA384.new
        elsif OpenSSL::Digest.const_defined?('SHA224')
          OpenSSL::Digest::SHA224.new
        else
          @logger.err "Error: No FIPS 140-2 compliant digest algorithm in OpenSSL::Digest"
          nil
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

      def create_csr(key, name, signing_digest)
        csr = OpenSSL::X509::Request.new

        csr.public_key = key.public_key
        csr.subject = OpenSSL::X509::Name.new([["CN", name]])
        csr.version = 2
        csr.sign(key, signing_digest)

        csr
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

      def parse(cli_args)
        parser, inputs, unparsed = parse_inputs(cli_args)

        if !unparsed.empty?
          @logger.err 'Error:'
          @logger.err 'Unknown arguments or flags:'
          unparsed.each do |arg|
            @logger.err "    #{arg}"
          end

          @logger.err ''
          @logger.err parser.help

          exit_code = 1
        else
          exit_code = nil
        end

        return inputs, exit_code
      end

      def parse_inputs(inputs)
        parsed = {}
        unparsed = []

        parser = self.class.parser(parsed)

        begin
          parser.order!(inputs) do |nonopt|
            unparsed << nonopt
          end
        rescue OptionParser::ParseError => e
          unparsed += e.args
          unparsed << inputs.shift unless inputs.first =~ /^-{1,2}/
          retry
        end

        return parser, parsed, unparsed
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
