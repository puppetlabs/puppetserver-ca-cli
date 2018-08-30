require 'puppetserver/ca/host'

require 'openssl'

module Puppetserver
  module Ca
    class LocalCertificateAuthority

      # Make the certificate valid as of yesterday, because so many people's
      # clocks are out of sync.  This gives one more day of validity than people
      # might expect, but is better than making every person who has a messed up
      # clock fail, and better than having every cert we generate expire a day
      # before the user expected it to when they asked for "one year".
      CERT_VALID_FROM = (Time.now - (60*60*24)).freeze

      SSL_SERVER_CERT = "1.3.6.1.5.5.7.3.1"
      SSL_CLIENT_CERT = "1.3.6.1.5.5.7.3.2"

      MASTER_EXTENSIONS = [
        ["basicConstraints", "CA:FALSE", true],
        ["nsComment", "Puppet Server Internal Certificate", false],
        ["authorityKeyIdentifier", "keyid:always", false],
        ["extendedKeyUsage", "#{SSL_SERVER_CERT}, #{SSL_CLIENT_CERT}", true],
        ["keyUsage", "keyEncipherment, digitalSignature", true],
        ["subjectKeyIdentifier", "hash", false]
      ].freeze

      CA_EXTENSIONS = [
        ["basicConstraints", "CA:TRUE", true],
        ["keyUsage", "keyCertSign, cRLSign", true],
        ["subjectKeyIdentifier", "hash", false],
        ["nsComment", "Puppet Server Internal Certificate", false],
        ["authorityKeyIdentifier", "keyid:always", false]
      ].freeze

      attr_reader :host

      def initialize(digest, settings)
        @digest = digest
        @host = Host.new(digest)
        @settings = settings
      end

      def valid_until
        Time.now + @settings[:ca_ttl]
      end

      def extension_factory_for(ca, cert = nil)
        ef = OpenSSL::X509::ExtensionFactory.new
        ef.issuer_certificate  = ca
        ef.subject_certificate = cert if cert

        ef
      end

      def inventory_entry(cert)
        "0x%04x %s %s %s" % [cert.serial, format_time(cert.not_before),
                             format_time(cert.not_after), cert.subject]
      end

      def format_time(time)
        time.strftime('%Y-%m-%dT%H:%M:%S%Z')
      end

      def create_master_cert(ca_key, ca_cert)
        master_key = @host.create_private_key(@settings[:keylength])
        master_csr = @host.create_csr(name: @settings[:certname], key: master_key)
        master_cert = sign_master_cert(ca_key, ca_cert, master_csr)
        return master_key, master_cert
      end

      def sign_master_cert(int_key, int_cert, csr)
        cert = OpenSSL::X509::Certificate.new
        cert.public_key = csr.public_key
        cert.subject = csr.subject
        cert.issuer = int_cert.subject
        cert.version = 2
        cert.serial = 1
        cert.not_before = CERT_VALID_FROM
        cert.not_after = valid_until

        ef = extension_factory_for(int_cert, cert)
        MASTER_EXTENSIONS.each do |ext|
          extension = ef.create_extension(*ext)
          cert.add_extension(extension)
        end

        return unless add_custom_extensions(cert)

        sans =
          if @settings[:subject_alt_names].empty?
            "DNS:puppet, DNS:#{@settings[:certname]}"
          else
            @settings[:subject_alt_names]
          end
        alt_names_ext = ef.create_extension("subjectAltName", sans, false)
        cert.add_extension(alt_names_ext)

        cert.sign(int_key, @digest)
        cert
      end

      # This takes all the custom_attributes and extension requests
      # from the csr_attributes.yaml and adds those to the cert
      def add_custom_extensions(cert)
        if File.exist?(@settings[:csr_attributes])
          custom_attributes = @host.custom_csr_attributes(@settings[:csr_attributes])
          return false unless custom_attributes
          extension_requests = custom_attributes.fetch('extension_requests', {})
          extensions = @host.validated_extensions(extension_requests)
          extensions.each do |ext|
            cert.add_extension(ext)
          end
        end
        @host.errors.empty?
      end

      def create_root_cert
        root_key = @host.create_private_key(@settings[:keylength])
        root_cert = self_signed_ca(root_key)
        root_crl = create_crl_for(root_cert, root_key)

        return root_key, root_cert, root_crl
      end

      def self_signed_ca(key)
        cert = OpenSSL::X509::Certificate.new

        cert.public_key = key.public_key
        cert.subject = OpenSSL::X509::Name.new([["CN", @settings[:root_ca_name]]])
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

        cert.sign(key, @digest)

        cert
      end

      def create_crl_for(cert, key)
        crl = OpenSSL::X509::CRL.new
        crl.version = 1
        crl.issuer = cert.subject

        ef = extension_factory_for(cert)
        crl.add_extension(
          ef.create_extension(["authorityKeyIdentifier", "keyid:always", false]))
        crl.add_extension(
          OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(0)))

        crl.last_update = CERT_VALID_FROM
        crl.next_update = valid_until
        crl.sign(key, @digest)

        crl
      end

      def create_intermediate_cert(root_key, root_cert)
        int_key = @host.create_private_key(@settings[:keylength])
        int_csr = @host.create_csr(name: @settings[:ca_name], key: int_key)
        int_cert = sign_intermediate(root_key, root_cert, int_csr)
        int_crl = create_crl_for(int_cert, int_key)

        return int_key, int_cert, int_crl
      end

      def sign_intermediate(ca_key, ca_cert, csr)
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

        cert.sign(ca_key, @digest)

        cert
      end
    end
  end
end
