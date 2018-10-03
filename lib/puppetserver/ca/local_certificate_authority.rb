require 'puppetserver/ca/host'
require 'puppetserver/ca/utils/file_system'

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

      CLI_AUTH_EXT_OID = "1.3.6.1.4.1.34380.1.3.39"

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

      def initialize(digest, settings)
        @digest = digest
        @host = Host.new(digest)
        @settings = settings
        @errors = []
      end

      def errors
        @errors += @host.errors
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

      def next_serial(serial_file)
        if File.exist?(serial_file)
          File.read(serial_file).to_i
        else
          1
        end
      end

      def format_time(time)
        time.strftime('%Y-%m-%dT%H:%M:%S%Z')
      end

      def create_master_cert(ca_key, ca_cert)
        master_cert = nil
        master_key = @host.create_private_key(@settings[:keylength],
                                              @settings[:hostprivkey],
                                              @settings[:hostpubkey])
        if master_key
          master_csr = @host.create_csr(name: @settings[:certname], key: master_key)
          if @settings[:subject_alt_names].empty?
            alt_names = "DNS:puppet, DNS:#{@settings[:certname]}"
          else
            alt_names = @settings[:subject_alt_names]
          end

          master_cert = sign_authorized_cert(ca_key, ca_cert, master_csr, alt_names)
        end

        return master_key, master_cert
      end

      def load_root
        root_cert = nil
        root_key = nil

        if File.exist?(@settings[:cacert]) && File.exist?(@settings[:cakey]) &&
          File.exist?(@settings[:cacrl]) && File.exist?(@settings[:rootkey])
          loader = Puppetserver::Ca::X509Loader.new(@settings[:cacert], @settings[:cakey], @settings[:cacrl], @settings[:rootkey])
          if loader.errors.empty?
            root_cert = loader.certs[1]
            root_key = loader.root_key
          else
            @errors += loader.errors
          end
        else
          @errors << "CA not initialized. Please set up your CA before attempting to generate certs offline."
        end

        return root_cert, root_key
      end

      # Used when generating certificates offline.
      def load_ca
        signing_cert = nil
        key = nil

        if File.exist?(@settings[:cacert]) && File.exist?(@settings[:cakey]) &&
          File.exist?(@settings[:cacrl]) && File.exist?(@settings[:rootkey])
          loader = Puppetserver::Ca::X509Loader.new(@settings[:cacert], @settings[:cakey], @settings[:cacrl])
          if loader.errors.empty?
            signing_cert = loader.certs[0]
            key = loader.key
          else
            @errors += loader.errors
          end
        else
          @errors << "CA not initialized. Please set up your CA before attempting to generate certs offline."
        end

        return signing_cert, key
      end

      def sign_authorized_cert(int_key, int_cert, csr, alt_names = '')
        cert = OpenSSL::X509::Certificate.new
        cert.public_key = csr.public_key
        cert.subject = csr.subject
        cert.issuer = int_cert.subject
        cert.version = 2
        cert.serial = next_serial(@settings[:serial])
        cert.not_before = CERT_VALID_FROM
        cert.not_after = valid_until

        return unless add_custom_extensions(cert)

        ef = extension_factory_for(int_cert, cert)
        add_authorized_extensions(cert, ef)

        if !alt_names.empty?
          add_subject_alt_names_extension(alt_names, cert, ef)
        end

        cert.sign(int_key, @digest)

        cert
      end

      def add_authorized_extensions(cert, ef)
        MASTER_EXTENSIONS.each do |ext|
          extension = ef.create_extension(*ext)
          cert.add_extension(extension)
        end

        # Status API access for the CA CLI
        cli_auth_ext = OpenSSL::X509::Extension.new(CLI_AUTH_EXT_OID, OpenSSL::ASN1::UTF8String.new("true").to_der, false)
        cert.add_extension(cli_auth_ext)
      end

      def add_subject_alt_names_extension(alt_names, cert, ef)
        alt_names_ext = ef.create_extension("subjectAltName", alt_names, false)
        cert.add_extension(alt_names_ext)
      end

      # This takes all the extension requests from csr_attributes.yaml and
      # adds those to the cert
      def add_custom_extensions(cert)
        extension_requests = @host.get_extension_requests(@settings[:csr_attributes])

        if extension_requests
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

      def create_intermediate_cert(root_key, root_cert, ca_name = @settings[:ca_name])
        int_key = @host.create_private_key(@settings[:keylength])
        int_csr = @host.create_csr(name: ca_name, key: int_key)
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

      def update_serial_file(serial)
        Puppetserver::Ca::Utils::FileSystem.write_file(@settings[:serial], serial, 0644)
      end
    end
  end
end
