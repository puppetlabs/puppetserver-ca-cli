require 'openssl'

module Puppetserver
  module Ca
    class X509Loader

      attr_reader :errors, :certs, :key, :crls
      def initialize(bundle_file, key_file, chain_file)
        @bundle_file = bundle_file
        @key_file = key_file
        @chain_file = chain_file

        @certs, @key, @crls = nil, nil, nil

        @errors = []
      end

      def load_and_validate!
        @certs = parse_certs(@bundle_file)
        @key = parse_key(@key_file)

        @crls = @chain_file ? parse_crls(@chain_file) : []

        unless @crls.empty? || @certs.empty?
          validate_crl_and_cert(@crls.first, @certs.first)
        end

        if @key && !@certs.empty?
          validate_cert_and_key(@key, @certs.first)
        end

        unless @certs.empty?
          validate_full_chain(@certs, @crls)
        end
      end

      def parse_certs(bundle)
        errs = []
        errs << "Could not parse #{bundle}"

        bundle_string = File.read(bundle)
        cert_strings = bundle_string.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
        certs = cert_strings.map do |cert_string|
          begin
            OpenSSL::X509::Certificate.new(cert_string)
          rescue OpenSSL::X509::CertificateError
            errs << "Could not parse entry:\n#{cert_string}"

            nil
          end
        end.compact

        if certs.empty?
          errs << "Could not detect any certs within #{bundle}"
        end

        @errors += errs if errs.length > 1

        return certs
      end

      def parse_key(key_path)
        begin
          OpenSSL::PKey.read(File.read(key_path))
        rescue ArgumentError => e
          @errors << "Could not parse #{key_path}"

          return nil
        end
      end

      def parse_crls(chain)
        errs = []
        errs << "Could not parse #{chain}"

        chain_string = File.read(chain)
        crl_strings = chain_string.scan(/-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m)
        actual_crls = crl_strings.map do |crl_string|
          begin
            OpenSSL::X509::CRL.new(crl_string)
          rescue OpenSSL::X509::CRLError
            errs << "Could not parse entry:\n#{crl_string}"

            nil
          end
        end.compact

        if actual_crls.empty?
          errs << "Could not detect any crls within #{chain}"
        end

        @errors += errs if errs.length > 1

        return actual_crls
      end

      def validate_cert_and_key(key, cert)
        unless cert.check_private_key(key)
          @errors << 'Private key and certificate do not match'
        end
      end

      def validate_crl_and_cert(crl, cert)
        unless crl.issuer == cert.subject
          @errors << 'Leaf CRL was not issued by leaf certificate'
        end
      end

      def validate_full_chain(certs, crls)
        store = OpenSSL::X509::Store.new
        certs.each {|cert| store.add_cert(cert) }
        if crls
          store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
          crls.each {|crl| store.add_crl(crl) }
        end

        unless store.verify(certs.first)
          @errors << 'Leaf certificate could not be validated'
        end
      end
    end
  end
end
