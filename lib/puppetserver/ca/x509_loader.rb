require 'openssl'

module Puppetserver
  module Ca
    class X509Loader

      attr_reader :errors, :certs, :key, :crls

      def initialize(bundle_path, key_path, chain_path = nil)
        @errors = []

        @certs = load_certs(bundle_path)
        @key = load_key(key_path)
        @crls = chain_path ? load_crls(chain_path) : []

        validate(@certs, @key, @crls)
      end

      def validate(bundle, pkey, chain)
        if !chain.empty? && !bundle.empty?
          validate_crl_and_cert(chain.first, bundle.first)
        end

        if pkey && !bundle.empty?
          validate_cert_and_key(pkey, bundle.first)
        end

        unless bundle.empty?
          validate_full_chain(bundle, chain)
        end
      end

      def load_certs(bundle_path)
        certs, errs = [], []

        bundle_string = File.read(bundle_path)
        cert_strings = bundle_string.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
        cert_strings.each do |cert_string|
          begin
            certs << OpenSSL::X509::Certificate.new(cert_string)
          rescue OpenSSL::X509::CertificateError
            errs << "Could not parse entry:\n#{cert_string}"
          end
        end

        if certs.empty?
          errs << "Could not detect any certs within #{bundle_path}"
        end

        unless errs.empty?
          @errors << "Could not parse #{bundle_path}"
          @errors += errs
        end

        return certs
      end

      def load_key(key_path)
        begin
          OpenSSL::PKey.read(File.read(key_path))
        rescue ArgumentError => e
          @errors << "Could not parse #{key_path}"

          return nil
        end
      end

      def load_crls(chain_path)
        errs, crls = [], []

        chain_string = File.read(chain_path)
        crl_strings = chain_string.scan(/-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m)
        crl_strings.map do |crl_string|
          begin
            crls << OpenSSL::X509::CRL.new(crl_string)
          rescue OpenSSL::X509::CRLError
            errs << "Could not parse entry:\n#{crl_string}"
          end
        end

        if crls.empty?
          errs << "Could not detect any crls within #{chain_path}"
        end

        unless errs.empty?
          @errors << "Could not parse #{chain_path}"
          @errors += errs
        end

        return crls
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
