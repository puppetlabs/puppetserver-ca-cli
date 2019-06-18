require 'openssl'

module Puppetserver
  module Ca
    # Load, validate, and store x509 objects needed by the Puppet Server CA.
    class X509Loader

      attr_reader :errors, :certs, :cert, :key, :crls, :crl

      def initialize(bundle_path, key_path, chain_path)
        @errors = []

        @certs = load_certs(bundle_path)
        @key = load_key(key_path)
        @crls = load_crls(chain_path)
        @cert = find_signing_cert
        @crl = find_leaf_crl

        validate(@certs, @key, @crls)
      end

      def find_signing_cert
        return if @key.nil? || @certs.empty?

        signing_cert = @certs.find do |cert|
          cert.check_private_key(@key)
        end

        if signing_cert.nil?
          @errors << "Could not find certificate matching private key"
        end

        signing_cert
      end

      def find_leaf_crl
        return if @crls.empty? || @cert.nil?

        leaf_crl = @crls.find do |crl|
          crl.issuer == @cert.subject
        end

        if leaf_crl.nil?
          @errors << 'Could not find CRL issued by CA certificate'
        end

        leaf_crl
      end

      # Only do as much validation as is possible, assume whoever tried to
      # load the objects wrote errors about any invalid ones, but that bundle
      # and chain may be empty arrays and pkey may be nil.
      def validate(bundle, pkey, chain)
        if !@crl.nil? && !@cert.nil?
          validate_crl_and_cert(@crl, @cert)
        end

        if pkey && !@cert.nil?
          validate_cert_and_key(pkey, @cert)
        end

        unless bundle.empty? || @cert.nil?
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
        rescue ArgumentError, OpenSSL::PKey::PKeyError => e
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

      # By creating an X509::Store and validating the leaf cert with it we:
      #   - Ensure a full chain of trust (root to leaf) is within the bundle
      #   - If provided, there are CRLs for the CAs
      #   - If provided, no CAs within the chain of trust have been revoked
      # However this does allow for:
      #   - Additional, ignored, certs and CRLs in the bundle/chain
      #   - certs and CRLs in any order
      def validate_full_chain(certs, crls)
        store = OpenSSL::X509::Store.new
        certs.each {|cert| store.add_cert(cert) }
        if !crls.empty?
          store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
          crls.each {|crl| store.add_crl(crl) }
        end

        unless store.verify(@cert)
          @errors << 'Leaf certificate could not be validated'
          @errors << "Validating cert store returned: #{store.error} - #{store.error_string}"
        end
      end
    end
  end
end
