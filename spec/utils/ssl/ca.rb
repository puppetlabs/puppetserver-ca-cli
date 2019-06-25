require 'openssl'

module Utils
  module SSL
    class CA

      PRIVATE_KEY_LENGTH = 2048
      FIVE_YEARS = 5 * 365 * 24 * 60 * 60
      CA_EXTENSIONS = [
          ['basicConstraints', 'CA:TRUE', true],
          ['keyUsage', 'keyCertSign, cRLSign', true],
          ['subjectKeyIdentifier', 'hash', false],
          ['authorityKeyIdentifier', 'keyid:always', false]
      ]
      NODE_EXTENSIONS = [
          ['keyUsage', 'digitalSignature', true],
          ['subjectKeyIdentifier', 'hash', false]
      ]
      DEFAULT_SIGNING_DIGEST = OpenSSL::Digest::SHA256.new
      DEFAULT_REVOCATION_REASON = OpenSSL::OCSP::REVOKED_STATUS_KEYCOMPROMISE
      ROOT_CA_NAME = '/CN=root-ca-\u{2070E}'
      REVOKED_INT_CA_NAME = '/CN=revoked-int-ca-\u16A0'
      INT_CA_NAME = '/CN=unrevoked-int-ca\u06FF\u16A0\u{2070E}'
      LEAF_CA_NAME = '/CN=leaf-ca-\u06FF'
      EXPLANATORY_TEXT = <<-EOT
# Root Issuer: #{ROOT_CA_NAME}
# Intermediate Issuer: #{INT_CA_NAME}
# Leaf Issuer: #{LEAF_CA_NAME}
      EOT


      def initialize
        @root_key = CA.create_private_key
        @root_cert = CA.self_signed_ca(@root_key, ROOT_CA_NAME)
        @root_crl = CA.create_crl_for(@root_cert, @root_key)
      end

      def sign_csr(csr)
        extensions = CA.get_csr_extension_reqs(csr)
        CA.sign(@root_key, @root_cert, csr, extensions)
      end

      def self.create_private_key(length = PRIVATE_KEY_LENGTH)
        OpenSSL::PKey::RSA.new(length)
      end

      def self.self_signed_ca(key, name)
        cert = OpenSSL::X509::Certificate.new

        cert.public_key = key.public_key
        cert.subject = OpenSSL::X509::Name.parse(name)
        cert.issuer = cert.subject
        cert.version = 2
        cert.serial = rand(2 ** 128)

        not_before = CA.just_now
        cert.not_before = not_before
        cert.not_after = not_before + FIVE_YEARS

        ext_factory = CA.extension_factory_for(cert, cert)
        CA_EXTENSIONS.each do |ext|
          extension = ext_factory.create_extension(*ext)
          cert.add_extension(extension)
        end

        cert.sign(key, DEFAULT_SIGNING_DIGEST)

        cert
      end

      def self.create_csr(key, name)
        csr = OpenSSL::X509::Request.new

        csr.public_key = key.public_key
        csr.subject = OpenSSL::X509::Name.parse(name)
        csr.version = 2
        csr.sign(key, DEFAULT_SIGNING_DIGEST)

        csr
      end

      def self.sign(ca_key, ca_cert, csr, extensions = NODE_EXTENSIONS)
        cert = OpenSSL::X509::Certificate.new

        cert.public_key = csr.public_key
        cert.subject = csr.subject
        cert.issuer = ca_cert.subject
        cert.version = 2
        cert.serial = rand(2 ** 128)

        not_before = CA.just_now
        cert.not_before = not_before
        cert.not_after = not_before + FIVE_YEARS

        ext_factory = CA.extension_factory_for(ca_cert, cert)
        extensions.each do |ext|
          extension = ext_factory.create_extension(*ext)
          cert.add_extension(extension)
        end

        cert.sign(ca_key, DEFAULT_SIGNING_DIGEST)

        cert
      end

      def self.create_crl_for(ca_cert, ca_key)
        crl = OpenSSL::X509::CRL.new
        crl.version = 1
        crl.issuer = ca_cert.subject

        ef = CA.extension_factory_for(ca_cert)
        crl.add_extension(
            ef.create_extension(["authorityKeyIdentifier", "keyid:always", false]))
        crl.add_extension(
            OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(0)))

        not_before = CA.just_now
        crl.last_update = not_before
        crl.next_update = not_before + FIVE_YEARS
        crl.sign(ca_key, DEFAULT_SIGNING_DIGEST)

        crl
      end

      def self.revoke(serial, crl, ca_key)
        revoked = OpenSSL::X509::Revoked.new
        revoked.serial = serial
        revoked.time = Time.now
        revoked.add_extension(
            OpenSSL::X509::Extension.new("CRLReason",
                                         OpenSSL::ASN1::Enumerated(DEFAULT_REVOCATION_REASON)))

        crl.add_revoked(revoked)
        extensions = crl.extensions.group_by {|e| e.oid == 'crlNumber'}
        crl_number = extensions[true].first
        unchanged_exts = extensions[false]

        next_crl_number = crl_number.value.to_i + 1
        new_crl_number_ext = OpenSSL::X509::Extension.new("crlNumber",
                                                          OpenSSL::ASN1::Integer(next_crl_number))

        crl.extensions = unchanged_exts + [new_crl_number_ext]
        crl.sign(ca_key, DEFAULT_SIGNING_DIGEST)

        crl
      end

      def self.flatten_reqs(item)
        if item.is_a?(OpenSSL::ASN1::ASN1Data)
          return flatten_reqs(item.value)
        elsif item.is_a?(Array)
          oid = item.find {|entry| entry.is_a?(OpenSSL::ASN1::ObjectId)}
          value = item.find {|entry| entry.is_a?(OpenSSL::ASN1::OctetString)}
          required = item.find {|entry| entry.is_a?(OpenSSL::ASN1::Boolean)}
          if oid.nil? || value.nil?
            return item.map {|i| flatten_reqs(i)}.flatten
          else
            return {
                :oid => oid.value,
                :value => value.value,
                :required => required.nil? ? false : required.value,
            }
          end
        else
          return item
        end
      end

      def self.get_csr_extension_reqs(csr)
        ext_req_attr = csr.attributes
                           .find {|attr| attr.oid = 'extReq'}

        raw_reqs = flatten_reqs(ext_req_attr.value)

        return raw_reqs.map do |ext|
          [ext[:oid], ext[:value], ext[:required]]
        end
      end

      private

      def self.just_now
        Time.now - 1
      end

      def self.extension_factory_for(ca, cert = nil)
        ef = OpenSSL::X509::ExtensionFactory.new
        ef.issuer_certificate = ca
        ef.subject_certificate = cert if cert

        ef
      end

      def self.bundle(*items)
        items.map {|i| EXPLANATORY_TEXT + i.to_pem}.join("\n")
      end
    end
  end
end
