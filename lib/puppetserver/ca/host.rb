require 'openssl'

module Puppetserver
  module Ca
    class Host

      def initialize(digest)
        @digest = digest
      end

      def create_private_key(keylength)
        OpenSSL::PKey::RSA.new(keylength)
      end

      def create_csr(name, key, extensions = [])
        csr = OpenSSL::X509::Request.new
        csr.public_key = key.public_key
        csr.subject = OpenSSL::X509::Name.new([["CN", name]])
        csr.version = 2
        add_csr_extension(csr, extensions) unless extensions.empty?
        csr.sign(key, @digest)

        csr
      end

      def create_extension(extension_name, extension_value, critical = false)
        OpenSSL::X509::ExtensionFactory.new.create_extension(extension_name, extension_value, critical)
      end

      def add_csr_extension(csr, extensions)
        attribute_values = OpenSSL::ASN1::Set [OpenSSL::ASN1::Sequence(extensions)]
        att = OpenSSL::X509::Attribute.new('extReq', attribute_values)
        csr.add_attribute(att)
      end
    end
  end
end
