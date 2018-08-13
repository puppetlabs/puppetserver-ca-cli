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

      def create_csr(name, key)
        csr = OpenSSL::X509::Request.new
        csr.public_key = key.public_key
        csr.subject = OpenSSL::X509::Name.new([["CN", name]])
        csr.version = 2
        csr.sign(key, @digest)

        csr
      end
    end
  end
end
