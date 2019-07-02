require 'openssl'
require 'utils/ssl'

module Utils
  module SSL
    class CA
      include Utils::SSL

      def initialize
        @root_key = create_private_key
        @root_cert = self_signed_ca(@root_key, ROOT_CA_NAME)
        @root_crl = create_crl_for(@root_cert, @root_key)
      end

      def sign(csr)
        extensions = get_csr_extension_reqs(csr)
        sign_csr(@root_key, @root_cert, csr, extensions)
      end


    end
  end
end
