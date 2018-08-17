module Puppetserver
  module Ca
    module Utils
      class SigningDigest

        attr_reader :errors, :digest

        def initialize
          @errors = []
          if OpenSSL::Digest.const_defined?('SHA256')
            @digest = OpenSSL::Digest::SHA256.new
          elsif OpenSSL::Digest.const_defined?('SHA1')
            @digest = OpenSSL::Digest::SHA1.new
          elsif OpenSSL::Digest.const_defined?('SHA512')
            @digest = OpenSSL::Digest::SHA512.new
          elsif OpenSSL::Digest.const_defined?('SHA384')
            @digest = OpenSSL::Digest::SHA384.new
          elsif OpenSSL::Digest.const_defined?('SHA224')
            @digest = OpenSSL::Digest::SHA224.new
          else
            @errors << "Error: No FIPS 140-2 compliant digest algorithm in OpenSSL::Digest"
          end
        end
      end
    end
  end
end
