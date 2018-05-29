require 'fileutils'

module Puppetserver
  module Ca
    module Stub
      KEY_PATH    = '/etc/puppetlabs/puppet/ssl/ca/ca_key.pem'
      BUNDLE_PATH = '/etc/puppetlabs/puppet/ssl/ca/ca_crt.pem'
      CRL_PATH    = '/etc/puppetlabs/puppet/ssl/ca/ca_crl.pem'

      def self.import(key, bundle, crl)
        FileUtils.copy(File.absolute_path(key), KEY_PATH)
        FileUtils.copy(File.absolute_path(bundle), BUNDLE_PATH)
        FileUtils.copy(File.absolute_path(crl), CRL_PATH)
      end
    end
  end
end
