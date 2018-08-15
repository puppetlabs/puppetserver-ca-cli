require 'spec_helper'
require 'utils/ssl'

require 'fileutils'

require 'puppetserver/utils/http_client'
require 'puppetserver/utils/signing_digest'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/generate_action'

RSpec.describe Puppetserver::Utils::HttpClient do
  include Utils::SSL

  it 'creates a store that can validate connections to CA' do
    stdout = StringIO.new
    stderr = StringIO.new
    logger = Puppetserver::Ca::Logger.new(:info, stdout, stderr)
    generate_action = Puppetserver::Ca::GenerateAction.new(logger)

    Dir.mktmpdir do |tmpdir|
      cadir = tmpdir
      cacert = File.join(tmpdir, 'ca_crt.pem')
      cakey = File.join(tmpdir, 'ca_key.pem')
      rootkey = File.join(tmpdir, 'root_key.pem')
      cacrl = File.join(tmpdir, 'ca_crl.pem')
      localcacert = File.join(tmpdir, 'localcacert.pem')
      hostcrl = File.join(tmpdir, 'hostcrl.pem')
      hostcert = File.join(tmpdir, 'hostcert.pem')
      hostprivkey = File.join(tmpdir, 'hostkey.pem')

      settings = {
        ca_ttl: (5 * 365 * 24 * 60 * 60),
        keylength: 2048,
        root_ca_name: "root",
        ca_name: 'leaf',
        cadir: cadir,
        cacert: cacert,
        cakey: cakey,
        rootkey: rootkey,
        cacrl: cacrl,
        localcacert: localcacert,
        hostcrl: hostcrl,
        hostcert: hostcert,
        hostprivkey: hostprivkey,
      }

      signer = Puppetserver::Utils::SigningDigest.new
      generate_action.generate_root_and_intermediate_ca(settings, signer.digest)

      hostkey = OpenSSL::PKey::RSA.new(2048)
      cakey_content = OpenSSL::PKey.read(File.read(settings[:cakey]))
      cacert_content = OpenSSL::X509::Certificate.new(File.read(settings[:cacert]))
      hostcert_content = create_cert(hostkey, 'foobar', cakey_content, cacert_content)
      File.write(hostcert, hostcert_content)
      File.write(hostprivkey, hostkey)

      FileUtils.cp(settings[:cacert], settings[:localcacert])
      FileUtils.cp(settings[:cacrl], settings[:hostcrl])

      client = Puppetserver::Utils::HttpClient.new(settings)
      store = client.store
      hostcert = OpenSSL::X509::Certificate.new(File.read(settings[:hostcert]))
      cacert = OpenSSL::X509::Certificate.new(File.read(settings[:cacert]))

      expect(store.verify(hostcert)).to be(true)
      expect(store.verify(cacert)).to be(true)
    end
  end
end
