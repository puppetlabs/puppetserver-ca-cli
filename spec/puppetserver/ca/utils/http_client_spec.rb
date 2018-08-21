require 'spec_helper'
require 'utils/ssl'

require 'fileutils'

require 'puppetserver/ca/utils/http_client'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/action/generate'

RSpec.describe Puppetserver::Ca::Utils::HttpClient do
  include Utils::SSL

  it 'creates a store that can validate connections to CA' do
    stdout = StringIO.new
    stderr = StringIO.new
    logger = Puppetserver::Ca::Logger.new(:info, stdout, stderr)
    generate_action = Puppetserver::Ca::Action::Generate.new(logger)

    Dir.mktmpdir do |tmpdir|
      cadir = tmpdir
      cacert = File.join(tmpdir, 'ca_crt.pem')
      cakey = File.join(tmpdir, 'ca_key.pem')
      capub = File.join(tmpdir, 'ca_pub.pem')
      rootkey = File.join(tmpdir, 'root_key.pem')
      cacrl = File.join(tmpdir, 'ca_crl.pem')
      localcacert = File.join(tmpdir, 'localcacert.pem')
      localcacrl = File.join(tmpdir, 'localcacrl.pem')
      hostcrl = File.join(tmpdir, 'hostcrl.pem')
      hostcert = File.join(tmpdir, 'hostcert.pem')
      hostprivkey = File.join(tmpdir, 'hostkey.pem')
      hostpubkey = File.join(tmpdir, 'hostpubkey.pem')
      inventory = File.join(tmpdir, 'inventory.txt')
      serial = File.join(tmpdir, 'serial')

      settings = {
        ca_ttl: (5 * 365 * 24 * 60 * 60),
        keylength: 2048,
        root_ca_name: "root",
        ca_name: 'leaf',
        cadir: cadir,
        cacert: cacert,
        cakey: cakey,
        capub: capub,
        rootkey: rootkey,
        cacrl: cacrl,
        localcacert: localcacert,
        localcacrl: localcacrl,
        hostcrl: hostcrl,
        hostcert: hostcert,
        hostprivkey: hostprivkey,
        certname: 'foo',
        certdir: cadir,
        privatekeydir: cadir,
        publickeydir: cadir,
        hostpubkey: hostpubkey,
        cert_inventory: inventory,
        serial: serial,
      }

      signer = Puppetserver::Ca::Utils::SigningDigest.new
      generate_action.generate_pki(settings, signer.digest)

      hostkey = OpenSSL::PKey::RSA.new(2048)
      cakey_content = OpenSSL::PKey.read(File.read(settings[:cakey]))
      cacert_content = OpenSSL::X509::Certificate.new(File.read(settings[:cacert]))
      hostcert_content = create_cert(hostkey, 'foobar', cakey_content, cacert_content)
      File.write(hostcert, hostcert_content)
      File.write(hostprivkey, hostkey)

      FileUtils.cp(settings[:cacert], settings[:localcacert])
      FileUtils.cp(settings[:cacrl], settings[:hostcrl])

      client = Puppetserver::Ca::Utils::HttpClient.new(settings)
      store = client.store
      hostcert = OpenSSL::X509::Certificate.new(File.read(settings[:hostcert]))
      cacert = OpenSSL::X509::Certificate.new(File.read(settings[:cacert]))

      expect(store.verify(hostcert)).to be(true)
      expect(store.verify(cacert)).to be(true)
    end
  end
end
