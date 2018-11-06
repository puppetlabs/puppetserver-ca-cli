require 'spec_helper'
require 'utils/ssl'

require 'fileutils'

require 'puppetserver/ca/utils/http_client'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/action/setup'

RSpec.describe Puppetserver::Ca::Utils::HttpClient do
  include Utils::SSL
  let(:tmpdir) {Dir.mktmpdir}
  let(:settings) {
    with_ca_in(tmpdir) do |config, confdir|
      Puppetserver::Ca::Config::Puppet.new(config).load({
        :hostcert => "#{tmpdir}/hostcert.pem",
        :hostprivkey => "#{tmpdir}/hostkey.pem",
        :confdir => confdir
      })
    end
  }

  after do
    FileUtils.rm_rf(tmpdir)
  end

  it 'creates a store that can validate connections to CA' do
    stdout = StringIO.new
    stderr = StringIO.new
    logger = Puppetserver::Ca::Logger.new(:info, stdout, stderr)
    setup_action = Puppetserver::Ca::Action::Setup.new(logger)

      signer = Puppetserver::Ca::Utils::SigningDigest.new
      setup_action.generate_pki(settings, signer.digest)

      hostkey = OpenSSL::PKey::RSA.new(512)
      cakey_content = OpenSSL::PKey.read(File.read(settings[:cakey]))
      cacert_content = OpenSSL::X509::Certificate.new(File.read(settings[:cacert]))
      hostcert_content = create_cert(hostkey, 'foobar', cakey_content, cacert_content)
      File.write("#{tmpdir}/hostcert.pem", hostcert_content)
      File.write("#{tmpdir}/hostkey.pem", hostkey)

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
