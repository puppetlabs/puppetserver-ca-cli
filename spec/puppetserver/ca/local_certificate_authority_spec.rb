require 'puppetserver/ca/local_certificate_authority'

require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/signing_digest'

require 'utils/ssl'
require 'stringio'

RSpec.describe Puppetserver::Ca::LocalCertificateAuthority do
  include Utils::SSL

  let(:tmpdir) { Dir.mktmpdir }
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }
  let(:settings) {
    with_ca_in(tmpdir) do |config, confdir|
      return Puppetserver::Ca::Config::Puppet.new(config).load(cli_overrides: {confdir: confdir }, logger: logger)
    end
  }

  after(:each) do
    FileUtils.rm_rf(tmpdir)
  end

  let(:subject) { Puppetserver::Ca::LocalCertificateAuthority.new(OpenSSL::Digest::SHA256.new, settings) }

  describe '#initialize' do
    it 'loads ssl assets if they exist' do
      expect(subject.cert).to be_kind_of(OpenSSL::X509::Certificate)
      expect(subject.key).to be_kind_of(OpenSSL::PKey::RSA)
      expect(subject.crl).to be_kind_of(OpenSSL::X509::CRL)
    end

    context 'when an ssl asset is missing' do
      let(:cadir) { Dir.mktmpdir }
      let(:settings) {
        with_ca_in(cadir) do |config|
          return Puppetserver::Ca::Config::Puppet.new(config).load(cli_overrides: {cacert: '/some/rando/path'}, logger: logger)
        end
      }
      after(:each) { FileUtils.rm_rf(cadir) }
      it 'does not load ssl assets if they are not found' do
        expect(subject.cert).to be_nil
        expect(subject.key).to be_nil
        expect(subject.crl).to be_nil
      end
    end

    context 'with a malformed certificate' do
      before do
        File.write(settings[:cacert], 'This_is_not_a_valid_cert')
      end
      it 'adds an error to the ca object' do
        expect(subject.errors).not_to be_empty
      end
    end
  end

  describe "#create_server_cert" do
    context "without a csr_attributes file" do
      it "adds only MA extensions to the csr" do
        root_key, root_cert, root_crl = subject.create_root_cert
        subject.create_intermediate_cert(root_key, root_cert)

        _, cert = subject.create_server_cert
        expect(cert.extensions.count).to eq(8)
      end
    end

    context "with a csr_attributes file" do
      let(:csr_attributes) {
        { 'extension_requests' => {
            '1.3.6.1.4.1.34380.1.1.1' => 'ED803750-E3C7-44F5-BB08-41A04433FE2E',
            '1.3.6.1.4.1.34380.1.1.1.4' => 'I am undefined but still work' },
          'custom_attributes' => {
            '1.2.840.113549.1.9.7' => '342thbjkt82094y0uthhor289jnqthpc2290' }
        }
      }

      before(:each) do
        allow(File).to receive(:exist?).with(/ca_crt\.pem/).and_return(true)
        allow(File).to receive(:exist?).with(/ca_key\.pem/).and_return(true)
        allow(File).to receive(:exist?).with(/ca_crl\.pem/).and_return(true)
        allow(File).to receive(:exist?).with(/serial/).and_return(false)
        allow(File).to receive(:exist?).with(/public_keys/).and_return(false)
        allow(File).to receive(:exist?).with(/private_keys/).and_return(false)

        # The Host#{create_server_cert,create_intermediate_cert,create_root_cert}
        # methods all call `create_csr` and don't pass the `csr_attributes_path`
        # keyword arg, so we sometimes call File.exist?(''). Then later we call
        # create_server_cert, which does load the csr attributes.
        allow(File).to receive(:exist?).with('').and_return(false)
        allow(File).to receive(:exist?).with(/csr_attributes.yaml/).and_return(true)
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
      end

      it "adds extensions from csr_attributes yaml to the csr" do
        root_key, root_cert, root_crl = subject.create_root_cert
        subject.create_intermediate_cert(root_key, root_cert)

        _, cert = subject.create_server_cert
        expect(cert.extensions.count).to eq(10)
      end
    end
  end

  describe "#sign_authorized_cert" do
    it "has the special auth extension" do
      root_key, root_cert, root_crl = subject.create_root_cert
      subject.create_intermediate_cert(root_key, root_cert)

      host = Puppetserver::Ca::Host.new(Puppetserver::Ca::Utils::SigningDigest.new.digest)
      private_key = host.create_private_key(settings[:keylength])
      csr = host.create_csr(name: "foo", key: private_key)

      cert = subject.sign_authorized_cert(csr)
      auth_ext = cert.extensions.find do |ext|
        ext.oid == "1.3.6.1.4.1.34380.1.3.39"
      end
      expect(auth_ext.value).to eq("..true")
    end

    it "does not add default subject alt names" do
      root_key, root_cert, root_crl = subject.create_root_cert
      subject.create_intermediate_cert(root_key, root_cert)

      host = Puppetserver::Ca::Host.new(Puppetserver::Ca::Utils::SigningDigest.new.digest)
      private_key = host.create_private_key(settings[:keylength])
      csr = host.create_csr(name: "foo", key: private_key)

      cert = subject.sign_authorized_cert(csr)
      san = cert.extensions.find do |ext|
        ext.oid == "subjectAltNames"
      end
      expect(san).to be(nil)
    end

    it "adds subject alt names if specified" do
      root_key, root_cert, root_crl = subject.create_root_cert
      subject.create_intermediate_cert(root_key, root_cert)

      host = Puppetserver::Ca::Host.new(Puppetserver::Ca::Utils::SigningDigest.new.digest)
      private_key = host.create_private_key(settings[:keylength])
      csr = host.create_csr(name: "foo", key: private_key)

      cert = subject.sign_authorized_cert(csr, "DNS:bar,IP:123.0.0.5")
      san = cert.extensions.find do |ext|
        ext.oid == "subjectAltName"
      end
      expect(san.value).to eq("DNS:bar, IP Address:123.0.0.5")
    end
  end
  context "hex serial file" do
    before do
      File.write(settings[:serial], '01C')
      allow(File).to receive(:exist?).and_return(true)
    end
    it "converts the hex serial to integer on read" do
      expect(subject.next_serial(settings[:serial])).to eq(28)
    end
    it "converts the hex serial to integer on write" do
      subject.update_serial_file(28)
      expect(File.read(settings[:serial])).to match(/1c/i)
    end
  end
end
