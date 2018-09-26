require 'puppetserver/ca/local_certificate_authority'

require 'puppetserver/ca/utils/signing_digest'

RSpec.describe Puppetserver::Ca::LocalCertificateAuthority do

  let(:settings) {
    { :ca_ttl => 157680000,
      :ca_name => 'bulla2',
      :subject_alt_names => '',
      :root_ca_name => 'bulla',
      :certname => 'ulla',
      :keylength => 512,
      :hostprivkey => '$privatekeydir/$certname.pem',
      :hostpubkey => '$publickeydir/$certname.pem',
      :csr_attributes => '$confdir/csr_attributes.yaml',
      :serial => '$cadir/serial' } }

  let(:subject) { Puppetserver::Ca::LocalCertificateAuthority.new(OpenSSL::Digest::SHA256.new, settings) }

  describe "#create_master_cert" do
    context "without a csr_attributes file" do
      it "adds only MA extensions to the csr" do
        root_key, root_cert, root_crl = subject.create_root_cert
        int_key, int_cert, int_crl = subject.create_intermediate_cert(root_key, root_cert)

        _, cert = subject.create_master_cert(int_key, int_cert)
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
        allow(File).to receive(:exist?).and_return(true)
        allow(File).to receive(:exist?).with('$cadir/serial').and_return(false)
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
      end

      it "adds extensions from csr_attributes yaml to the csr" do
        root_key, root_cert, root_crl = subject.create_root_cert
        int_key, int_cert, int_crl = subject.create_intermediate_cert(root_key, root_cert)

        _, cert = subject.create_master_cert(int_key, int_cert)
        expect(cert.extensions.count).to eq(10)
      end
    end
  end

  describe "#sign_authorized_cert" do
    it "has the special auth extension" do
      root_key, root_cert, root_crl = subject.create_root_cert
      int_key, int_cert, int_crl = subject.create_intermediate_cert(root_key, root_cert)

      host = Puppetserver::Ca::Host.new(Puppetserver::Ca::Utils::SigningDigest.new.digest)
      private_key = host.create_private_key(settings[:keylength])
      csr = host.create_csr(name: "foo", key: private_key)

      cert = subject.sign_authorized_cert(int_key, int_cert, csr)
      auth_ext = cert.extensions.find do |ext|
        ext.oid == "1.3.6.1.4.1.34380.1.3.39"
      end
      expect(auth_ext.value).to eq("..true")
    end

    it "does not add default subject alt names" do
      root_key, root_cert, root_crl = subject.create_root_cert
      int_key, int_cert, int_crl = subject.create_intermediate_cert(root_key, root_cert)

      host = Puppetserver::Ca::Host.new(Puppetserver::Ca::Utils::SigningDigest.new.digest)
      private_key = host.create_private_key(settings[:keylength])
      csr = host.create_csr(name: "foo", key: private_key)

      cert = subject.sign_authorized_cert(int_key, int_cert, csr)
      san = cert.extensions.find do |ext|
        ext.oid == "subjectAltNames"
      end
      expect(san).to be(nil)
    end

    it "adds subject alt names if specified" do
      root_key, root_cert, root_crl = subject.create_root_cert
      int_key, int_cert, int_crl = subject.create_intermediate_cert(root_key, root_cert)

      host = Puppetserver::Ca::Host.new(Puppetserver::Ca::Utils::SigningDigest.new.digest)
      private_key = host.create_private_key(settings[:keylength])
      csr = host.create_csr(name: "foo", key: private_key)

      cert = subject.sign_authorized_cert(int_key, int_cert, csr, "DNS:bar,IP:123.0.0.5")
      san = cert.extensions.find do |ext|
        ext.oid == "subjectAltName"
      end
      expect(san.value).to eq("DNS:bar, IP Address:123.0.0.5")
    end
  end
end
