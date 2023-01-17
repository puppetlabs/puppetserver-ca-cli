require 'spec_helper'
require 'utils/ssl'
require 'utils/http'

require 'tmpdir'

require 'puppetserver/ca/action/generate'
require 'puppetserver/ca/errors'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/http_client'

RSpec.describe Puppetserver::Ca::Action::Generate do
  include Utils::SSL

  let(:httpclient) { Puppetserver::Ca::Utils::HttpClient }
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  subject { Puppetserver::Ca::Action::Generate.new(logger) }

  describe 'flags' do
    it 'takes a single certname' do
      result, maybe_code = subject.parse(['--certname', 'foo.example.com'])
      expect(maybe_code).to eq(nil)
      expect(result['certnames']).to eq(['foo.example.com'])
    end

    it 'takes a comma separated list of certnames' do
      result, maybe_code = subject.parse(['--certname', 'foo,bar'])
      expect(maybe_code).to eq(nil)
      expect(result['certnames']).to eq(['foo', 'bar'])
    end

    it 'takes a custom puppet.conf location' do
      result, maybe_code = subject.parse(['--certname', 'foo',
                                          '--config', '/dev/tcp/example.com'])
      expect(maybe_code).to be(nil)
      expect(result['config']).to eq('/dev/tcp/example.com')
    end

    it 'takes an optional ttl value' do
      result, maybe_code = subject.parse(['--certname', 'foo.example.com',
                                          '--ttl', '1y'])
      expect(maybe_code).to be(nil)
      expect(result['ttl']).to eq('1y')
    end
  end

  describe 'validation' do
    it 'prints the help output & returns 1 if invalid flags are given' do
      _, code = subject.parse(['--hello', '--certname', "amy.net"])
      expect(code).to eq(1)
      expect(stderr.string).to match(/Error.*--hello/m)
    end

    it 'requires at least one certname' do
      _, code = subject.parse([])
      expect(code).to eq(1)
      expect(stderr.string).to include('one certname is required')
    end

    it 'cannot create certs with the names of flags' do
      result, code = subject.parse(['--certname', '--config'])
      expect(code).to eq(1)
      expect(stderr.string).to include('Cannot manage cert named `--config`')
      expect(result['certnames']).to eq(['--config'])
    end

    it 'requires certnames to be in all lowercase characters' do
      _, code = subject.parse(['--certname', 'uPperCase.net'])
      expect(code).to eq(1)
      expect(stderr.string).to include('Certificate names must be lower case')
    end
  end

  describe 'downloading' do
    let(:success) { Utils::Http::Result.new('204', '') }
    let(:success_with_content) { Utils::Http::Result.new('200', 'some cert') }
    let(:not_found) { Utils::Http::Result.new('404', 'Not Found') }
    let(:connection) { double }

    before do
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:with_connection).and_yield(connection)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:make_store)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:load_cert)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:load_key)
    end

    it 'logs success and returns zero if downloaded' do
      allow(connection).to receive(:put).and_return(success)
      allow(connection).to receive(:get).and_return(success_with_content)
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          code = subject.run({'certnames' => ['foo'],
                              'config' => config,
                              'subject-alt-names' => ''})
          expect(code).to eq(0)
          expect(stdout.string.chomp).to include('Successfully saved certificate for foo')
          expect(stderr.string).to be_empty
        end
      end
    end

    it 'converts the ttl value of 1y to seconds in the request to sign the certificate' do
      allow(connection).to receive(:put).and_return(success)
      expect(connection).to receive(:put).with(/31536000/, any_args).and_return(success).once
      expect(connection).to receive(:get).and_return(not_found).ordered
      expect(connection).to receive(:get).and_return(success_with_content).ordered
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          code = subject.run({'certnames' => ['foo'],
            'config' => config,
            'subject-alt-names' => '',
            'ttl' => '1y'})
          expect(code).to eq(0)
        end
      end
    end

    it 'converts the ttl value without units as seconds in the request to sign the certificate' do
      allow(connection).to receive(:put).and_return(success)
      expect(connection).to receive(:put).with(/7200/, any_args).and_return(success).once
      expect(connection).to receive(:get).and_return(not_found).ordered
      expect(connection).to receive(:get).and_return(success_with_content).ordered
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          code = subject.run({'certnames' => ['foo'],
            'config' => config,
            'subject-alt-names' => '',
            'ttl' => '7200'})
          expect(code).to eq(0)
        end
      end
    end

    it 'errors if there is an invalid ttl' do
      allow(connection).to receive(:put).and_return(success).once
      allow(connection).to receive(:get).and_return(not_found)
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          code = subject.run({'certnames' => ['foo'],
            'config' => config,
            'subject-alt-names' => '',
            'ttl' => '1yy'})
          expect(stderr.string).to match(/Error.* invalid ttl value/m)
          expect(code).to eq(1)
        end
      end
    end

    it 'logs an error if any could not be downloaded' do
      allow(connection).to receive(:put).and_return(success)
      # Look for each cert twice, before and after signing
      allow(connection).to receive(:get).and_return(not_found, not_found,
                                                    not_found, success_with_content)
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          code = subject.run({'certnames' => ['foo', 'bar'],
                              'config' => config,
                              'subject-alt-names' => ''})
          expect(code).to eq(1)
          expect(stdout.string.chomp).to include('Successfully saved certificate for bar')
          expect(stderr.string).to match(/Error.*foo.*not be found/m)
        end
      end
    end

    it 'prints an error if an unknown error occurs' do
      error = Utils::Http::Result.new('500', 'Internal Server Error')
      allow(connection).to receive(:put).and_return(success)
      # Look for each cert twice, before and after signing
      allow(connection).to receive(:get).and_return(error, error,
                                                    not_found, success_with_content)
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          code = subject.run({'certnames' => ['foo', 'bar'],
                              'config' => config,
                              'subject-alt-names' => ''})
          expect(code).to eq(1)
          expect(stdout.string.chomp).to include('Successfully saved certificate for bar')
          expect(stderr.string).
            to match(/Error.*attempting to download.*code: 500.*body: Internal Server Error/m)
        end
      end
    end

    it "refuses to overwrite existing cert files" do
      allow(connection).to receive(:put).and_return(success)
      allow(connection).to receive(:get).and_return(success_with_content)
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          code = subject.run({'certnames' => ['foo'],
                              'config' => config,
                              'subject-alt-names' => ''})
          expect(code).to eq(0)
          expect(stderr.string).to be_empty
          expect(stdout.string.chomp).to include('Successfully saved certificate for foo')

          code = subject.run({'certnames' => ['foo', 'bar'],
                              'config' => config,
                              'subject-alt-names' => ''})
          expect(code).to eq(1)
          expect(stderr.string).to match(/Error.*Existing file at.*foo/m)
          expect(stdout.string.chomp).to include('Successfully saved certificate for bar')
        end
      end
    end

    context "with autosigning enabled" do
      it 'does not request that the cert be signed if the CA already autosigned it' do
        allow(connection).to receive(:put).and_return(success).once
        allow(connection).to receive(:get).and_return(success_with_content)

        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            code = subject.run({'certnames' => ['foo'],
                                'config' => config,
                                'subject-alt-names' => ''})
            expect(code).to eq(0)
            expect(stdout.string.chomp).to include('Successfully saved certificate for foo')
            expect(stdout.string.chomp).to include('Certificate for foo was autosigned.')
          end
        end
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

      let(:settings) {
        { :subject_alt_names => '',
          :keylength => 512,
          :csr_attributes => '$confdir/csr_attributes.yaml' } }

      before(:each) do
        allow(File).to receive(:exist?).with(/csr_attributes\.yaml/).and_return(true)
        allow(File).to receive(:exist?).with(/puppet\.conf/).and_return(true)
        allow(File).to receive(:exist?).with(/ssl/).and_return(true)
        allow(File).to receive(:exist?).with('').and_return(false)

        allow_any_instance_of(Puppetserver::Ca::Action::Generate)
          .to receive(:check_for_existing_ssl_files).and_return([])
      end

      it "adds attributes and extensions to the csr" do
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr.attributes.count).to eq(2)
      end

      it "adds puppet short name attributes and extensions to the csr" do
        csr_attributes['extension_requests'].merge!({'pp_uuid' => "hahahah"})
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr.attributes.count).to eq(2)
      end

      it "return nil for csr if extension is incorrect" do
        csr_attributes['extension_requests'].merge!({'funny_extension' => "hahahah"})
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr).to eq(nil)
      end

      it "return nil for csr if extension name provided is subjectAltName" do
        csr_attributes['extension_requests'].merge!({'subjectAltName' => "ulla"})
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr).to eq(nil)
      end

      it "return nil for csr if attribute name provided isn't correct" do
        csr_attributes['custom_attributes'].merge!({'funny_att' => "hahahah"})
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr).to eq(nil)
      end

      it "return nil for csr if attribute name provided is private" do
        csr_attributes['custom_attributes'].merge!({'extReq' => "ulla"})
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr).to eq(nil)
      end

      it 'logs an error if csr attributes were incorrect' do
        csr_attributes['custom_attributes'].merge!({'funny_att' => "hahahah"})
        allow(YAML).to receive(:load_file).and_return(csr_attributes)
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            code = subject.run({'certnames' => ['foo', 'bar'],
                                'config' => config,
                                'subject-alt-names' => ''})
            expect(code).to eq(1)
            expect(stderr.string).to match(/Error.*Cannot create CSR.*funny_att/m)
          end
        end
      end

      it 'logs an error if csr attributes are not in hash format' do
        csr_attributes['custom_attributes'].merge!({'funny_att' => "hahahah"})
        allow(YAML).to receive(:load_file).and_return(["funny stuff"])
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            code = subject.run({'certnames' => ['foo', 'bar'],
                                'config' => config,
                                'subject-alt-names' => ''})
            expect(code).to eq(1)
            expect(stderr.string).to match(/Error.*Invalid CSR attributes.*Array/m)
          end
        end
      end
    end

    describe 'subject alternative names' do
      it 'accepts unprefixed alt names' do
        result, maybe_code = subject.parse(['--subject-alt-names', 'foo.com',
                                            '--certname', 'ulla.com'])
        expect(maybe_code).to eq(nil)
        expect(result['subject-alt-names']).to eq('foo.com')
      end

      it 'ignores the subject_alt_names setting' do
        settings = { :subject_alt_names => 'DNS:foobar',
                     :keylength => 512,
                     :csr_attributes => '$confdir/csr_attributes.yaml'}
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr.attributes.count).to eq(0)
      end

      it 'adds an attribute to csr if subject_alt_names are passed' do
        settings = { :keylength => 512,
                     :csr_attributes => '$confdir/csr_attributes.yaml'}
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new, "DNS:foobar")
        expect(csr.attributes.count).to eq(1)
      end

      it 'correctly encodes subject alt names' do
        settings = { :keylength => 512,
                     :csr_attributes => '$confdir/csr_attributes.yaml'}
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new, 'DNS:foo, DNS:puppet')

        # If the subject alt names are correctly encoded then we should be able
        # to decode just their context dependent values (ie just the names,
        # not their type labels)
        alt_request = csr.attributes[0].value.value[0].value[0].value[1].value
        alt_names = OpenSSL::ASN1.decode(alt_request)
        alt_names = alt_names.value.map {|name| name.value }
        expect(alt_names).to include('foo', 'puppet')
      end
    end
  end

  describe "ca-client flag" do
    let(:result) { Utils::Http::Result.new('200', 'running') }
    let(:connection) { double }

    before do
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:with_connection).and_yield(connection)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:make_store)
    end

    it 'returns false if nothing is listening on the port' do
      allow(Puppetserver::Ca::Utils::HttpClient).
        to receive(:new).
        and_raise(
          Puppetserver::Ca::ConnectionFailed.create(
            Errno::ECONNREFUSED.new,
            'uncaught exception'))

      settings = {ca_server: 'foo.com', ca_port: 8080}
      expect(httpclient.check_server_online(settings, logger)).to be false
    end

    it 'dies if there are other issues with the connection' do
      allow(Puppetserver::Ca::Utils::HttpClient).
        to receive(:new).
        and_raise(
          Puppetserver::Ca::ConnectionFailed.create(
            StandardError.new,
            'uncaught exception'))

      settings = {ca_server: 'foo.com', ca_port: 8080}
      expect{ httpclient.check_server_online(settings, logger) }.
        to raise_error(Puppetserver::Ca::ConnectionFailed)
    end

    it "refuses to generate a cert if the server is running" do
      allow(connection).to receive(:get).and_return(result)
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          allow(subject).to receive(:generate_authorized_certs) { true }
          code = subject.run({'certnames' => ['foo'],
                              'config' => config,
                              'subject-alt-names' => '',
                              'ca-client' => true})
          expect(code).to eq(1)
          expect(stderr.string).to include("server service is running")
        end
      end
    end

    it "refuses to generate a cert if server status can't be determined" do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          allow(subject).to receive(:generate_authorized_certs) { true }
          allow(httpclient).to receive(:check_server_online).and_raise(
            Puppetserver::Ca::ConnectionFailed.create(
              StandardError.new,
                'UnknownException'))
          expect { subject.run({'certname' => ['foo'],
                                'config' => config,
                                'subject-alt-names' => '',
                                'ca-client' => true})}.to raise_error(Puppetserver::Ca::ConnectionFailed)
        end
      end
    end

    it "generates a cert if server status can't be determined and --force is used" do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          allow(subject).to receive(:generate_authorized_certs) { true }
          allow(httpclient).to receive(:check_server_online).and_raise(
            Puppetserver::Ca::ConnectionFailed.create(
             StandardError.new,
                'UnknownException'))
          expect { subject.run({'certname' => ['foo'],
                                'config' => config,
                                'subject-alt-names' => '',
                                'ca-client' => true,
                                'force' => true})}.not_to raise_error
          expect(stdout.string).to include("Continuing with certificate signing")
        end
      end
    end

    it "does not contact the CA API when a ca-client cert is requested" do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          allow(subject).to receive(:generate_authorized_certs) { true }
          allow(httpclient).to receive(:check_server_online).and_return(false)
          expect(subject).to receive(:generate_certs).never
          code = subject.run({'certnames' => ['foo'],
                              'config' => config,
                              'subject-alt-names' => '',
                              'ca-client' => true})
          expect(code).to eq(0)
          expect(stderr.string).to be_empty
        end
      end
    end

    it 'always supplies the certname as a SAN' do
      Dir.mktmpdir do |tmpdir|
        with_ca_in(tmpdir) do |config, ca_dir|
          allow(httpclient).to receive(:check_server_online).and_return(false)
          code = subject.run({'certnames' => ['foo'],
                              'config' => config,
                              'subject-alt-names' => '',
                              'ca-client' => true})
          expect(stderr.string).to be_empty
          expect(code).to eq(0)
          cert = OpenSSL::X509::Certificate.new(File.read(File.join(ca_dir, "signed", "foo.pem")))
          auth_ext = cert.extensions.find do |ext|
            ext.oid == "subjectAltName"
          end
          expect(auth_ext.value).to eq("DNS:foo")
        end
      end
    end

    it 'adds the certname to supplied SANs' do
      Dir.mktmpdir do |tmpdir|
        with_ca_in(tmpdir) do |config, ca_dir|
          allow(httpclient).to receive(:check_server_online).and_return(false)
          code = subject.run({'certnames' => ['foo'],
                              'config' => config,
                              'subject-alt-names' => 'DNS:carrot',
                              'ca-client' => true})
          expect(stderr.string).to be_empty
          expect(code).to eq(0)
          cert = OpenSSL::X509::Certificate.new(File.read(File.join(ca_dir, "signed", "foo.pem")))
          auth_ext = cert.extensions.find do |ext|
            ext.oid == "subjectAltName"
          end
          expect(auth_ext.value).to eq("DNS:carrot, DNS:foo")
        end
      end
    end

    it "adds the auth extension to the cert" do
      Dir.mktmpdir do |tmpdir|
        with_ca_in(tmpdir) do |config, ca_dir|
          allow(httpclient).to receive(:check_server_online).and_return(false)
          code = subject.run({'certnames' => ['foo'],
                              'config' => config,
                              'subject-alt-names' => '',
                              'ca-client' => true})
          expect(stderr.string).to be_empty
          expect(code).to eq(0)
          cert = OpenSSL::X509::Certificate.new(File.read(File.join(ca_dir, "signed", "foo.pem")))
          auth_ext = cert.extensions.find do |ext|
            ext.oid == "1.3.6.1.4.1.34380.1.3.39"
          end
          expect(auth_ext.value).to eq("..true")
        end
      end
    end

    it "updates the serial file" do
      Dir.mktmpdir do |tmpdir|
        with_ca_in(tmpdir) do |config, ca_dir|
          allow(httpclient).to receive(:check_server_online).and_return(false)
          code = subject.run({'certnames' => ['foo'],
                              'config' => config,
                              'subject-alt-names' => '',
                              'ca-client' => true})
          expect(stderr.string).to be_empty
          expect(code).to eq(0)
          serial = File.read(File.join(ca_dir, "serial")).chomp.to_i
          expect(serial).to eq(2)
        end
      end
    end
  end
end
