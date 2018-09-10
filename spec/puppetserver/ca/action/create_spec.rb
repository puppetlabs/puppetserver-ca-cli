require 'spec_helper'
require 'utils/ssl'

require 'tmpdir'

require 'puppetserver/ca/action/create'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/http_client'

RSpec.describe Puppetserver::Ca::Action::Create do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  subject { Puppetserver::Ca::Action::Create.new(logger) }

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
    Result = Struct.new(:code, :body)

    let(:success) { Result.new('204', '') }
    let(:success_with_content) { Result.new('200', 'some cert') }
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

    it 'logs an error if any could not be downloaded' do
      not_found = Result.new('404', 'Not Found')
      allow(connection).to receive(:put).and_return(success)
      allow(connection).to receive(:get).and_return(not_found, success_with_content)
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
      error = Result.new('500', 'Internal Server Error')
      allow(connection).to receive(:put).and_return(success)
      allow(connection).to receive(:get).and_return(error, success_with_content)
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
        allow(File).to receive(:exist?).and_return(true)
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

      it 'adds no attributes to csr if subject_alt_names is empty' do
        settings = { :subject_alt_names => '',
                     :keylength => 512,
                     :csr_attributes => '$confdir/csr_attributes.yaml'}
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr.attributes.count).to eq(0)
      end

      it 'adds an attribute to csr if subject_alt_names are present' do
        settings = { :subject_alt_names => 'DNS:foo',
                     :keylength => 512,
                     :csr_attributes => '$confdir/csr_attributes.yaml'}
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)
        expect(csr.attributes.count).to eq(1)
      end

      it 'correctly encodes subject alt names' do
        settings = { :subject_alt_names => 'DNS:foo, DNS:puppet',
                     :keylength => 512,
                     :csr_attributes => '$confdir/csr_attributes.yaml'}
        _, csr = subject.generate_key_csr('foo', settings, OpenSSL::Digest::SHA256.new)

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
end
