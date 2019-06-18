require 'spec_helper'
require 'utils/ssl'

require 'tmpdir'

require 'puppetserver/ca/action/generate_csr'
require 'puppetserver/ca/errors'
require 'puppetserver/ca/logger'

RSpec.describe Puppetserver::Ca::Action::GenerateCsr do
  include Utils::SSL

  let(:stdout) {StringIO.new}
  let(:stderr) {StringIO.new}
  let(:logger) {Puppetserver::Ca::Logger.new(:info, stdout, stderr)}

  subject {Puppetserver::Ca::Action::GenerateCsr.new(logger)}

  describe 'flags' do
    it 'takes a single output directory' do
      Dir.mktmpdir do |tmpdir|
        result, maybe_code = subject.parse(['--output-dir', tmpdir])
        expect(maybe_code).to eq(nil)
        expect(result['output-dir']).to eq(tmpdir)
      end
    end

    describe 'flags' do
      it 'takes a single CA name' do
        Dir.mktmpdir do |tmpdir|
          result, maybe_code = subject.parse(['--ca-name', 'foo.example.com',
                                              '--output-dir', tmpdir])
          expect(maybe_code).to eq(nil)
          expect(result['ca-name']).to eq('foo.example.com')
        end
      end

      it 'takes a custom puppet.conf location' do
        Dir.mktmpdir do |tmpdir|
          result, maybe_code = subject.parse(['--ca-name', 'foo',
                                              '--config', '/dev/tcp/example.com',
                                              '--output-dir', tmpdir])
          expect(maybe_code).to be(nil)
          expect(result['config']).to eq('/dev/tcp/example.com')
        end
      end
    end
  end

  describe 'validation' do
    it 'fails with no output directory' do
      result, maybe_code = subject.parse([])
      expect(maybe_code).to eq(1)
      expect(stderr.string).to include('Must specify an output directory to store generated files in')
    end

    it 'fails with nonexistent output directory' do
      result, maybe_code = subject.parse(['--output-dir', '/fake/fake/foo/bar/does/not/exist'])
      expect(maybe_code).to eq(1)
      expect(stderr.string).to include('Specified output directory must exist')
    end

    it 'fails if files to write already exist' do
      Dir.mktmpdir do |tmpdir|
        files = [File.join(tmpdir, 'ca.key'), File.join(tmpdir, 'ca.csr')]
        files.each {|file| IO.write(file, '')}
        result, maybe_code = subject.parse(['--output-dir', tmpdir])
        expect(maybe_code).to eq(1)
        expect(stderr.string).to include('ca.key')
        expect(stderr.string).to include('ca.csr')
        expect(stderr.string).to include('Please delete these files if you want to generate a CSR')
      end
    end
  end

  describe 'csr generation' do
    it 'creates the appropriate files' do
      Dir.mktmpdir do |output_tmpdir|
        Dir.mktmpdir do |puppet_tmpdir|
          with_temp_dirs puppet_tmpdir do |config|
            code = subject.run({'ca-name' => 'foo.example.com',
                                'config' => config,
                                'output-dir' => output_tmpdir})
            expected_name = OpenSSL::X509::Name.new([["CN", 'foo.example.com']])
            expect(code).to eq(0)
            expect(File).to exist(File.join(output_tmpdir, 'ca.csr'))
            expect(File).to exist(File.join(output_tmpdir, 'ca.key'))
            csr = OpenSSL::X509::Request.new(File.read(File.join(output_tmpdir, 'ca.csr')))
            key = OpenSSL::PKey::RSA.new(File.read(File.join(output_tmpdir, 'ca.key')))
            expect(csr).not_to be_nil
            expect(key).not_to be_nil
            expect(csr).to be_kind_of(OpenSSL::X509::Request)
            expect(key).to be_kind_of(OpenSSL::PKey::RSA)
            expect(csr.subject).to eq(expected_name)
          end
        end
      end
    end
  end
end
