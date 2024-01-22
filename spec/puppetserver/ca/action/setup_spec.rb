require 'spec_helper'
require 'utils/ssl'
require 'shared_examples/setup'

require 'tmpdir'
require 'fileutils'
require 'puppetserver/ca/action/setup'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/host'

RSpec.describe Puppetserver::Ca::Action::Setup do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }
  let(:usage) { /.*Usage:.* puppetserver ca setup.*Display this command-specific help output.*/m }

  subject { Puppetserver::Ca::Action::Setup.new(logger) }

  it 'prints the help output & returns 1 if invalid flags are given' do
    _, exit_code = subject.parse(['--hello'])
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to eq(1)
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = subject.run({ 'config' => conf,
                                  'subject-alt-names' => '',
                                  'ca-name' => '',
                                  'root-ca-name' => '',
                                  'certname' => '' })
        puts stderr.string
        expect(stderr.string).to be_empty
        expect(stdout.string.strip).to eq("Generation succeeded. Find your files in #{tmpdir}/ca")
        expect(exit_code).to eq(0)
      end
    end
  end

  include_examples 'properly sets up ca and ssl dir', Puppetserver::Ca::Action::Setup

  describe 'command line name overrides' do
    it 'uses the ca_name and root_ca_name as specified on the command line' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |conf|
          exit_code = subject.run({ 'config' => conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => 'Foo CA',
                                    'root-ca-name' => 'Foo Root CA',
                                    'certname' => '' })
          expect(exit_code).to eq(0)
          ca_cert_file = File.join(tmpdir, 'ca', 'ca_crt.pem')
          expect(File.exist?(ca_cert_file)).to be true
          ca_cert = OpenSSL::X509::Certificate.new(File.read(ca_cert_file))
          expect(ca_cert.subject.to_s).to include('Foo CA')
          expect(ca_cert.issuer.to_s).to include('Foo Root CA')
        end
      end
    end

    it 'uses the default ca_name if none specified' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |conf|
          exit_code = subject.run({ 'config' => conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => '',
                                    'root-ca-name' => '',
                                    'certname' => '' })
          expect(exit_code).to eq(0)
          ca_cert_file = File.join(tmpdir, 'ca', 'ca_crt.pem')
          expect(File.exist?(ca_cert_file)).to be true
          ca_cert = OpenSSL::X509::Certificate.new(File.read(ca_cert_file))
          expect(ca_cert.subject.to_s).to include('Puppet CA')
          expect(ca_cert.issuer.to_s).to match(/Puppet Root CA: ([0-9a-f]{14})/)
        end
      end
    end
  end
end
