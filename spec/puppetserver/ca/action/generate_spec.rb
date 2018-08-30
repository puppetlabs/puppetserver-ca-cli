require 'spec_helper'
require 'utils/ssl'

require 'tmpdir'
require 'fileutils'
require 'puppetserver/ca/action/generate'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/host'

RSpec.describe Puppetserver::Ca::Action::Generate do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }
  let(:usage) { /.*Usage:.* puppetserver ca generate.*Display this generate specific help output.*/m }

  subject { Puppetserver::Ca::Action::Generate.new(logger) }

  it 'prints the help output & returns 1 if invalid flags are given' do
    _, exit_code = subject.parse(['--hello'])
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to eq(1)
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |puppet_conf, server_conf|
        exit_code = subject.run({ 'puppet-config' => puppet_conf,
                                  'server-config' => server_conf,
                                  'subject-alt-names' => '',
                                  'ca-name' => '',
                                  'certname' => '' })
        expect(stderr.string).to be_empty
        expect(stdout.string.strip).to eq("Generation succeeded. Find your files in #{tmpdir}/ca")
        expect(exit_code).to eq(0)
      end
    end
  end

  it 'generates a bundle ca_crt file, ca_key, int_key, ca_crl, and master cert file' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |puppet_conf, server_conf|
        exit_code = subject.run({ 'puppet-config' => puppet_conf,
                                  'server-config' => server_conf,
                                  'subject-alt-names' => '',
                                  'ca-name' => '',
                                  'certname' => 'foocert' })
        expect(exit_code).to eq(0)
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crt.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_key.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'root_key.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crl.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ssl', 'certs', 'foocert.pem'))).to be true
      end
    end
  end

  describe 'command line name overrides' do
    it 'uses the ca_name as specified on the command line' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |puppet_conf, server_conf|
          exit_code = subject.run({ 'puppet-config' => puppet_conf,
                                    'server-config' => server_conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => 'Foo CA',
                                    'certname' => '' })
          expect(exit_code).to eq(0)
          ca_cert_file = File.join(tmpdir, 'ca', 'ca_crt.pem')
          expect(File.exist?(ca_cert_file)).to be true
          ca_cert = OpenSSL::X509::Certificate.new(File.read(ca_cert_file))
          expect(ca_cert.subject.to_s).to include('Foo CA')
        end
      end
    end

    it 'uses the default ca_name if none specified' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |puppet_conf, server_conf|
          exit_code = subject.run({ 'puppet-config' => puppet_conf,
                                    'server-config' => server_conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => '',
                                    'certname' => '' })
          expect(exit_code).to eq(0)
          ca_cert_file = File.join(tmpdir, 'ca', 'ca_crt.pem')
          expect(File.exist?(ca_cert_file)).to be true
          ca_cert = OpenSSL::X509::Certificate.new(File.read(ca_cert_file))
          expect(ca_cert.subject.to_s).to include('Puppet CA')
        end
      end
    end
  end

  describe 'subject alternative names' do
    it 'accepts unprefixed alt names' do
      result, maybe_code = subject.parse(['--subject-alt-names', 'foo.com'])
      expect(maybe_code).to eq(nil)
      expect(result['subject-alt-names']).to eq('foo.com')
    end

    it 'accepts DNS and IP alt names' do
      result, maybe_code = subject.parse(['--subject-alt-names', 'DNS:foo.com,IP:123.456.789'])
      expect(maybe_code).to eq(nil)
      expect(result['subject-alt-names']).to eq('DNS:foo.com,IP:123.456.789')
    end

    it 'adds default subject alt names to the master cert' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |puppet_conf, server_conf|
          exit_code = subject.run({ 'puppet-config' => puppet_conf,
                                    'server-config' => server_conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => '',
                                    'certname' => 'foo' })
          expect(exit_code).to eq(0)
          master_cert_file = File.join(tmpdir, 'ssl', 'certs', 'foo.pem')
          expect(File.exist?(master_cert_file)).to be true
          master_cert = OpenSSL::X509::Certificate.new(File.read(master_cert_file))
          expect(master_cert.extensions[6].to_s).to eq("subjectAltName = DNS:foo, DNS:puppet")
        end
      end
    end

    it 'adds custom subject alt names to the master cert' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |puppet_conf, server_conf|
          exit_code = subject.run({ 'puppet-config' => puppet_conf,
                                    'server-config' => server_conf,
                                    'subject-alt-names' => 'bar.net,IP:123.123.0.1',
                                    'ca-name' => '',
                                    'certname' => 'foo' })
          expect(exit_code).to eq(0)
          master_cert_file = File.join(tmpdir, 'ssl', 'certs', 'foo.pem')
          expect(File.exist?(master_cert_file)).to be true
          master_cert = OpenSSL::X509::Certificate.new(File.read(master_cert_file))
          expect(master_cert.extensions[6].to_s).to eq("subjectAltName = DNS:bar.net, IP Address:123.123.0.1")
        end
      end
    end
  end

  it 'will not overwrite existing CA files' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |puppet_conf, server_conf|
        exit_code = subject.run({ 'puppet-config' => puppet_conf,
                                  'server-config' => server_conf,
                                  'subject-alt-names' => '',
                                  'ca-name' => '',
                                  'certname' => '' })
        expect(exit_code).to eq(0)
        exit_code2 = subject.run({ 'puppet-config' => puppet_conf,
                                   'server-config' => server_conf,
                                   'subject-alt-names' => '',
                                   'ca-name' => '',
                                   'certname' => '' })
        expect(exit_code2).to eq(1)
        expect(stderr.string).to match(/Existing file.*/)
        expect(stderr.string).to match(/.*please delete the existing files.*/)
      end
    end
  end
end
