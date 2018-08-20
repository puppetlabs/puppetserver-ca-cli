require 'spec_helper'
require 'utils/ssl'

require 'tmpdir'
require 'fileutils'

require 'puppetserver/ca/cli'
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
    exit_code = Puppetserver::Ca::Cli.run(['generate', '--hello'], stdout, stderr)
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to eq(1)
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = Puppetserver::Ca::Cli.run(['generate', '--config', conf], stdout, stderr)
        expect(stderr.string).to be_empty
        expect(stdout.string.strip).to eq("Generation succeeded. Find your files in #{tmpdir}/ca")
        expect(exit_code).to eq(0)
      end
    end
  end

  it 'generates a bundle ca_crt file, ca_key, int_key, and ca_crl file' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = subject.run({ 'config' => conf, 'subject_alt_names' => '' })
        expect(exit_code).to eq(0)
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crt.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_key.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'root_key.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crl.pem'))).to be true
      end
    end
  end

  describe 'subject alternative names' do
    it 'accepts unprefixed alt names' do
      result, maybe_code = subject.parse(['--subject-alt-names', 'foo.com'])
      expect(maybe_code).to eq(nil)
      expect(result['subject_alt_names']).to eq('foo.com')
    end

    it 'accepts DNS and IP alt names' do
      result, maybe_code = subject.parse(['--subject-alt-names', 'DNS:foo.com,IP:123.456.789'])
      expect(maybe_code).to eq(nil)
      expect(result['subject_alt_names']).to eq('DNS:foo.com,IP:123.456.789')
    end

    it 'prepends "DNS" to unprefixed alt names' do
      expect(subject.munge_alt_names('foo.com,IP:123.456.789')).to eq('DNS:foo.com, IP:123.456.789')
    end

    it 'adds subject alt names to the master cert' do
      digest = Puppetserver::Ca::Utils::SigningDigest.new.digest
      host = Puppetserver::Ca::Host.new(digest)
      valid_until = Time.now + 1000
      root_key = host.create_private_key(4096)
      root_cert = subject.self_signed_ca(root_key, "root", valid_until, digest)
      int_key = host.create_private_key(4096)
      int_csr = host.create_csr("int_ca", int_key)
      int_cert = subject.sign_intermediate(root_key, root_cert, int_csr, valid_until, digest)
      master_key = host.create_private_key(4096)
      master_csr = host.create_csr("master", master_key)
      master_cert = subject.sign_master_cert(int_key, int_cert, master_csr, valid_until, digest, "DNS:bar.net, IP:123.123.0.1")
      expect(master_cert.extensions[6].to_s).to eq("subjectAltName = DNS:bar.net, IP Address:123.123.0.1")
    end
  end
end
