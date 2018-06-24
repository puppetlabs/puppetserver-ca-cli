require 'spec_helper'
require 'puppetserver/ca/cli'

require 'tmpdir'
require 'stringio'
require 'fileutils'
require 'openssl'

RSpec.describe Puppetserver::Ca::Cli do
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }

  def with_files_in(tmpdir, &block)
    bundle_file = File.join(tmpdir, 'bundle.pem')
    key_file = File.join(tmpdir, 'key.pem')
    chain_file = File.join(tmpdir, 'chain.pem')
    key = OpenSSL::PKey::RSA.new(2048)

    File.open(key_file, 'w') do |f|
      f.puts key.to_pem
    end

    not_before = Time.now - 1

    cert = OpenSSL::X509::Certificate.new
    cert.public_key = key.public_key
    cert.subject = OpenSSL::X509::Name.parse("/CN=foo")
    cert.issuer = cert.subject
    cert.version = 2
    cert.serial = rand(2**128)
    cert.not_before = not_before
    cert.not_after = not_before + 360
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = cert
    ef.subject_certificate = cert

    [
      ["basicConstraints", "CA:TRUE", true],
      ["keyUsage", "keyCertSign, cRLSign", true],
      ["subjectKeyIdentifier", "hash", false],
      ["authorityKeyIdentifier", "keyid:always", false]
    ].each do |ext|
      extension = ef.create_extension(*ext)
      cert.add_extension(extension)
    end
    cert.sign(key, OpenSSL::Digest::SHA256.new)

    File.open(bundle_file, 'w') do |f|
      f.puts cert.to_pem
    end

    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = cert.subject
    crl.add_extension(
      ef.create_extension(["authorityKeyIdentifier", "keyid:always", false]))
    crl.add_extension(
      OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(0)))
    crl.last_update = not_before
    crl.next_update = not_before + 360
    crl.sign(key, OpenSSL::Digest::SHA256.new)

    File.open(chain_file, 'w') {|f| f.puts crl.to_pem }


    block.call(bundle_file, key_file, chain_file)
  end

  shared_examples 'basic cli args' do |subcommand, usage|
    it 'responds to a --help flag' do
      args = [subcommand, '--help'].compact
      exit_code = Puppetserver::Ca::Cli.run!(args, stdout, stderr)
      expect(stdout.string).to match(usage)
      expect(exit_code).to be 0
    end

    it 'prints the help output & returns 1 if no input is given' do
      args = [subcommand].compact
      exit_code = Puppetserver::Ca::Cli.run!(args, stdout, stderr)
      expect(stderr.string).to match(usage)
      expect(exit_code).to be 1
    end

    it 'prints the version' do
      semverish = /\d+\.\d+\.\d+(-[a-z0-9._-]+)?/
      args = [subcommand, '--version'].compact
      first_code = Puppetserver::Ca::Cli.run!(args, stdout, stderr)
      expect(stdout.string).to match(semverish)
      expect(stderr.string).to be_empty
      expect(first_code).to be 0
    end
  end

  describe 'general options' do
    include_examples 'basic cli args',
      nil,
      /.*Usage: puppetserver ca <command> .*This general help output.*/m
  end

  describe 'the setup subcommand' do
    let(:usage) do
      /.*Usage: puppetserver ca setup.*This setup specific help output.*/m
    end

    include_examples 'basic cli args',
      'setup',
      /.*Usage: puppetserver ca setup.*This setup specific help output.*/m

    it 'does not print the help output if called correctly' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain|
          exit_code = Puppetserver::Ca::Cli.run!(['setup',
                                                  '--cert-bundle', bundle,
                                                  '--private-key', key,
                                                  '--crl-chain', chain],
                                                stdout, stderr)
          expect(stderr.string).to be_empty
          expect(exit_code).to be 0
        end
      end
    end

    context 'validation' do
      it 'requires both the --cert-bundle and --private-key options' do
        exit_code = Puppetserver::Ca::Cli.run!(
                      ['setup', '--private-key', 'foo'],
                      stdout,
                      stderr)
        expect(stderr.string).to include('Missing required argument')
        expect(stderr.string).to match(usage)
        expect(exit_code).to be 1

        exit_code = Puppetserver::Ca::Cli.run!(
                      ['setup', '--cert-bundle', 'foo'],
                      stdout,
                      stderr)
        expect(stderr.string).to include('Missing required argument')
        expect(stderr.string).to match(usage)
        expect(exit_code).to be 1
      end

      it 'warns when no CRL is given' do
        Dir.mktmpdir do |tmpdir|
          with_files_in tmpdir do |bundle, key, chain|
            exit_code = Puppetserver::Ca::Cli.run!(
                          ['setup',
                           '--cert-bundle', bundle,
                           '--private-key', key],
                          stdout,
                          stderr)
            expect(stderr.string).to include('Full CRL chain checking will not be possible')
          end
        end
      end

      it 'requires cert-bundle, private-key, and crl-chain to be readable' do
        # All errors are surfaced from validations
        Dir.mktmpdir do |tmpdir|
          exit_code = Puppetserver::Ca::Cli.run!(
                        ['setup',
                         '--cert-bundle', File.join(tmpdir, 'cert_bundle.pem'),
                         '--private-key', File.join(tmpdir, 'private_key.pem'),
                         '--crl-chain', File.join(tmpdir, 'crl_chain.pem')],
                        stdout, stderr)
          expect(stderr.string).to match(/Could not read .*cert_bundle.pem/)
          expect(stderr.string).to match(/Could not read .*private_key.pem/)
          expect(stderr.string).to match(/Could not read .*crl_chain.pem/)
          expect(exit_code).to be 1
        end
      end

      it 'validates certs in bundle are parseable' do
        Dir.mktmpdir do |tmpdir|
          with_files_in tmpdir do |bundle, key, chain|
            File.open(bundle, 'a') do |f|
              f.puts '-----BEGIN CERTIFICATE-----'
              f.puts 'garbage'
              f.puts '-----END CERTIFICATE-----'
            end
            exit_code = Puppetserver::Ca::Cli.run!(
                          ['setup',
                           '--cert-bundle', bundle,
                           '--private-key', key,
                           '--crl-chain', chain],
                          stdout,
                          stderr)

            expect(stderr.string).to match(/Could not parse .*bundle.pem/)
            expect(stderr.string).to include('garbage')
          end
        end
      end

      it 'validates that there are certs in the bundle' do
        Dir.mktmpdir do |tmpdir|
          with_files_in tmpdir do |bundle, key, chain|
            File.open(bundle, 'w') {|f| f.puts '' }
            exit_code = Puppetserver::Ca::Cli.run!(
                          ['setup',
                           '--cert-bundle', bundle,
                           '--private-key', key,
                           '--crl-chain', chain],
                          stdout,
                          stderr)

            expect(stderr.string).to match(/Could not detect .*bundle.pem/)
            expect(stderr.string).not_to include('garbage')
          end
        end
      end
    end
  end
end
