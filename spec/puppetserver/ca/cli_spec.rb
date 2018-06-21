require 'spec_helper'
require 'puppetserver/ca/cli'

require 'tmpdir'
require 'stringio'
require 'fileutils'

RSpec.describe Puppetserver::Ca::Cli do
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }

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
      /.*usage: puppetserver ca <command> .*This general help output.*/m
  end

  describe 'the setup subcommand' do
    let(:usage) do
      /.*usage: puppetserver ca setup.*This setup specific help output.*/m
    end

    include_examples 'basic cli args',
      'setup',
      /.*usage: puppetserver ca setup.*This setup specific help output.*/m

    it 'does not print the help output if called correctly' do
      Dir.mktmpdir do |tmpdir|
        bundle = File.join(tmpdir, 'bundle.pem')
        key = File.join(tmpdir, 'key.pem')
        chain = File.join(tmpdir, 'chain.pem')
        [bundle, key, chain].each {|file| FileUtils.touch(file) }
        exit_code = Puppetserver::Ca::Cli.run!(['setup',
                                                '--cert-bundle', bundle,
                                                '--private-key', key,
                                                '--crl-chain', chain],
                                              stdout, stderr)
        expect(stderr.string).to be_empty
        expect(exit_code).to be 0
      end
    end

    context 'validation' do
      it 'requires both the --cert-bundle and --private-key options' do
        exit_code = Puppetserver::Ca::Cli.run!(
                      ['setup', '--private-key', 'foo'],
                      stdout,
                      stderr)
        expect(stderr.string).to include('missing required argument')
        expect(stderr.string).to match(usage)
        expect(exit_code).to be 1

        exit_code = Puppetserver::Ca::Cli.run!(
                      ['setup', '--cert-bundle', 'foo'],
                      stdout,
                      stderr)
        expect(stderr.string).to include('missing required argument')
        expect(stderr.string).to match(usage)
        expect(exit_code).to be 1
      end

      it 'warns when no CRL is given' do
        exit_code = Puppetserver::Ca::Cli.run!(
                      ['setup',
                       '--cert-bundle', 'foo',
                       '--private-key', 'bar'],
                      stdout,
                      stderr)
        expect(stderr.string).to include('Full CRL chain checking will not be possible')
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
        end
      end
    end
  end
end
