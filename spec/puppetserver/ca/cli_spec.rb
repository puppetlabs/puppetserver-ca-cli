require 'spec_helper'
require 'puppetserver/ca/cli'

require 'tmpdir'
require 'stringio'
require 'fileutils'

RSpec.describe Puppetserver::Ca::Cli do
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }

  it 'responds to a --help flag' do
    exit_code = Puppetserver::Ca::Cli.run!(['--help'], stdout, stderr)
    expect(stdout.string).to include('usage: puppetserver ca <command> [options]')
    expect(stdout.string).to include('This general help output')
    expect(exit_code).to be 0
  end

  it 'prints the help output & returns 1 if no input is given' do
    exit_code = Puppetserver::Ca::Cli.run!([], stdout, stderr)
    expect(stderr.string).to include('This general help output')
    expect(exit_code).to be 1
  end

  it 'prints the version regardless of subcommand' do
    out1, err1 = StringIO.new, StringIO.new
    first_code = Puppetserver::Ca::Cli.run!(['--version'], out1, err1)
    expect(out1.string).to match(/\d+\.\d+\.\d+(-[a-z0-9._-]+)?/)
    expect(err1.string).to be_empty
    expect(first_code).to be 0

    out2, err2 = StringIO.new, StringIO.new
    second_code = Puppetserver::Ca::Cli.run!(['setup', '--version'],
                                             out2,
                                             err2)
    expect(out2.string).to match(/\d+\.\d+\.\d+(-[a-z0-9._-]+)?/)
    expect(err2.string).to be_empty
    expect(second_code).to be 0
  end

  describe 'the setup subcommand' do
    it 'responds with a specific help output when given the --help flag"' do
      exit_code = Puppetserver::Ca::Cli.run!(['setup', '--help'], stdout, stderr)
      expect(stdout.string).to include('usage: puppetserver ca setup [options]')
      expect(stdout.string).to include('This setup specific help output')
      expect(exit_code).to be 0
    end

    it 'prints the help output & returns 1 if no input is given' do
      exit_code = Puppetserver::Ca::Cli.run!(['setup'], stdout, stderr)
      expect(stderr.string).to include('This setup specific help output')
      expect(exit_code).to be 1
    end

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

    context 'required options' do
      it 'requires the --cert-bundle if only given the --private-key' do
        exit_code = Puppetserver::Ca::Cli.run!(
                      ['setup', '--private-key', 'foo'],
                      stdout,
                      stderr)
        expect(stderr.string).to include('Warning')
        expect(stderr.string).to include('missing required argument')
        expect(stderr.string).to include('usage: ')
        expect(exit_code).to be 1
      end

      it 'requires the --private-key if only given the --cert-bundle' do
        exit_code = Puppetserver::Ca::Cli.run!(
                      ['setup', '--cert-bundle', 'foo'],
                      stdout,
                      stderr)
        expect(stderr.string).to include('Warning')
        expect(stderr.string).to include('missing required argument')
        expect(stderr.string).to include('usage: ')
        expect(exit_code).to be 1
      end
    end

    it 'warns when no crl is given' do
      exit_code = Puppetserver::Ca::Cli.run!(
                    ['setup',
                     '--cert-bundle', 'foo',
                     '--private-key', 'bar'],
                    stdout,
                    stderr)
      expect(stderr.string).to include('Warning')
      expect(stderr.string).to include('Full CRL chain checking will not be possible')
    end

    it 'requires cert-bundle, private-key, and crl-chain to be readable' do
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
