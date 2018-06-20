require 'spec_helper'
require 'puppetserver/ca/cli'

require 'stringio'

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
      exit_code = Puppetserver::Ca::Cli.run!(['setup',
                                              '--cert-bundle', 'foo',
                                              '--private-key', 'bar',
                                              '--crl-chain', 'baz'])
      expect(stderr.string).to be_empty
      expect(exit_code).to be 0
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
  end
end
