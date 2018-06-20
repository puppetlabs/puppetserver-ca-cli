require 'spec_helper'
require 'puppetserver/ca/cli'

require 'stringio'

RSpec.describe Puppetserver::CA::CLI do
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }

  it 'responds to a --help flag' do
    exit_code = Puppetserver::CA::CLI.run!(['--help'], stdout, stderr)
    expect(stdout.string).to include('usage: puppetserver ca <command> [options]')
    expect(stdout.string).to include('This general help output')
    expect(exit_code).to be 0
  end

  it 'prints the help output & returns 1 if no input is given' do
    exit_code = Puppetserver::CA::CLI.run!([], stdout, stderr)
    expect(stderr.string).to include('This general help output')
    expect(exit_code).to be 1
  end

  describe 'the setup subcommand' do
    it 'responds with a specific help output when given the --help flag"' do
      exit_code = Puppetserver::CA::CLI.run!(['setup', '--help'], stdout, stderr)
      expect(stdout.string).to include('usage: puppetserver ca setup [options]')
      expect(stdout.string).to include('This setup specific help output')
      expect(exit_code).to be 0
    end

    it 'prints the help output & returns 1 if no input is given' do
      exit_code = Puppetserver::CA::CLI.run!(['setup'], stdout, stderr)
      expect(stderr.string).to include('This setup specific help output')
      expect(exit_code).to be 1
    end

    context 'required options' do
      it 'requires the --cert-bundle if only given the --private-key' do
        exit_code = Puppetserver::CA::CLI.run!(
                      ['setup', '--private-key', 'foo'],
                      stdout,
                      stderr)
        expect(stderr.string).to include('Warning')
        expect(stderr.string).to include('missing required argument')
        expect(stderr.string).to include('usage: ')
        expect(exit_code).to be 1
      end

      it 'requires the --private-key if only given the --cert-bundle' do
        exit_code = Puppetserver::CA::CLI.run!(
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
      exit_code = Puppetserver::CA::CLI.run!(
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
