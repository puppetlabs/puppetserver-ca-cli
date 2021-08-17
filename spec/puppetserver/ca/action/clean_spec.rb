require 'spec_helper'
require 'utils/http'
require 'utils/helpers'

require 'puppetserver/ca/action/clean'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/http_client'

RSpec.describe Puppetserver::Ca::Action::Clean do
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  subject { Puppetserver::Ca::Action::Clean.new(logger) }

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
    it 'requires at least one certname' do
      result, code = subject.parse([])
      expect(code).to eq(1)
      expect(stderr.string).to include('one certname is required')
    end

    it 'cannot clean certs with the names of flags' do
      result, code = subject.parse(['--certname', '--config'])
      expect(code).to eq(1)
      expect(stderr.string).to include('Cannot manage cert named `--config`')
      expect(result['certnames']).to eq(['--config'])
    end
  end

  describe 'clean' do
    let(:success) { Utils::Http::Result.new('204', '') }
    let(:not_found) { Utils::Http::Result.new('404', 'Not Found') }
    let(:error) { Utils::Http::Result.new('500', 'Internal Server Error') }
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

    it 'logs success and returns zero if revoked and cleaned' do
      allow(connection).to receive(:put).and_return(success)
      allow(connection).to receive(:delete).and_return(success)

      code = subject.run({'certnames' => ['foo']})
      expect(code).to eq(0)
      expect(stdout.string).to match(/Certificate.*foo/)
      expect(stdout.string).to include('Cleaned files related to foo')
      expect(Utils::Helpers.remove_cadir_deprecation(stderr)).to be_empty
    end

    it 'logs success and returns zero if cleaned but already revoked' do
      allow(connection).to receive(:put).and_return(not_found)
      allow(connection).to receive(:delete).and_return(success)

      code = subject.run({'certnames' => ['foo']})
      expect(code).to eq(0)
      expect(stdout.string).to include('Cleaned files related to foo')
      expect(Utils::Helpers.remove_cadir_deprecation(stderr)).to be_empty
    end

    it 'fails and does not attempt to clean if revocation fails' do
      allow(connection).to receive(:put).and_return(error)
      expect(connection).not_to receive(:delete)

      code = subject.run({'certnames' => ['foo']})
      expect(code).to eq(1)
      expect(stdout.string).to be_empty
      expect(stderr.string).to include('Internal Server Error')
    end

    it 'logs an error and returns 1 if some did not exist' do
      not_found = Utils::Http::Result.new('404', 'Not Found')
      allow(connection).to receive(:put).and_return(not_found, success)
      allow(connection).to receive(:delete).and_return(not_found, success)

      code = subject.run({'certnames' => ['foo', 'bar']})
      expect(code).to eq(1)
      expect(stdout.string).to include('Cleaned files related to bar')
      expect(stderr.string).to match(/Error.*not find files.*foo/m)
    end

    it 'logs an error and returns 24 if some were unsigned' do
      unsigned = Utils::Http::Result.new('409', 'Conflict')
      allow(connection).to receive(:put).and_return(unsigned, success)
      allow(connection).to receive(:delete).and_return(success, success)

      code = subject.run({'certnames' => ['foo', 'bar']})
      expect(code).to eq(24)
      expect(stdout.string).to include('Cleaned files related to bar')
      expect(stdout.string).to include('Cleaned files related to foo')
      expect(Utils::Helpers.remove_cadir_deprecation(stderr)).to be_empty
    end

    it 'logs returns 1 if some were unsigned and not found' do
      unsigned = Utils::Http::Result.new('409', 'Conflict')
      not_found = Utils::Http::Result.new('404', 'Not Found')
      allow(connection).to receive(:put).and_return(unsigned, success, not_found)
      allow(connection).to receive(:delete).and_return(success, success, not_found)

      code = subject.run({'certnames' => ['foo', 'bar', 'baz']})
      expect(code).to eq(1)
      expect(stdout.string).to include('Cleaned files related to bar')
      expect(stdout.string).to include('Cleaned files related to foo')
      expect(stderr.string).to match(/Error.*not find files.*baz/m)
    end

    it 'prints an error and returns 1 if an unknown error occurs' do
      error = Utils::Http::Result.new('500', 'Internal Server Error')
      allow(connection).to receive(:put).and_return(success)
      allow(connection).to receive(:delete).and_return(error, success)

      code = subject.run({'certnames' => ['foo', 'bar']})
      expect(code).to eq(1)
      expect(stdout.string).to include('Cleaned files related to bar')
      expect(stderr.string).
        to match(/Error.*attempting to clean.*code: 500.*body: Internal Server Error/m)
    end
  end
end
