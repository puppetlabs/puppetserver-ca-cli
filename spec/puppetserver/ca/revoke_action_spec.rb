require 'spec_helper'

require 'puppetserver/ca/action/revoke'
require 'puppetserver/ca/logger'
require 'puppetserver/utils/http_client'

RSpec.describe Puppetserver::Ca::Action::Revoke do
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  subject { Puppetserver::Ca::Action::Revoke.new(logger) }

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

    it 'cannot revoke certs with the names of flags' do
      result, code = subject.parse(['--certname', '--config'])
      expect(code).to eq(1)
      expect(stderr.string).to include('Cannot manage cert named `--config`')
      expect(result['certnames']).to eq(['--config'])
    end
  end

  describe 'revocation' do
    Result = Struct.new(:code, :body)

    let(:success) { Result.new('204', '') }
    let(:connection) { double }

    before do
      allow_any_instance_of(Puppetserver::Utils::HttpClient).
        to receive(:with_connection).and_yield(connection)
      allow_any_instance_of(Puppetserver::Utils::HttpClient).
        to receive(:make_store)
      allow_any_instance_of(Puppetserver::Utils::HttpClient).
        to receive(:load_cert)
      allow_any_instance_of(Puppetserver::Utils::HttpClient).
        to receive(:load_key)
    end

    it 'logs success and returns zero if revoked' do
      allow(connection).to receive(:put).and_return(success)

      code = subject.run({'certnames' => ['foo']})
      expect(code).to eq(0)
      expect(stdout.string.chomp).to eq('Revoked certificate for foo')
      expect(stderr.string).to be_empty
    end

    it 'logs an error and returns 1 if any could not be revoked' do
      not_found = Result.new('404', 'Not Found')
      allow(connection).to receive(:put).and_return(not_found, success)

      code = subject.run({'certnames' => ['foo', 'bar']})
      expect(code).to eq(1)
      expect(stdout.string.chomp).to eq('Revoked certificate for bar')
      expect(stderr.string).to match(/Error.*not find certificate for foo/m)
    end

    it 'prints an error and returns 1 if an unknown error occurs' do
      error = Result.new('500', 'Internal Server Error')
      allow(connection).to receive(:put).and_return(error, success)

      code = subject.run({'certnames' => ['foo', 'bar']})
      expect(code).to eq(1)
      expect(stdout.string.chomp).to eq('Revoked certificate for bar')
      expect(stderr.string).
        to match(/Error.*revoking foo.*code: 500.*body: Internal Server Error/m)
    end
  end
end
