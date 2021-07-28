require 'spec_helper'
require 'utils/ssl'
require 'utils/http'

require 'tmpdir'

require 'puppetserver/ca/logger'
require 'puppetserver/ca/action/prune'
require 'puppetserver/ca/utils/http_client'

RSpec.describe Puppetserver::Ca::Action::Prune do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  subject { Puppetserver::Ca::Action::Prune.new(logger) }

  describe 'flags' do
    it 'take a custom path to the puppet.conf' do
      result, maybe_exit_code = subject.parse(['--config', '/dev/tcp/example.com'])
      expect(maybe_exit_code).to be(nil)
      expect(result['config']).to eq('/dev/tcp/example.com')
    end
  end

  describe 'prune' do
    let(:connection) { double }
    let(:online) { Utils::Http::Result.new('200', 'running') }
    let(:offline) { Utils::Http::Result.new('503', 'offline') }

    before do
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:with_connection).and_yield(connection)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:make_store)
    end

    it 'errors when validating path to puppet.conf' do
      exit_code = subject.run({'config' => "fake/faker/puppet.conf"})
      expect(exit_code).to eq(1)
      expect(stderr.string).to eq("Error:\nCould not read file 'fake/faker/puppet.conf'\n")
    end

    it 'refuses to prune when server is running' do
      allow(connection).to receive(:get).and_return(online)
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |config|
          exit_code = subject.run({'config' => config})
          expect(exit_code).to eq(1)
          expect(stderr.string).to include('server service is running')
        end
      end
    end

    it 'errors when fails to validate puppet settings' do
      allow(connection).to receive(:get).and_return(offline)
      Dir.mktmpdir do |dir|
        puppet_conf = File.join(dir, 'puppet.conf')
        File.open puppet_conf, 'w' do |f|
          f.puts(<<-INI)
            [main]
              certname = $cadir
          INI
        end
        exit_code = subject.run({ 'config' => puppet_conf })
        expect(exit_code).to eq(1)
        expect(stderr.string).to include('Could not parse')
      end
    end

    it 'reduces a CRL with duplicate revoked certs down to 1 cert' do
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      revoked_cert = create_cert(ca_key, 'revoked')
      ca_crl = create_crl(ca_cert, ca_key, Array.new(5, revoked_cert))

      number_of_removed_duplicates = subject.prune_CRLs([ca_crl])
      expect(ca_crl.revoked.length).to eq(1)
      expect(number_of_removed_duplicates).to eq(4)
    end

    it 'deduplicates a CRL with multiple certs that have duplicate of themselves' do
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      first_cert = Array.new(5, create_cert(ca_key, 'first'))
      second_cert = Array.new(10, create_cert(ca_key, 'second'))
      third_cert = Array.new(3, create_cert(ca_key, 'third'))

      ca_crl = create_crl(ca_cert, ca_key, first_cert + second_cert + third_cert)

      number_of_removed_duplicates = subject.prune_CRLs([ca_crl])
      expect(ca_crl.revoked.length).to eq(3)
      expect(number_of_removed_duplicates).to eq(15)
    end
  end

  describe 'update' do
    it 'bumps CRL number up by 1' do
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "Bazzup")
      ca_crl = create_crl(ca_cert, ca_key)

      subject.update_pruned_CRL([ca_crl], ca_key)

      extensions = ca_crl.extensions.select { |ext| ext.oid == "crlNumber"}
      extensions.each do |ext|
        expect(ext.value).to eq("1")
      end
    end
  end
end