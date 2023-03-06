require 'spec_helper'
require 'utils/http'
require 'utils/ssl'
require 'openssl'
require 'puppetserver/ca/action/delete'
require 'puppetserver/ca/logger'

RSpec.describe Puppetserver::Ca::Action::Delete do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  subject { Puppetserver::Ca::Action::Delete.new(logger) }

  describe 'parse' do
    it 'takes a single certname' do
      result, maybe_code = subject.parse(['--certname', 'foo.example.com'])
      expect(maybe_code).to eq(nil)
      expect(result['certname']).to eq(['foo.example.com'])
    end

    it 'takes a comma separated list of certnames' do
      result, maybe_code = subject.parse(['--certname', 'foo,bar'])
      expect(maybe_code).to eq(nil)
      expect(result['certname']).to eq(['foo', 'bar'])
    end

    it 'takes a custom puppet.conf location' do
      result, maybe_code = subject.parse(['--certname', 'foo',
                                          '--config', '/dev/tcp/example.com'])
      expect(maybe_code).to be(nil)
      expect(result['config']).to eq('/dev/tcp/example.com')
    end
  end

  describe 'validation' do
    it 'cannot revoke certs with the names of flags' do
      result, code = subject.parse(['--certname', '--config'])
      expect(code).to eq(1)
      expect(stderr.string).to include('Cannot manage cert named `--config`')
      expect(result['certname']).to eq(['--config'])
    end

    it 'must pass one of the flags to determine the action' do
      result, code = subject.parse([])
      expect(code).to eq(1)
      expect(stderr.string).to include('Must pass one of the valid flags')
    end
  end

  def timefmt(time)
    time.utc.strftime("%Y-%m-%dT%H:%M:%SUTC")
  end

  def prepare_certs_and_inventory(cadir)
    FileUtils.mkdir_p "#{cadir}/signed"
    # Foo expires now, Bar expires far in the future, Baz is expired and not present in inventory
    # Include a line for an old Bar cert to ensure we aren't deleting it and only acting based off
    # the newest entry for a cert
    key = OpenSSL::PKey::RSA.new(512)
    not_before_unexpired = Time.now - 1
    not_after_unexpired = Time.now + 360000
    not_before_expired = Time.now - 100
    not_after_expired = Time.now - 1
    File.write("#{cadir}/signed/foo.pem", create_cert(key, 'foo', nil, nil, not_before_expired, not_after_expired, 1))
    File.write("#{cadir}/signed/bar.pem", create_cert(key, 'bar', nil, nil, not_before_unexpired, not_after_unexpired, 3))
    File.write("#{cadir}/signed/baz.pem", create_cert(key, 'baz', nil, nil, not_before_expired, not_after_expired, 4))
    inventory = <<~INV
      0x0001 #{timefmt(not_before_expired)} #{timefmt(not_after_expired)} /CN=foo
      0x0002 #{timefmt(not_before_expired)} #{timefmt(not_after_expired)} /CN=bar
      0x0003 #{timefmt(not_before_unexpired)} #{timefmt(not_after_unexpired)} /CN=bar

    INV
    File.write("#{cadir}/inventory.txt", inventory)
  end

  context 'running the action' do
    let(:connection) { double }
    let(:online) { Utils::Http::Result.new('200', 'running') }
    let(:offline) { Utils::Http::Result.new('503', 'offline') }
    before(:each) do
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:with_connection).and_yield(connection)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:make_store)
    end

    describe 'common to all actionable flags' do
      it 'errors when validating path to puppet.conf' do
        code = subject.run({'config' => 'fake/puppet.conf'})
        expect(code).to eq(1)
        expect(stderr.string).to eq("Error:\nCould not read file 'fake/puppet.conf'\n")
      end

      it 'errors when puppetserver is still online' do
        allow(connection).to receive(:get).and_return(online)
        code = subject.run({'expired' => true})
        expect(code).to eq(1)
        expect(stderr.string).to eq("Puppetserver service is running. Please stop it before attempting to run this command.\n")
      end
    end

    describe '--expired' do
      before(:each) { allow(connection).to receive(:get).and_return(offline) }

      it 'clears the two expired certs and leaves the other one alone' do
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            cadir = "#{tmpdir}/ca"
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'expired' => true})
            expect(code).to eq(0)
            expect(stdout.string).to match(/2 certificates deleted./)
            expect(File.exist?("#{cadir}/signed/foo.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/bar.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/baz.pem")).to eq(false)
          end
        end
      end

      it 'handles one of the certs from inventory.txt being missing' do
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            cadir = "#{tmpdir}/ca"
            prepare_certs_and_inventory(cadir)
            FileUtils.rm_f("#{cadir}/signed/foo.pem")
            code = subject.run({'config' => config, 'expired' => true})
            expect(code).to eq(24)
            expect(stderr.string).to match(/Could not find certificate file at #{cadir}\/signed\/foo.pem/)
            expect(stdout.string).to match(/1 certificate deleted./)
          end
        end
      end

      it 'handles a cert on disk not in the inventory file being a bad cert file' do
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            cadir = "#{tmpdir}/ca"
            prepare_certs_and_inventory(cadir)
            File.write("#{cadir}/signed/baz.pem", "badcert")
            code = subject.run({'config' => config, 'expired' => true})
            expect(code).to eq(24)
            expect(stderr.string).to match(/Error reading certificate at #{cadir}\/signed\/baz.pem/)
            expect(stdout.string).to match(/1 certificate deleted./)
          end
        end
      end
    end

    describe '--certname' do
      before(:each) { allow(connection).to receive(:get).and_return(offline) }

      it 'deletes the given single certname' do
        # Single certname is transformed into an array by the parser
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            cadir = "#{tmpdir}/ca"
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'certname' => ['foo']})
            expect(code).to eq(0)
            expect(stdout.string).to match(/1 certificate deleted./)
            expect(File.exist?("#{cadir}/signed/foo.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/bar.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/baz.pem")).to eq(true)
          end
        end
      end

      it 'deletes the given multiple certnames' do
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            cadir = "#{tmpdir}/ca"
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'certname' => ['foo', 'bar']})
            expect(code).to eq(0)
            expect(stdout.string).to match(/2 certificates deleted./)
            expect(File.exist?("#{cadir}/signed/foo.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/bar.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/baz.pem")).to eq(true)
          end
        end
      end

      it 'shows an error when one of the certs does not exist' do
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            cadir = "#{tmpdir}/ca"
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'certname' => ['foo', 'lolwut']})
            expect(code).to eq(24)
            expect(stderr.string).to match(/Could not find certificate file at.*lolwut.pem/)
            expect(stdout.string).to match(/1 certificate deleted./)
            expect(File.exist?("#{cadir}/signed/foo.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/bar.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/baz.pem")).to eq(true)
          end
        end
      end

      it 'works correctly with the --expired flag, adding on an additional cert' do
        Dir.mktmpdir do |tmpdir|
          with_temp_dirs tmpdir do |config|
            cadir = "#{tmpdir}/ca"
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'expired' => true, 'certname' => ['bar']})
            expect(code).to eq(0)
            expect(stdout.string).to match(/3 certificates deleted./)
            expect(File.exist?("#{cadir}/signed/foo.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/bar.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/baz.pem")).to eq(false)
          end
        end
      end
    end
  end
end

