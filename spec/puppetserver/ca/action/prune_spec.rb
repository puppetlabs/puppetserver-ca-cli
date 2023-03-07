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

    it 'takes --remove-duplicates option' do
      result, maybe_code = subject.parse(['--remove-duplicates'])
      expect(maybe_code).to eq(nil)
      expect(result['remove-duplicates']).to eq(true)
    end

    it 'takes --remove-expired option' do
      result, maybe_code = subject.parse(['--remove-expired'])
      expect(maybe_code).to eq(nil)
      expect(result['remove-expired']).to eq(true)
    end

    it 'takes --remove-entries option' do
      result, maybe_code = subject.parse(['--remove-entries'])
      expect(maybe_code).to eq(nil)
      expect(result['remove-entries']).to eq(true)
    end

    it 'takes a single serialnumber' do
      result, maybe_code = subject.parse(['--serial', '1C'])
      expect(maybe_code).to eq(nil)
      expect(result['serial']).to eq(['1C'])
    end

    it 'takes a comma separated list of serialnumbers' do
      result, maybe_code = subject.parse(['--serial', '1C,2D'])
      expect(maybe_code).to eq(nil)
      expect(result['serial']).to eq(['1C', '2D'])
    end

    it 'takes a single certname' do
      result, maybe_code = subject.parse(['--certname', 'foo.example.com'])
      expect(maybe_code).to eq(nil)
      expect(result['certname']).to eq(['foo.example.com'])
    end

    it 'takes a comma separated list of certnames' do
      result, maybe_code = subject.parse(['--certname', 'foo.example.com,bar'])
      expect(maybe_code).to eq(nil)
      expect(result['certname']).to eq(['foo.example.com', 'bar'])
    end
  end

  describe 'prune' do
    let(:connection) { double }
    let(:online) { Utils::Http::Result.new('200', 'running') }
    let(:offline) { Utils::Http::Result.new('503', 'offline') }
    let(:tmpdir) { Dir.mktmpdir }
    let(:settings) {
      with_ca_in(tmpdir) do |config, confdir|
        return Puppetserver::Ca::Config::Puppet.new(config).load(cli_overrides: {confdir: confdir }, logger: logger)
      end
    }
    let(:ca) { Puppetserver::Ca::LocalCertificateAuthority.new(OpenSSL::Digest::SHA256.new, settings) }

    before do
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:with_connection).and_yield(connection)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:make_store)
    end

    after(:each) do
      FileUtils.rm_rf(tmpdir)
    end

    it 'errors when validating path to puppet.conf' do
      exit_code = subject.run({'config' => "fake/faker/puppet.conf"})
      expect(exit_code).to eq(1)
      expect(stderr.string).to eq("Error:\nCould not read file 'fake/faker/puppet.conf'\n")
    end

    it 'errors when missing argument' do
      exit_code = subject.run({"remove-entries"=>true})
      expect(exit_code).to eq(1)
      expect(stderr.string).to include("Error:\n--remove-entries option require --serial or --certname values")
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

      number_of_removed_duplicates = subject.prune_CRL(ca_crl)
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

      number_of_removed_duplicates = subject.prune_CRL(ca_crl)
      expect(ca_crl.revoked.length).to eq(3)
      expect(number_of_removed_duplicates).to eq(15)
    end

    it 'reduces a CRL with duplicate revoked certs when called without any arguments' do
      allow(connection).to receive(:get).and_return(offline)
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          puppet_conf = File.join(tmpdir, 'puppet.conf')
          File.open puppet_conf, 'w' do |f|
            f.puts(<<-INI)
              [agent]
                publickeydir = /agent/pubkeys
              [main]
                certname = fooberry
              [master]
                ssldir = /foo/bar
                cacrl = #{tmpdir}/ca//crl.pem
                cadir = #{tmpdir}/ca
            INI
          end
          conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
          conf.load(logger: logger)
          ca_key = OpenSSL::PKey::RSA.new(512)
          ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
          revoked_cert = create_cert(ca_key, 'revoked')
          ca_crl = create_crl(ca_cert, ca_key, Array.new(5, revoked_cert))
          File.write("#{tmpdir}/ca/ca_crt.pem", ca_cert)
          File.write("#{tmpdir}/ca/ca_key.pem", ca_key)
          File.write("#{tmpdir}/ca/crl.pem", ca_crl)

          exit_code = subject.run({"config"=>puppet_conf})
          updated_crl = OpenSSL::X509::CRL::new(File.read("#{tmpdir}/ca/crl.pem"))
          expect(exit_code).to eq(0)
          expect(updated_crl.revoked.length).to eq(1)
          expect(stdout.string).to include("Removed 4 duplicated certs from Puppet's CRL.")
        end
      end
    end
    it 'reduces a CRL with duplicate revoked certs when called with --remove-duplicates' do
      allow(connection).to receive(:get).and_return(offline)
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          puppet_conf = File.join(tmpdir, 'puppet.conf')
          File.open puppet_conf, 'w' do |f|
            f.puts(<<-INI)
              [agent]
                publickeydir = /agent/pubkeys
              [main]
                certname = fooberry
              [master]
                ssldir = /foo/bar
                cacrl = #{tmpdir}/ca//crl.pem
                cadir = #{tmpdir}/ca
            INI
          end
          conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
          conf.load(logger: logger)
          ca_key = OpenSSL::PKey::RSA.new(512)
          ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
          revoked_cert = create_cert(ca_key, 'revoked')
          ca_crl = create_crl(ca_cert, ca_key, Array.new(5, revoked_cert))
          File.write("#{tmpdir}/ca/ca_crt.pem", ca_cert)
          File.write("#{tmpdir}/ca/ca_key.pem", ca_key)
          File.write("#{tmpdir}/ca/crl.pem", ca_crl)

          exit_code = subject.run({"config"=>puppet_conf,"remove-duplicates"=>true})
          updated_crl = OpenSSL::X509::CRL::new(File.read("#{tmpdir}/ca/crl.pem"))
          expect(exit_code).to eq(0)
          expect(updated_crl.revoked.length).to eq(1)
          expect(stdout.string).to include("Removed 4 duplicated certs from Puppet's CRL.")
        end
      end
    end

    it 'remove expired crl entries using inventory.txt and scanning CA directory' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      first_revoked_cert = create_cert(ca_key, 'foo')
      second_revoked_cert = create_cert(ca_key, 'bar')
      first_revoked_cert.not_before = Time.now - (60 * 60 * 24 * 365 * 2)
      first_revoked_cert.not_after = Time.now  - (60 * 60 * 24 * 365 * 1)
      second_revoked_cert.not_before = Time.now - (60 * 60 * 24 * 365 * 2)
      second_revoked_cert.not_after = Time.now  - (60 * 60 * 24 * 60)
      ca_crl = create_crl(ca_cert, ca_key, [first_revoked_cert, second_revoked_cert])
      inventory_entries = ca.inventory_entry(first_revoked_cert)
      File.write(settings[:cert_inventory], inventory_entries)
      File.write("#{settings[:cadir]}/signed/bar.pem", second_revoked_cert)
      allow(File).to receive(:exist?).and_return(true)
      number_of_removed_crl_entries = subject.prune_expired(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir])
      expect(number_of_removed_crl_entries).to eq(2)
      expect(ca_crl.revoked.length).to eq(0)
    end

    it 'does not remove unexpired crl entries ' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      first_revoked_cert = create_cert(ca_key, 'foo')
      second_revoked_cert = create_cert(ca_key, 'bar')
      third_revoked_cert = create_cert(ca_key, 'baz')
      fourth_revoked_cert = create_cert(ca_key, 'wine')
      first_revoked_cert.not_before = Time.now - (60 * 60 * 24 * 365 * 2)
      first_revoked_cert.not_after = Time.now  - (60 * 60 * 24 * 365 * 1)
      second_revoked_cert.not_before = Time.now - (60 * 60 * 24 * 365 * 2)
      second_revoked_cert.not_after = Time.now  - (60 * 60 * 24 * 60)
      ca_crl = create_crl(ca_cert, ca_key, [first_revoked_cert, \
                                            second_revoked_cert, \
                                            third_revoked_cert, \
                                            fourth_revoked_cert])
      inventory_entries = ca.inventory_entry(first_revoked_cert) + "\n" + ca.inventory_entry(third_revoked_cert)
      File.write(settings[:cert_inventory], inventory_entries)
      File.write("#{settings[:cadir]}/signed/bar.pem", second_revoked_cert)
      File.write("#{settings[:cadir]}/signed/wine.pem", fourth_revoked_cert)
      allow(File).to receive(:exist?).and_return(true)
      number_of_removed_crl_entries = subject.prune_expired(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir])
      expect(number_of_removed_crl_entries).to eq(2)
      expect(ca_crl.revoked.length).to eq(2)
    end

    it 'continue to scan CA directory and remove expired entries if inventory.txt is missing' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      revoked_cert = create_cert(ca_key, 'foo')
      revoked_cert.not_before = Time.now - (60 * 60 * 24 * 365 * 2)
      revoked_cert.not_after = Time.now  - (60 * 60 * 24 * 365 * 1)
      ca_crl = create_crl(ca_cert, ca_key, [revoked_cert])
      inventory_entries = ca.inventory_entry(revoked_cert)
      File.write("#{settings[:cadir]}/signed/foo.pem", revoked_cert)
      allow(File).to receive(:exist?).with(settings[:cert_inventory]).and_return(false)
      allow(File).to receive(:exist?).with("#{settings[:cadir]}/signed/foo.pem").and_return(true)
      number_of_removed_crl_entries = subject.prune_expired(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir])
      expect(number_of_removed_crl_entries).to eq(1)
      expect(ca_crl.revoked.length).to eq(0)
    end

    it 'correctly parse inventory.txt file with miscellaneous entries when checking for expired entries' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      revoked_cert = create_cert(ca_key, 'foo.example.com')
      revoked_cert.not_before = Time.now - (60 * 60 * 24 * 365 * 2)
      revoked_cert.not_after = Time.now  - 1
      ca_crl = create_crl(ca_cert, ca_key, Array.new(1, revoked_cert))
      File.write(settings[:cert_inventory], "\n"+"I am bad /CN=foo.example.com\n"+ca.inventory_entry(revoked_cert)+"\nHello")
      allow(File).to receive(:exist?).and_return(true)
      number_of_removed_crl_entries = subject.prune_expired(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir])
      expect(number_of_removed_crl_entries).to eq(1)
      expect(ca_crl.revoked.length).to eq(0)
      expect(stderr.string).to include("Invalid not_after time found in inventory.txt file at I am bad /CN=foo.example.com")
    end

    it 'scan CA directory and remove expired entries even if miscellaneous files exist' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      revoked_cert = create_cert(ca_key, 'foo')
      revoked_cert.not_before = Time.now - (60 * 60 * 24 * 365 * 2)
      revoked_cert.not_after = Time.now  - (60 * 60 * 24)
      ca_crl = create_crl(ca_cert, ca_key, [revoked_cert])
      inventory_entries = ca.inventory_entry(revoked_cert)
      File.write("#{settings[:cadir]}/signed/foo.pem", revoked_cert)
      File.write("#{settings[:cadir]}/signed/hello", "hello")
      File.write("#{settings[:cadir]}/signed/test.txt", "testing")
      allow(File).to receive(:exist?).with(settings[:cert_inventory]).and_return(false)
      allow(File).to receive(:exist?).with("#{settings[:cadir]}/signed/foo.pem").and_return(true)
      allow(File).to receive(:exist?).with("#{settings[:cadir]}/signed/hello").and_return(true)
      allow(File).to receive(:exist?).with("#{settings[:cadir]}/signed/test.txt").and_return(true)
      number_of_removed_crl_entries = subject.prune_expired(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir])
      expect(number_of_removed_crl_entries).to eq(1)
      expect(ca_crl.revoked.length).to eq(0)
    end

    it 'removes crl entry when passing single serial number' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      revoked_cert = create_cert(ca_key, 'foo')
      ca_crl = create_crl(ca_cert, ca_key, Array.new(1, revoked_cert))
      number_of_removed_crl_entries = subject.prune_using_serial(ca_crl, ca_key, [revoked_cert.serial.to_s(16)])
      expect(number_of_removed_crl_entries).to eq(1)
      expect(ca_crl.revoked.length).to eq(0)
    end

    it 'remove crl entries when passing multiple  serial numbers' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      first_revoked_cert = create_cert(ca_key, 'foo')
      second_revoked_cert = create_cert(ca_key, 'bar')
      ca_crl = create_crl(ca_cert, ca_key, [first_revoked_cert, second_revoked_cert])
      number_of_removed_crl_entries = subject.prune_using_serial(ca_crl, ca_key, [first_revoked_cert.serial.to_s(16),second_revoked_cert.serial.to_s(16)])
      expect(number_of_removed_crl_entries).to eq(2)
      expect(ca_crl.revoked.length).to eq(0)
    end

    it 'removes crl entry when passing single certname' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      revoked_cert = create_cert(ca_key, 'foo')
      ca_crl = create_crl(ca_cert, ca_key, Array.new(1, revoked_cert))
      File.write(settings[:cert_inventory], ca.inventory_entry(revoked_cert))
      allow(File).to receive(:exist?).and_return(true)
      number_of_removed_crl_entries = subject.prune_using_certname(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir], ["foo"])
      expect(number_of_removed_crl_entries).to eq(1)
      expect(ca_crl.revoked.length).to eq(0)
    end

    it 'removes crl entry when passing multiple certnames' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      first_revoked_cert = create_cert(ca_key, 'foo')
      second_revoked_cert = create_cert(ca_key, 'bar')
      ca_crl = create_crl(ca_cert, ca_key, [first_revoked_cert, second_revoked_cert])
      inventory_entries = ca.inventory_entry(first_revoked_cert) + "\n" + ca.inventory_entry(second_revoked_cert)
      File.write(settings[:cert_inventory], inventory_entries)
      allow(File).to receive(:exist?).and_return(true)
      number_of_removed_crl_entries = subject.prune_using_certname(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir], ["foo","bar"])
      expect(number_of_removed_crl_entries).to eq(2)
      expect(ca_crl.revoked.length).to eq(0)
    end

    it 'removes crl entry when passing certnames that are not in inventory.txt' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      first_revoked_cert = create_cert(ca_key, 'foo')
      second_revoked_cert = create_cert(ca_key, 'bar')
      ca_crl = create_crl(ca_cert, ca_key, [first_revoked_cert, second_revoked_cert])
      inventory_entries = ca.inventory_entry(first_revoked_cert)
      File.write(settings[:cert_inventory], inventory_entries)
      File.write("#{settings[:cadir]}/signed/bar.pem", second_revoked_cert)
      allow(File).to receive(:exist?).and_return(true)
      number_of_removed_crl_entries = subject.prune_using_certname(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir], ["foo","bar"])
      expect(number_of_removed_crl_entries).to eq(2)
      expect(ca_crl.revoked.length).to eq(0)
    end

    it 'prints warning when inventory file is missing and still removes crl entry' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      revoked_cert = create_cert(ca_key, 'foo')
      ca_crl = create_crl(ca_cert, ca_key, [revoked_cert])
      File.write("#{settings[:cadir]}/signed/foo.pem", revoked_cert)
      allow(File).to receive(:exist?).with(settings[:cert_inventory]).and_return(false)
      allow(File).to receive(:exist?).with("#{settings[:cadir]}/signed/foo.pem").and_return(true)
      number_of_removed_crl_entries = subject.prune_using_certname(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir], ["foo"])
      expect(number_of_removed_crl_entries).to eq(1)
      expect(ca_crl.revoked.length).to eq(0)
      expect(stderr.string).to include("Reading inventory file at #{settings[:cert_inventory]} failed with error")
    end

    it 'correctly parse inventory.txt file with miscellaneous entries' do
      allow(connection).to receive(:get).and_return(offline)
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "You-Shall-Not-Pass")
      revoked_cert = create_cert(ca_key, 'foo.example.com')
      ca_crl = create_crl(ca_cert, ca_key, Array.new(1, revoked_cert))
      File.write(settings[:cert_inventory], "\n"+"I am bad foo.example.com\n"+ca.inventory_entry(revoked_cert)+"\nHello")
      allow(File).to receive(:exist?).and_return(true)
      number_of_removed_crl_entries = subject.prune_using_certname(ca_crl, ca_key, settings[:cert_inventory], settings[:cadir], ["foo.example.com"])
      expect(number_of_removed_crl_entries).to eq(1)
      expect(ca_crl.revoked.length).to eq(0)
    end
  end

  describe 'update' do
    it 'bumps CRL number up by 1' do
      ca_key = OpenSSL::PKey::RSA.new(512)
      ca_cert = create_cert(ca_key, "Bazzup")
      ca_crl = create_crl(ca_cert, ca_key)

      extensions_before = ca_crl.extensions.select { |ext| ext.oid == "crlNumber"}
      extensions_before.each do |ext|
        expect(ext.value.to_i).to eq(0)
      end

      subject.update_pruned_CRL(ca_crl, ca_key)

      extensions_after = ca_crl.extensions.select { |ext| ext.oid == "crlNumber"}
      extensions_after.each do |ext|
        expect(ext.value.to_i).to eq(1)
      end
    end
  end
end
