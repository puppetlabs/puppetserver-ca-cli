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

    it 'disallows running --all with other action flags' do
      result, with_revoked_code = subject.parse(['--all', '--revoked'])
      result, with_expired_code = subject.parse(['--all', '--expired'])
      result, with_certname_code = subject.parse(['--all', '--certname', 'foo'])
      expect(with_revoked_code).to eq(1)
      expect(with_expired_code).to eq(1)
      expect(with_certname_code).to eq(1)
      expect(stderr.string).to match(/The --all flag must not be used with --expired, --revoked, or --certname/)
    end
  end

  def timefmt(time)
    time.utc.strftime("%Y-%m-%dT%H:%M:%SUTC")
  end

  def prepare_certs_and_inventory(cadir)
    FileUtils.mkdir_p "#{cadir}/signed"
    # nodeA expires now, nodeB expires far in the future, nodeC is expired and not present in inventory
    # Include a line for an old nodeB cert to ensure we aren't deleting it and only acting based off
    # the newest entry for a cert
    #
    # Loads the key if this is run inside a with_ca_in block. Otherwise, creates a new one.
    key = File.exist?("#{cadir}/ca_key.pem") ? OpenSSL::PKey::RSA.new(File.read("#{cadir}/ca_key.pem")) : OpenSSL::PKey::RSA.new(512)
    not_before_unexpired = Time.now - 1
    not_after_unexpired = Time.now + 360000
    not_before_expired = Time.now - 100
    not_after_expired = Time.now - 1
    File.write("#{cadir}/signed/nodeA.pem", create_cert(key, 'nodeA', nil, nil, not_before_expired, not_after_expired, 1))
    File.write("#{cadir}/signed/nodeB.pem", create_cert(key, 'nodeB', nil, nil, not_before_unexpired, not_after_unexpired, 3))
    File.write("#{cadir}/signed/nodeC.pem", create_cert(key, 'nodeC', nil, nil, not_before_expired, not_after_expired, 4))
    inventory = <<~INV
      0x0001 #{timefmt(not_before_expired)} #{timefmt(not_after_expired)} /CN=nodeA
      0x0002 #{timefmt(not_before_expired)} #{timefmt(not_after_expired)} /CN=nodeB
      0x0003 #{timefmt(not_before_unexpired)} #{timefmt(not_after_unexpired)} /CN=nodeB

    INV
    File.write("#{cadir}/inventory.txt", inventory)
    key
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
          with_ca_in tmpdir do |config, cadir|
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'expired' => true})
            expect(code).to eq(0)
            expect(stdout.string).to match(/2 certificates deleted./)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeC.pem")).to eq(false)
          end
        end
      end

      it 'handles one of the certs from inventory.txt being missing' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_certs_and_inventory(cadir)
            FileUtils.rm_f("#{cadir}/signed/nodeA.pem")
            code = subject.run({'config' => config, 'expired' => true})
            expect(code).to eq(24)
            expect(stderr.string).to match(/Could not find certificate file at #{cadir}\/signed\/nodeA.pem/)
            expect(stdout.string).to match(/1 certificate deleted./)
          end
        end
      end

      it 'handles a cert on disk not in the inventory file being a bad cert file' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_certs_and_inventory(cadir)
            File.write("#{cadir}/signed/nodeC.pem", "badcert")
            code = subject.run({'config' => config, 'expired' => true})
            expect(code).to eq(24)
            expect(stderr.string).to match(/Error reading certificate at #{cadir}\/signed\/nodeC.pem/)
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
          with_ca_in tmpdir do |config, cadir|
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'certname' => ['nodeA']})
            expect(code).to eq(0)
            expect(stdout.string).to match(/1 certificate deleted./)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeC.pem")).to eq(true)
          end
        end
      end

      it 'deletes the given multiple certnames' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'certname' => ['nodeA', 'nodeB']})
            expect(code).to eq(0)
            expect(stdout.string).to match(/2 certificates deleted./)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeC.pem")).to eq(true)
          end
        end
      end

      it 'shows an error when one of the certs does not exist' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'certname' => ['nodeA', 'lolwut']})
            expect(code).to eq(24)
            expect(stderr.string).to match(/Could not find certificate file at.*lolwut.pem/)
            expect(stdout.string).to match(/1 certificate deleted./)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeC.pem")).to eq(true)
          end
        end
      end

      it 'works correctly with the --expired flag, adding on an additional cert' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'expired' => true, 'certname' => ['nodeB']})
            expect(code).to eq(0)
            expect(stdout.string).to match(/3 certificates deleted./)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeC.pem")).to eq(false)
          end
        end
      end
    end

    describe '--revoked' do
      before(:each) { allow(connection).to receive(:get).and_return(offline) }

      def prepare_revoked(cadir)
        # This should be run inside a with_ca_in block so we pick up the right key
        ca_key = prepare_certs_and_inventory(cadir)
        ca_crt = OpenSSL::X509::Certificate.new(File.read("#{cadir}/ca_crt.pem"))
        # Create nodeD.pem at serial 5 and revoke it (test it deletes currently revoked cert)
        # Revoke nodeB at serial 3, regen at serial 6 (test it finds the old serial and doesn't delete the current cert)
        # Revoke nodeC (test it searches the disk for the serial and deletes it)
        not_before = Time.now - 1
        not_after = Time.now + 360000
        nodeD_cert = create_cert(ca_key, 'nodeD', nil, nil, not_before, not_after, 5)
        nodeB_cert = OpenSSL::X509::Certificate.new(File.read("#{cadir}/signed/nodeB.pem"))
        nodeB_new_cert = create_cert(ca_key, 'nodeB', nil, nil, not_before, not_after, 6)
        nodeC_cert = OpenSSL::X509::Certificate.new(File.read("#{cadir}/signed/nodeC.pem"))
        File.write("#{cadir}/signed/nodeB.pem", nodeB_new_cert)
        File.write("#{cadir}/signed/nodeD.pem", nodeD_cert)
        File.write("#{cadir}/ca_crl.pem", create_crl(ca_crt, ca_key, [nodeB_cert, nodeC_cert, nodeD_cert]))
        newinv = <<~INV
        0x0005 #{timefmt(not_before)} #{timefmt(not_after)} /CN=nodeD
        0x0006 #{timefmt(not_before)} #{timefmt(not_after)} /CN=nodeB
        INV
        File.write("#{cadir}/inventory.txt", newinv, mode: 'a')
      end

      it 'deletes a currently revoked cert on disk, does not delete cert for certname with old serial that was revoked, and deletes cert that is revoked but not in inventory.txt' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_revoked(cadir)
            code = subject.run({'config' => config, 'revoked' => true})
            expect(code).to eq(0)
            expect(stdout.string).to match(/2 certificates deleted./)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeC.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeD.pem")).to eq(false)
          end
        end
      end

      it 'handles trying to read a bad certificate when verifying current cert does not have the old serial' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_revoked(cadir)
            File.write("#{cadir}/signed/nodeB.pem", 'bad data')
            code = subject.run({'config' => config, 'revoked' => true})
            expect(code).to eq(24)
            expect(stdout.string).to match(/2 certificates deleted./)
            expect(stderr.string).to match(/Error reading serial from certificate for nodeB/)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeC.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeD.pem")).to eq(false)
          end
        end
      end

      it 'handles not finding a revoked serial in inventory.txt or in files on disk' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_revoked(cadir)
            FileUtils.rm_f("#{cadir}/signed/nodeC.pem")
            code = subject.run({'config' => config, 'revoked' => true})
            expect(code).to eq(24)
            expect(stdout.string).to match(/1 certificate deleted./)
            expect(stderr.string).to match(/Could not find serial 4 in inventory.txt or in any certificate file currently on disk./)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(true)
            expect(File.exist?("#{cadir}/signed/nodeD.pem")).to eq(false)
          end
        end
      end
    end

    describe '--all' do
      before(:each) { allow(connection).to receive(:get).and_return(offline) }

      it 'deletes all certs in the signed directory' do
        Dir.mktmpdir do |tmpdir|
          with_ca_in tmpdir do |config, cadir|
            prepare_certs_and_inventory(cadir)
            code = subject.run({'config' => config, 'all' => true})
            expect(code).to eq(0)
            expect(stdout.string).to match(/3 certificates deleted./)
            expect(File.exist?("#{cadir}/signed/nodeA.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeB.pem")).to eq(false)
            expect(File.exist?("#{cadir}/signed/nodeC.pem")).to eq(false)
          end
        end
      end
    end
  end
end

