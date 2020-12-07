require 'puppetserver/ca/action/migrate'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/utils/config'

RSpec.describe Puppetserver::Ca::Action::Migrate do

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  subject { Puppetserver::Ca::Action::Migrate.new(logger) }

  describe 'flags' do
    it 'has no required arguments' do
      result, maybe_code = subject.parse([])
      expect(maybe_code).to be(nil)
      expect(result['config']).to eq(nil)
    end

    it 'takes a custom puppet.conf location' do
      result, maybe_code = subject.parse(['--config', '/dev/tcp/example.conf'])
      expect(maybe_code).to be(nil)
      expect(result['config']).to eq('/dev/tcp/example.conf')
    end
  end

  describe 'validation' do
    it 'prints the help output & returns 1 if invalid flags are given' do
      _, code = subject.parse(['--hello', '--certname', "amy.net"])
      expect(code).to eq(1)
      expect(stderr.string).to match(/Error.*--hello/m)
    end
  end

  describe '#run' do
    let(:filesystem) { Puppetserver::Ca::Utils::FileSystem }
    let(:httpclient) { Puppetserver::Ca::Utils::HttpClient }
    let(:config) { Puppetserver::Ca::Config::Puppet.new.load(logger: logger) }
    let(:new_cadir) { Puppetserver::Ca::Utils::Config.new_default_cadir }

    it 'exits with 1 when the server is found running' do
      allow(httpclient).to receive(:check_server_online).and_return(true)
      expect(subject.run(config)).to eq(1)
    end

    it 'exits with 1 when the puppetserver/ca dir is found' do
      allow(httpclient).to receive(:check_server_online).and_return(false)
      allow(filesystem).to receive(:check_for_existing_files).
        with(new_cadir).and_return(['/path/'])
      expect(subject.run(config)).to eq(1)
    end

    it 'exits with 1 when no CA dir is found' do
      allow(httpclient).to receive(:check_server_online).and_return(false)
      allow(filesystem).to receive(:check_for_existing_files).
                             with(new_cadir).and_return([])
      allow(filesystem).to receive(:check_for_existing_files).
                             with(config[:cadir]).and_return([])
      expect(subject.run(config)).to eq(1)
    end

    it 'calls #migrate when the system is considered ready' do
      allow(httpclient).to receive(:check_server_online).and_return(false)
      expect(filesystem).to receive(:check_for_existing_files).
                             with(new_cadir).and_return([])
      allow(filesystem).to receive(:check_for_existing_files).
                             with(config[:cadir]).and_return(['/path/to/cadir'])
      expect(subject).to receive(:migrate).and_return(nil)
      expect(subject.run(config)).to eq(0)
    end
  end

  describe '#migrate' do
    let(:new_cadir) do
      tmpdir = Dir.mktmpdir
      File.join(tmpdir, 'ca')
    end
    let(:old_cadir) do
      tmpdir = Dir.mktmpdir
      cadir = File.join(tmpdir, 'ca')
      FileUtils.mkdir(cadir)
      FileUtils.touch(File.join(cadir, 'newfile'))
      cadir
    end

    it 'moves the dir and creates the symlink' do
      subject.migrate(old_cadir, new_cadir)
      expect(File.directory?(new_cadir)).to eq(true)
      expect(File.symlink?(old_cadir)).to eq(true)
      expect(File.readlink(old_cadir)).to eq(new_cadir)
      expect(File.exist?(File.join(old_cadir, 'newfile')))
      expect(File.exist?(File.join(new_cadir, 'newfile')))
    end
  end
end

