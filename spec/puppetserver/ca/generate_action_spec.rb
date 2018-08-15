require 'spec_helper'
require 'utils/ssl'

require 'tmpdir'
require 'fileutils'

require 'puppetserver/ca/import_action'
require 'puppetserver/ca/cli'

RSpec.describe Puppetserver::Ca::GenerateAction do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:usage) { /.*Usage:.* puppetserver ca generate.*Display this generate specific help output.*/m }

  it 'prints the help output & returns 1 if invalid flags are given' do
    exit_code = Puppetserver::Ca::Cli.run(['generate', '--hello'], stdout, stderr)
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to eq(1)
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = Puppetserver::Ca::Cli.run(['generate', '--config', conf], stdout, stderr)
        expect(stderr.string).to be_empty
        expect(stdout.string.strip).to eq("Generation succeeded. Find your files in #{tmpdir}/ca")
        expect(exit_code).to eq(0)
      end
    end
  end

  it 'generates a bundle ca_crt file, ca_key, int_key, and ca_crl file' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = Puppetserver::Ca::Cli.run(['generate', '--config', conf], stdout, stderr)
        expect(exit_code).to eq(0)
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crt.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_key.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'root_key.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crl.pem'))).to be true
      end
    end
  end
end
