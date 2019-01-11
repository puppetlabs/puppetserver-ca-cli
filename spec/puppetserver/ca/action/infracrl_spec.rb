require 'spec_helper'
require 'shared_examples/cli_parsing'
require 'utils/ssl'

require 'puppetserver/ca/action/infracrl'
require 'puppetserver/ca/logger'

RSpec.describe Puppetserver::Ca::Action::InfraCRL do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }
  let(:usage) { /.*Usage:.* puppetserver ca infracrl.*Display this setup specific help output.*/m }

  subject { Puppetserver::Ca::Action::InfraCRL.new(logger) }

  it 'prints the help output & returns 1 if invalid flags are given' do
    _, exit_code = subject.parse(['--hello'])
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to eq(1)
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_ca_in tmpdir do |conf, ca_dir|
        inventory = File.join(ca_dir, 'infra_inventory.txt')
        File.open(inventory, 'w') do |f|
          f.puts ''
        end

        exit_code = subject.run({ 'config' => conf })
        puts stderr.string
        expect(stderr.string).to be_empty
        expect(exit_code).to eq(0)
      end
    end
  end

  it 'generates auxiliary infra CRL files' do
    Dir.mktmpdir do |tmpdir|
      with_ca_in tmpdir do |conf, ca_dir|
        inventory = File.join(ca_dir, 'infra_inventory.txt')
        serials = File.join(ca_dir, 'infra_serials')
        infra_crl = File.join(ca_dir, 'infra_crl.pem')

        File.open(inventory, 'w') do |f|
          f.puts ''
        end
        exit_code = subject.run({ 'config' => conf })
        expect(File.exist?(serials)).to be true
        expect(File.exist?(infra_crl)).to be true
      end
    end
  end
end
