require 'spec_helper'
require 'puppetserver/ca/puppetserver_config'

RSpec.describe 'Puppetserver::Ca::PuppetserverConfig' do
  it 'overrides defaults with settings from the config file' do
    Dir.mktmpdir do |tmpdir|
      puppetserver_conf = File.join(tmpdir, 'ca.conf')
      File.open(puppetserver_conf, 'w') do |f|
      f.puts(<<-CONF)
      certificate-authority : {
          cadir: "/etc/fake/path/ca"
          cert-inventory: "/etc/fake/inventory.txt"
      }
      CONF
      end

      conf = Puppetserver::Ca::PuppetserverConfig.new(puppetserver_conf)
      conf.load
      expect(conf.settings[:cadir]).to eq('/etc/fake/path/ca')
      expect(conf.settings[:cacert]).to eq('/etc/fake/path/ca/ca_crt.pem')
      expect(conf.settings[:cert_inventory]).to eq('/etc/fake/inventory.txt')
    end
  end

  it 'logs errors that occur during HOCON parsing' do
    Dir.mktmpdir do |tmpdir|
      puppetserver_conf = File.join(tmpdir, 'ca.conf')
      File.open(puppetserver_conf, 'w') do |f|
      f.puts(<<-CONF)
      certificate-authority :
          cadir: "/etc/fake/path/ca"
          cert-inventory: "/etc/fake/inventory.txt"
      }
      CONF
      end

      conf = Puppetserver::Ca::PuppetserverConfig.new(puppetserver_conf)
      conf.load
      expect(conf.errors.size).to eq(1)
      expect(conf.errors[0]).to match(/Expecting close brace/)
    end
  end
end
