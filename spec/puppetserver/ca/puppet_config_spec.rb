require 'spec_helper'
require 'puppetserver/ca/puppet_config'

RSpec.describe 'Puppetserver::Ca::PuppetConfig' do
  it 'parses basic inifile' do
    conf = Puppetserver::Ca::PuppetConfig.new
    parsed = conf.parse_text(<<-INI)
    server = certname

    [master]
      dns_alt_names=puppet,foo
      cadir        = /var/www/super-secure

    [main]
    environment = prod_1_env
    INI

    expect(parsed.keys).to include(:master, :main)
    expect(parsed[:main]).to include({
      server: 'certname',
      environment: 'prod_1_env'
    })
    expect(parsed[:master]).to include({
      dns_alt_names: 'puppet,foo',
      cadir: '/var/www/super-secure'
    })
  end

  it 'discards weird file metadata info' do
    conf = Puppetserver::Ca::PuppetConfig.new
    parsed = conf.parse_text(<<-INI)
    [ca]
      cadir = /var/www/ca {user = service}

    [master]
      coming_at = Innsmouth
      mantra = Pu̴t t̢h͞é ̢ćlas̸s̡e̸s̢ ̴in̡ arra̴y͡s̸ ̸o͟r̨ ̸hashe͜s̀ or w̨h̕át̀ev̵èr

    Now ̸to m̡et̴apr̷og҉ram a si͠mpl͞e ḑsl
    INI

    expect(parsed).to include({ca: {cadir: '/var/www/ca'}})
  end

  it 'resolves dependent settings properly' do
    Dir.mktmpdir do |tmpdir|
      puppet_conf = File.join(tmpdir, 'puppet.conf')
      File.open puppet_conf, 'w' do |f|
        f.puts(<<-INI)
          [master]
            ssldir = /foo/bar
            cacrl = /fizz/buzz/crl.pem
        INI
      end

      conf = Puppetserver::Ca::PuppetConfig.new(puppet_conf)
      conf.load

      expect(conf.errors).to be_empty
      expect(conf.ca_cert_path).to eq('/foo/bar/ca/ca_crt.pem')
      expect(conf.ca_crl_path).to eq('/fizz/buzz/crl.pem')
    end
  end

  it 'errs if it cannot resolve dependent settings properly' do
    Dir.mktmpdir do |tmpdir|
      puppet_conf = File.join(tmpdir, 'puppet.conf')
      File.open puppet_conf, 'w' do |f|
        f.puts(<<-INI)
          [master]
            ssldir = $vardir/ssl
        INI
      end

      conf = Puppetserver::Ca::PuppetConfig.new(puppet_conf)
      conf.load

      expect(conf.errors.first).to include('$vardir in $vardir/ssl')
      expect(conf.ca_cert_path).to eq('$vardir/ssl/ca/ca_crt.pem')
    end
  end
end
