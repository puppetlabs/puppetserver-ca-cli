require 'spec_helper'
require 'utils/ssl'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/logger'
require 'stringio'
require 'fileutils'

RSpec.describe 'Puppetserver::Ca::Config::Puppet' do
  subject { Puppetserver::Ca::Config::Puppet.new }
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  it 'parses basic inifile' do
    parsed = subject.parse_text(<<-INI)
    certname = foo.example.org

    [agent]
      server = certname

    [master]
      dns_alt_names=puppet,foo
      cadir        = /var/www/super-secure

    [main]
    environment = prod_1_env
    INI

    expect(parsed.keys).to include(:agent, :master, :main)
    expect(parsed[:main]).to include({
      certname: 'foo.example.org',
      environment: 'prod_1_env'
    })
    expect(parsed[:master]).to include({
      dns_alt_names: 'puppet,foo',
      cadir: '/var/www/super-secure'
    })
    expect(parsed[:agent]).to include({
      server: 'certname'
    })
  end

  it 'discards weird file metadata info' do
    parsed = subject.parse_text(<<-INI)
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
          [agent]
            publickeydir = /agent/pubkeys

          [main]
            certname = fooberry

          [master]
            ssldir = /foo/bar
            cacrl = /fizz/buzz/crl.pem
        INI
      end

      conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
      conf.load(logger: logger)

      expect(conf.errors).to be_empty
      expect(conf.settings[:localcacert]).to eq('/foo/bar/certs/ca.pem')
      expect(conf.settings[:cacrl]).to eq('/fizz/buzz/crl.pem')
      expect(conf.settings[:hostpubkey]).to eq('/agent/pubkeys/fooberry.pem')
    end
  end

  it 'correctly reads server_list' do
    p1 = subject.parse_text(<<-INI)
    [main]
      server_list = foo:80,bar,baz:99
    INI
    expect(p1[:main]).to include({
      server_list: 'foo:80,bar,baz:99'
    })

    s1 = subject.resolve_settings(p1[:main], logger)
    expect(s1[:server_list]).to eq([
      ["foo", "80"], ["bar"], ["baz", "99"]
    ])

    p2 = subject.parse_text(<<-INI)
      [main]
        server = foo
    INI
    s2 = subject.resolve_settings(p2[:main], logger)
    expect(s2[:server_list]).to eq([])
  end

  it 'uses server_list for default ca_server and ca_port' do
    parsed = subject.parse_text(<<-INI)
      [main]
        server_list = ca.example.com:8080

      [master]
        server = foo-master
    INI

    settings = subject.resolve_settings(parsed[:main].merge(parsed[:master]), logger)

    expect(settings[:server_list]).to eq([["ca.example.com", "8080"]])
    expect(settings[:ca_server]).to eq("ca.example.com")
    expect(settings[:ca_port]).to eq('8080')
  end

  it 'combines agent, main, and master sections properly' do
    Dir.mktmpdir do |tmpdir|
      puppet_conf = File.join(tmpdir, 'puppet.conf')
      File.open puppet_conf, 'w' do |f|
        f.puts(<<-INI)
          [agent]
            server = agent-server
            cacrl = agent-cacrl

          [main]
            server = main-server
            cacrl = main-cacrl
            certname = main-certname

          [master]
            server = master-server
            certname = master-certname
        INI
      end

      conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
      conf.load(logger: logger)

      expect(conf.errors).to be_empty
      expect(conf.settings[:certname]).to eq('master-certname')
      expect(conf.settings[:server]).to eq('master-server')
      expect(conf.settings[:cacrl]).to eq('main-cacrl')
    end
  end

  it 'converts ca_ttl setting correctly into seconds' do
    Dir.mktmpdir do |tmpdir|
      puppet_conf = File.join(tmpdir, 'puppet.conf')
      File.open puppet_conf, 'w' do |f|
        f.puts(<<-INI)
          [master]
            ca_ttl = 5y
        INI
      end

      conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
      conf.load(logger: logger)

      expect(conf.errors).to be_empty
      expect(conf.settings[:ca_ttl]).to eq(157680000)
    end
  end

  context "when dns_alt_names are provided" do
    it 'prepends "DNS" to unprefixed alt names and includes default certname' do
      allow_any_instance_of(Puppetserver::Ca::Config::Puppet).
        to receive(:default_certname).and_return("chihuahua-333")

      Dir.mktmpdir do |tmpdir|
        puppet_conf = File.join(tmpdir, 'puppet.conf')
        File.open puppet_conf, 'w' do |f|
          f.puts(<<-INI)
            [master]
              dns_alt_names = foo.com,IP:123.456.789
          INI
        end

        conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
        conf.load(logger: logger)

        expect(conf.errors).to be_empty
        expect(conf.settings[:subject_alt_names]).
          to eq('DNS:chihuahua-333, DNS:foo.com, IP:123.456.789')
      end
    end
  end

  context "when dns_alt_names are NOT provided" do
    it 'it returns an empty string for subject_alt_names' do
      Dir.mktmpdir do |tmpdir|
        puppet_conf = File.join(tmpdir, 'puppet.conf')
        File.open puppet_conf, 'w' do |f|
          f.puts(<<-INI)
            [master]
              certname = foo.com
          INI
        end

        conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
        conf.load(logger: logger)

        expect(conf.errors).to be_empty
        expect(conf.settings[:subject_alt_names]).
          to eq('')
      end
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

      conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
      conf.load(logger: logger)

      expect(conf.errors.first).to include('$vardir in $vardir/ssl')
      expect(conf.settings[:localcacert]).to eq('$vardir/ssl/certs/ca.pem')
    end
  end

  it 'warns if the cadir is set to a custom location within the ssldir' do
    Dir.mktmpdir do |tmpdir|
      puppet_conf = File.join(tmpdir, 'puppet.conf')
      ssldir = File.join(tmpdir, 'ssl')
      cadir = File.join(ssldir, 'ca')
      File.open puppet_conf, 'w' do |f|
        f.puts(<<-INI)
          [main]
            ssldir = #{ssldir}

          [master]
            cadir = #{cadir}
        INI
      end

      conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
      settings = conf.load(logger: logger)

      expect(settings[:cadir]).to eq(cadir)
      expect(stderr.string.each_line.first).
        to match(/migrate out from the puppet confdir to the \/etc\/puppetlabs\/puppetserver\/ca/)
    end
  end

  it 'warns if the cadir already exists within the ssldir' do
    Dir.mktmpdir do |tmpdir|
      puppet_conf = File.join(tmpdir, 'puppet.conf')
      ssldir = File.join(tmpdir, 'ssl')
      cadir = File.join(ssldir, 'ca')
      FileUtils.mkdir_p cadir
      File.open puppet_conf, 'w' do |f|
        f.puts(<<-INI)
          [main]
            confdir = #{tmpdir}
            ssldir = #{ssldir}
        INI
      end

      conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
      settings = conf.load(logger: logger)

      expect(settings[:cadir]).to eq(cadir)
      expect(stderr.string.each_line.first).
        to match(/migrate out from the puppet confdir to the \/etc\/puppetlabs\/puppetserver\/ca/)
    end
  end

  it 'does not warn if configured for a cadir outside of the ssldir' do
    Dir.mktmpdir do |tmpdir|
      puppet_conf = File.join(tmpdir, 'puppet.conf')
      ssldir = File.join(tmpdir, 'ssl')
      cadir = File.join(tmpdir, 'ca')
      File.open puppet_conf, 'w' do |f|
        f.puts(<<-INI)
          [main]
            ssldir = #{ssldir}

          [master]
            cadir = #{cadir}
        INI
      end

      conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
      settings = conf.load(logger: logger)

      expect(settings[:cadir]).to eq(cadir)
      expect(stderr.string).to be_empty
    end
  end

  it 'does not warn and returns the correct directory by default w/o existing directories or config' do
    Dir.mktmpdir do |tmpdir|
      puppet_conf = File.join(tmpdir, 'puppet.conf')
      confdir = File.join(tmpdir, 'puppet_confdir')
      File.open puppet_conf, 'w' do |f|
        f.puts(<<-INI)
          [main]
            confdir = #{confdir}
        INI
      end

      conf = Puppetserver::Ca::Config::Puppet.new(puppet_conf)
      settings = conf.load(logger: logger)

      expect(settings[:ssldir]).to eq(File.join(confdir, 'ssl'))
      expect(settings[:cadir]).to eq(File.join(tmpdir, 'puppetserver', 'ca'))
      expect(stderr.string).to be_empty
    end
  end

  context 'building the default certname' do
    it 'when there is a domain, concatenates the hostname and domain' do
      expect(Facter).to receive(:value).with(:hostname).and_return("foo")
      expect(Facter).to receive(:value).with(:domain).and_return("example.com")

      conf = Puppetserver::Ca::Config::Puppet.new
      expect(conf.default_certname).to eq("foo.example.com")
    end

    it 'when domain is nil, returns just the hostname' do
      expect(Facter).to receive(:value).with(:hostname).and_return("foo")
      expect(Facter).to receive(:value).with(:domain).and_return(nil)

      conf = Puppetserver::Ca::Config::Puppet.new
      expect(conf.default_certname).to eq("foo")
    end
  end
end
