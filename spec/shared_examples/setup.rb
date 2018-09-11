require 'puppetserver/ca/action/import'
require 'utils/ssl'

def mode(file)
  File.stat(file).mode.to_s(8)[-3..-1]
end

def default_config(conf, bundle, key, chain)
  shared_flags = {'config' => conf, 'subject-alt-names' => '', 'certname' => 'foocert'}
  import_flags = {'cert-bundle' => bundle, 'private-key' => key, 'crl-chain' => chain}
  importing ? shared_flags.merge(import_flags) : shared_flags.merge({'ca-name' => ''})
end

def flags_without_sans(*args)
  config = default_config(*args)
  config.flat_map{|k,v| k =~ /subject-alt-names/ ? [] : ["--#{k}", v] }
end

RSpec.shared_examples 'properly sets up ca and ssl dir' do |action_class|
  include Utils::SSL

  let(:importing) { action_class == Puppetserver::Ca::Action::Import }

  it 'creates all files with correct permissions' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        setup = action_class.new(logger)
        config = default_config(conf, bundle, key, chain)

        exit_code = setup.run(config)

        expect(exit_code).to eq(0)

        files = [['ca', 'ca_crt.pem', '644'],
                 ['ca', 'ca_crl.pem', '644'],
                 ['ca', 'ca_key.pem', '640'],
                 ['ca', 'infra_crl.pem', '644'],
                 ['ca', 'inventory.txt', '644'],
                 ['ca', 'infra_inventory.txt', '644'],
                 ['ca', 'serial', '644'],
                 ['ca', 'infra_serials', '644'],
                 ['ssl', 'certs', 'foocert.pem', '644'],
                 ['ssl', 'private_keys', 'foocert.pem', '640'],
                 ['ssl', 'public_keys', 'foocert.pem', '644']]


        files.each do |args|
          perms = args.pop
          file = File.join(tmpdir, *args)
          expect(File.exist?(file)).to be(true), "#{file} does not exit"
          expect(mode(file)).to eq(perms)
        end

        unless importing
          file = File.join(tmpdir, 'ca', 'root_key.pem')
          expect(File.exist?(file)).to be true
          expect(mode(file)).to eq('640')
        end
      end
    end
  end

  it 'accepts unprefixed alt names' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        flags = flags_without_sans(bundle, key, chain, conf)
        result, maybe_code = subject.parse(flags + ['--subject-alt-names', 'foo.com'])
        expect(maybe_code).to eq(nil)
        expect(result['subject-alt-names']).to eq('foo.com')
      end
    end
  end

  it 'accepts DNS and IP alt names' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        flags = flags_without_sans(bundle, key, chain, conf)
        result, maybe_code = subject.parse(flags + ['--subject-alt-names', 'DNS:foo.com,IP:123.456.789'])
        expect(maybe_code).to eq(nil)
        expect(result['subject-alt-names']).to eq('DNS:foo.com,IP:123.456.789')
      end
    end
  end

  it 'adds default subject alt names to the master cert' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        config = default_config(conf, bundle, key, chain)
        exit_code = subject.run(config)

        expect(exit_code).to eq(0)

        master_cert_file = File.join(tmpdir, 'ssl', 'certs', 'foocert.pem')
        expect(File.exist?(master_cert_file)).to be true
        master_cert = OpenSSL::X509::Certificate.new(File.read(master_cert_file))
        alt_names = master_cert.extensions.find do |ext|
          ext.to_s =~ /subjectAltName/
        end

        expect(alt_names.to_s).to eq("subjectAltName = DNS:puppet, DNS:foocert")
      end
    end
  end

  it 'adds custom subject alt names to the master cert' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        config = default_config(conf, bundle, key, chain)
        exit_code = subject.run(config.merge({'subject-alt-names' => 'bar.net,IP:123.123.0.1'}))

        expect(exit_code).to eq(0)

        master_cert_file = File.join(tmpdir, 'ssl', 'certs', 'foocert.pem')
        expect(File.exist?(master_cert_file)).to be true
        master_cert = OpenSSL::X509::Certificate.new(File.read(master_cert_file))
        alt_names = master_cert.extensions.find do |ext|
          ext.to_s =~ /subjectAltName/
        end

        expect(alt_names.to_s).to eq("subjectAltName = DNS:foocert, DNS:bar.net, IP Address:123.123.0.1")
      end
    end
  end

  it 'will not overwrite existing CA files' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        config = default_config(conf, bundle, key, chain)
        exit_code = subject.run(config)
        expect(exit_code).to eq(0)
        exit_code2 = subject.run(config)
        expect(exit_code2).to eq(1)
        expect(stderr.string).to match(/Existing file.*/)
        expect(stderr.string).to match(/.*please delete the existing files.*/)
      end
    end
  end

  it 'honors existing master key pair when generating masters cert' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        private_path = File.join(tmpdir, 'ssl', 'private_keys', 'foocert.pem')
        public_path = File.join(tmpdir, 'ssl', 'public_keys', 'foocert.pem')
        cert_path = File.join(tmpdir, 'ssl', 'certs', 'foocert.pem')

        FileUtils.mkdir_p(File.dirname(private_path))
        FileUtils.mkdir_p(File.dirname(public_path))

        pkey = OpenSSL::PKey::RSA.new(512)
        File.write(private_path, pkey.to_pem)
        File.write(public_path, pkey.public_key.to_pem)

        config = default_config(conf, bundle, key, chain)
        exit_code = subject.run(config)

        expect(exit_code).to eq(0)

        expect(File.exist?(File.join(cert_path))).to be true
        expect(File.read(private_path)).to eq pkey.to_pem
        expect(File.read(public_path)).to eq pkey.public_key.to_pem

        cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
        expect(cert.public_key.to_pem).to eq pkey.public_key.to_pem
        expect(cert.check_private_key(pkey)).to be true
      end
    end
  end

  it 'fails if only one of masters public, private keys are present' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        pkey = OpenSSL::PKey::RSA.new(512)
        private_path = File.join(tmpdir, 'ssl', 'private_keys', 'foocert.pem')

        FileUtils.mkdir_p File.dirname(private_path)
        File.write(private_path, pkey.to_pem)

        config = default_config(conf, bundle, key, chain)
        exit_code = subject.run(config)

        expect(exit_code).to eq(1)
        expect(stderr.string).to match(/Missing public key/)
      end
    end

    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        pkey = OpenSSL::PKey::RSA.new(512)
        public_path = File.join(tmpdir, 'ssl', 'public_keys', 'foocert.pem')

        FileUtils.mkdir_p File.dirname(public_path)
        File.write(public_path, pkey.public_key.to_pem)

        config = default_config(conf, bundle, key, chain)
        exit_code = subject.run(config)

        expect(exit_code).to eq(1)
        expect(stderr.string).to match(/Missing private key/)
      end
    end
  end
end
