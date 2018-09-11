require 'spec_helper'
require 'utils/ssl'

require 'tmpdir'
require 'fileutils'
require 'puppetserver/ca/action/generate'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/host'

RSpec.describe Puppetserver::Ca::Action::Generate do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }
  let(:usage) { /.*Usage:.* puppetserver ca generate.*Display this generate specific help output.*/m }

  subject { Puppetserver::Ca::Action::Generate.new(logger) }

  it 'prints the help output & returns 1 if invalid flags are given' do
    _, exit_code = subject.parse(['--hello'])
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to eq(1)
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = subject.run({ 'config' => conf,
                                  'subject-alt-names' => '',
                                  'ca-name' => '',
                                  'certname' => '' })
        expect(stderr.string).to be_empty
        expect(stdout.string.strip).to eq("Generation succeeded. Find your files in #{tmpdir}/ca")
        expect(exit_code).to eq(0)
      end
    end
  end

  it 'generates correct files with correct permissions' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = subject.run({ 'config' => conf,
                                  'subject-alt-names' => '',
                                  'ca-name' => '',
                                  'certname' => 'foocert' })
        expect(exit_code).to eq(0)

        created_correctly = ->(*args) do
          perms = args.pop
          file = File.join(tmpdir, *args)
          File.exists?(file) &&
            File.stat(file).mode.to_s(8)[-3..-1] == perms
        end

        expect(created_correctly.('ca', 'ca_crt.pem', '644')).to be true
        expect(created_correctly.('ca', 'ca_key.pem', '640')).to be true
        expect(created_correctly.('ca', 'root_key.pem', '640')).to be true
        expect(created_correctly.('ca', 'ca_crl.pem', '644')).to be true
        expect(created_correctly.('ca', 'infra_crl.pem', '644')).to be true
        expect(created_correctly.('ca', 'inventory.txt', '644')).to be true
        expect(created_correctly.('ca', 'infra_inventory.txt', '644')).to be true
        expect(created_correctly.('ca', 'infra_serials', '644')).to be true
        expect(created_correctly.('ca', 'serial', '644')).to be true
        expect(created_correctly.('ssl', 'certs', 'foocert.pem', '644')).to be true
        expect(created_correctly.('ssl', 'private_keys', 'foocert.pem', '640')).to be true
        expect(created_correctly.('ssl', 'public_keys', 'foocert.pem', '644')).to be true
      end
    end
  end

  describe 'command line name overrides' do
    it 'uses the ca_name as specified on the command line' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |conf|
          exit_code = subject.run({ 'config' => conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => 'Foo CA',
                                    'certname' => '' })
          expect(exit_code).to eq(0)
          ca_cert_file = File.join(tmpdir, 'ca', 'ca_crt.pem')
          expect(File.exist?(ca_cert_file)).to be true
          ca_cert = OpenSSL::X509::Certificate.new(File.read(ca_cert_file))
          expect(ca_cert.subject.to_s).to include('Foo CA')
        end
      end
    end

    it 'uses the default ca_name if none specified' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |conf|
          exit_code = subject.run({ 'config' => conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => '',
                                    'certname' => '' })
          expect(exit_code).to eq(0)
          ca_cert_file = File.join(tmpdir, 'ca', 'ca_crt.pem')
          expect(File.exist?(ca_cert_file)).to be true
          ca_cert = OpenSSL::X509::Certificate.new(File.read(ca_cert_file))
          expect(ca_cert.subject.to_s).to include('Puppet CA')
        end
      end
    end
  end

  describe 'subject alternative names' do
    it 'accepts unprefixed alt names' do
      result, maybe_code = subject.parse(['--subject-alt-names', 'foo.com'])
      expect(maybe_code).to eq(nil)
      expect(result['subject-alt-names']).to eq('foo.com')
    end

    it 'accepts DNS and IP alt names' do
      result, maybe_code = subject.parse(['--subject-alt-names', 'DNS:foo.com,IP:123.456.789'])
      expect(maybe_code).to eq(nil)
      expect(result['subject-alt-names']).to eq('DNS:foo.com,IP:123.456.789')
    end

    it 'adds default subject alt names to the master cert' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |conf|
          exit_code = subject.run({ 'config' => conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => '',
                                    'certname' => 'foo' })
          expect(exit_code).to eq(0)
          master_cert_file = File.join(tmpdir, 'ssl', 'certs', 'foo.pem')
          expect(File.exist?(master_cert_file)).to be true
          master_cert = OpenSSL::X509::Certificate.new(File.read(master_cert_file))
          alt_names = master_cert.extensions.find do |ext|
            ext.to_s =~ /subjectAltName/
          end
          expect(alt_names.to_s).to eq("subjectAltName = DNS:puppet, DNS:foo")
        end
      end
    end

    it 'adds custom subject alt names to the master cert' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |conf|
          exit_code = subject.run({ 'config' => conf,
                                    'subject-alt-names' => 'bar.net,IP:123.123.0.1',
                                    'ca-name' => '',
                                    'certname' => 'foo' })
          expect(exit_code).to eq(0)
          master_cert_file = File.join(tmpdir, 'ssl', 'certs', 'foo.pem')
          expect(File.exist?(master_cert_file)).to be true
          master_cert = OpenSSL::X509::Certificate.new(File.read(master_cert_file))
          alt_names = master_cert.extensions.find do |ext|
            ext.to_s =~ /subjectAltName/
          end
          expect(alt_names.to_s).to eq("subjectAltName = DNS:foo, DNS:bar.net, IP Address:123.123.0.1")
        end
      end
    end
  end

  it 'will not overwrite existing CA files' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = subject.run({ 'config' => conf,
                                  'subject-alt-names' => '',
                                  'ca-name' => '',
                                  'certname' => '' })
        expect(exit_code).to eq(0)
        exit_code2 = subject.run({ 'config' => conf,
                                   'subject-alt-names' => '',
                                   'ca-name' => '',
                                   'certname' => '' })
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
        File.open(private_path, 'w') {|f| f.puts pkey.to_pem}
        File.open(public_path, 'w') {|f| f.puts pkey.public_key.to_pem}

        exit_code = subject.run({ 'config' => conf,
                                  'ca-name' => '',
                                  'certname' => 'foocert',
                                  'subject-alt-names' => '' })

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

        exit_code = subject.run({ 'config' => conf,
                                  'ca-name' => '',
                                  'certname' => 'foocert',
                                  'subject-alt-names' => '' })

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

        exit_code = subject.run({ 'config' => conf,
                                  'ca-name' => '',
                                  'certname' => 'foocert',
                                  'subject-alt-names' => '' })

        expect(exit_code).to eq(1)
        expect(stderr.string).to match(/Missing private key/)
      end
    end
  end
end
