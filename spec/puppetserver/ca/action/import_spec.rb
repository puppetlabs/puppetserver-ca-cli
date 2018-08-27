require 'spec_helper'
require 'utils/ssl'

require 'tmpdir'
require 'fileutils'

require 'puppetserver/ca/logger'
require 'puppetserver/ca/action/import'

RSpec.describe Puppetserver::Ca::Action::Import do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }
  let(:usage) do
    /.*Usage:.* puppetserver ca import.*Display this import specific help output.*/m
  end

  subject { Puppetserver::Ca::Action::Import.new(logger) }

  it 'prints the help output & returns 1 if invalid flags are given' do
    _, exit_code = subject.parse(['--hello'])
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to be 1
  end


  it 'prints the help output & returns 1 if no input is given' do
    _, exit_code = subject.parse([])
    expect(stderr.string).to match(usage)
    expect(exit_code).to be 1
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        _, maybe_code = subject.parse(['--cert-bundle', bundle,
                                       '--private-key', key,
                                       '--crl-chain', chain,
                                       '--config', conf])
        expect(stderr.string).to be_empty
        expect(maybe_code).to be nil
      end
    end
  end

  describe 'validation' do
    it 'requires the --cert-bundle' do
      _, exit_code = subject.parse(['--private-key', 'foo', '--crl-chain', 'bar'])
      expect(stderr.string).to include('Missing required argument')
      expect(stderr.string).to match(usage)
      expect(exit_code).to be 1
    end

    it 'requires the --private-key' do
      _, exit_code = subject.parse(['--cert-bundle', 'foo', '--crl-chain', 'bar'])
      expect(stderr.string).to include('Missing required argument')
      expect(stderr.string).to match(usage)
      expect(exit_code).to be 1
    end

    it 'requires the --crl-chain' do
      _, exit_code = subject.parse(['--cert-bundle', 'foo', '--private-key', 'bar'])
      expect(stderr.string).to include('Missing required argument')
      expect(stderr.string).to match(usage)
      expect(exit_code).to be 1
    end

    it 'requires cert-bundle, private-key, and crl-chain to be readable' do
      # All errors are surfaced from validations
      Dir.mktmpdir do |tmpdir|
        exit_code = subject.run({ 'cert-bundle' => File.join(tmpdir, 'cert_bundle.pem'),
                                  'private-key' => File.join(tmpdir, 'private_key.pem'),
                                  'crl-chain' => File.join(tmpdir, 'crl_chain.pem'),
                                  'certname' => '' })
        expect(stderr.string).to match(/Could not read .*cert_bundle.pem/)
        expect(stderr.string).to match(/Could not read .*private_key.pem/)
        expect(stderr.string).to match(/Could not read .*crl_chain.pem/)
        expect(exit_code).to be 1
      end
    end

    it 'validates all certs in bundle are parseable' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(bundle, 'a') do |f|
            f.puts '-----BEGIN CERTIFICATE-----'
            f.puts 'garbage'
            f.puts '-----END CERTIFICATE-----'
          end
          exit_code = subject.run({ 'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain,
                                    'certname' => '' })
          expect(stderr.string).to match(/Could not parse .*bundle.pem/)
          expect(stderr.string).to include('garbage')
        end
      end
    end

    it 'validates that there are certs in the bundle' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(bundle, 'w') {|f| f.puts '' }
          exit_code = subject.run({ 'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain,
                                    'certname' => '' })
          expect(stderr.string).to match(/Could not detect .*bundle.pem/)
        end
      end
    end

    it 'validates the private key' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(key, 'w') {|f| f.puts '' }
          exit_code = subject.run({ 'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain })
          expect(stderr.string).to match(/Could not parse .*key.pem/)
        end
      end
    end

    it 'validates the private key and leaf cert match' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(key, 'w') {|f| f.puts OpenSSL::PKey::RSA.new(1024).to_pem }
          exit_code = subject.run({ 'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain })
          expect(stderr.string).to include('Private key and certificate do not match')
        end
      end
    end

    it 'validates all crls in chain are parseable' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(chain, 'a') do |f|
            f.puts '-----BEGIN X509 CRL-----'
            f.puts 'garbage'
            f.puts '-----END X509 CRL-----'
          end
          exit_code = subject.run({ 'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain })
          expect(stderr.string).to match(/Could not parse .*chain.pem/)
          expect(stderr.string).to include('garbage')
        end
      end
    end

    it 'validates that there are crls in the chain, if given chain' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(chain, 'w') {|f| f.puts '' }
          exit_code = subject.run({ 'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain })
          expect(stderr.string).to match(/Could not detect .*chain.pem/)
        end
      end
    end

    it 'validates the leaf crl and leaf cert match' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          crls = File.read(chain).scan(/----BEGIN X509 CRL----.*?----END X509 CRL----/m)

          baz_key = OpenSSL::PKey::RSA.new(1024)
          baz_cert = create_cert(baz_key, 'baz')
          baz_crl = create_crl(baz_cert, baz_key)

          File.open(chain, 'w') do |f|
            f.puts baz_crl.to_pem
            f.puts crls[1..-1]
          end

          exit_code = subject.run({ 'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain })
          expect(stderr.string).to include('Leaf CRL was not issued by leaf certificate')
        end
      end
    end

    it 'validates that leaf cert is valid wrt the provided chain/bundle' do
      Dir.mktmpdir do |tmpdir|
        bundle_file = File.join(tmpdir, 'bundle.pem')
        key_file = File.join(tmpdir, 'key.pem')
        chain_file = File.join(tmpdir, 'chain.pem')

        root_key = OpenSSL::PKey::RSA.new(1024)
        leaf_key = OpenSSL::PKey::RSA.new(1024)

        File.open(key_file, 'w') do |f|
          f.puts leaf_key.to_pem
        end

        root_cert = create_cert(root_key, 'foo')
        leaf_cert = create_cert(leaf_key, 'bar', root_key, root_cert)

        File.open(bundle_file, 'w') do |f|
          f.puts leaf_cert.to_pem
          f.puts root_cert.to_pem
        end

        # This should ensure the leaf cert is revoked
        root_crl = create_crl(root_cert, root_key, [leaf_cert])
        leaf_crl = create_crl(leaf_cert, leaf_key)

        File.open(chain_file, 'w') do |f|
          f.puts leaf_crl.to_pem
          f.puts root_crl.to_pem
        end

        exit_code = subject.run({ 'cert-bundle' => bundle_file,
                                  'private-key'=> key_file,
                                  'crl-chain' => chain_file })
        expect(stderr.string).to include('Leaf certificate could not be validated')
      end
    end

    it 'validates config from cli is readable' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          FileUtils.rm conf
          exit_code = subject.run({ 'config' => conf,
                                    'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain })
          expect(stderr.string).to match(/Could not read file .*puppet.conf/)
        end
      end
    end
  end

  it 'moves CA files and creates master cert files in the correct location' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        exit_code = subject.run({ 'config' => conf,
                                  'cert-bundle' => bundle,
                                  'private-key'=> key,
                                  'crl-chain' => chain,
                                  'certname' => 'foocert',
                                  'subject-alt-names' => '' })
        expect(exit_code).to eq(0)
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crl.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_key.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crt.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ssl', 'certs', 'foocert.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ssl', 'private_keys', 'foocert.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ssl', 'public_keys', 'foocert.pem'))).to be true
      end
    end
  end

  it 'does not overwrite existing CA files' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        exit_code = subject.run({ 'config' => conf,
                                  'cert-bundle' => bundle,
                                  'private-key'=> key,
                                  'crl-chain' => chain,
                                  'certname' => '',
                                  'subject-alt-names' => ''})
        expect(exit_code).to eq(0)

        exit_code2 = subject.run({ 'config' => conf,
                                   'cert-bundle' => bundle,
                                   'private-key'=> key,
                                   'crl-chain' => chain,
                                   'certname' => '',
                                   'subject-alt-names' => '' })
        expect(exit_code2).to eq(1)
        expect(stderr.string).to match(/Existing file.*/)
        expect(stderr.string).to match(/.*please delete the existing files.*/)
      end
    end
  end

  describe 'subject alternative names' do
    it 'accepts unprefixed alt names' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          result, maybe_code = subject.parse(['--cert-bundle', bundle,
                                         '--private-key', key,
                                         '--crl-chain', chain,
                                         '--config', conf,
                                         '--subject-alt-names', 'foo.com'])
          expect(maybe_code).to eq(nil)
          expect(result['subject-alt-names']).to eq('foo.com')
        end
      end
    end

    it 'accepts DNS and IP alt names' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          result, maybe_code = subject.parse(['--cert-bundle', bundle,
                                         '--private-key', key,
                                         '--crl-chain', chain,
                                         '--config', conf,
                                         '--subject-alt-names', 'DNS:foo.com,IP:123.456.789'])
          expect(maybe_code).to eq(nil)
          expect(result['subject-alt-names']).to eq('DNS:foo.com,IP:123.456.789')
        end
      end
    end

    it 'adds default subject alt names to the master cert' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          exit_code = subject.run({ 'config' => conf,
                                    'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain,
                                    'certname' => 'foo',
                                    'subject-alt-names' => '' })
          expect(exit_code).to eq(0)
          master_cert_file = File.join(tmpdir, 'ssl', 'certs', 'foo.pem')
          expect(File.exist?(master_cert_file)).to be true
          master_cert = OpenSSL::X509::Certificate.new(File.read(master_cert_file))
          expect(master_cert.extensions[6].to_s).to eq("subjectAltName = DNS:puppet, DNS:foo")
        end
      end
    end

    it 'adds custom subject alt names to the master cert' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          exit_code = subject.run({ 'config' => conf,
                                    'cert-bundle' => bundle,
                                    'private-key'=> key,
                                    'crl-chain' => chain,
                                    'certname' => 'foo',
                                    'subject-alt-names' => 'bar.net,IP:123.123.0.1' })
          expect(exit_code).to eq(0)
          master_cert_file = File.join(tmpdir, 'ssl', 'certs', 'foo.pem')
          expect(File.exist?(master_cert_file)).to be true
          master_cert = OpenSSL::X509::Certificate.new(File.read(master_cert_file))
          expect(master_cert.extensions[6].to_s).to eq("subjectAltName = DNS:foo, DNS:bar.net, IP Address:123.123.0.1")
        end
      end
    end
  end
end
