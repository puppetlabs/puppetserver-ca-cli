require 'spec_helper'
require 'utils/ssl'

require 'tmpdir'
require 'fileutils'

require 'puppetserver/ca/import_action'
require 'puppetserver/ca/cli'

RSpec.describe Puppetserver::Ca::ImportAction do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:usage) do
    /.*Usage:.* puppetserver ca import.*Display this import specific help output.*/m
  end

  it 'prints the help output & returns 1 if invalid flags are given' do
    exit_code = Puppetserver::Ca::Cli.run(['import', '--hello'], stdout, stderr)
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to be 1
  end


  it 'prints the help output & returns 1 if no input is given' do
    exit_code = Puppetserver::Ca::Cli.run(['import'], stdout, stderr)
    expect(stderr.string).to match(usage)
    expect(exit_code).to be 1
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        exit_code = Puppetserver::Ca::Cli.run(['import',
                                                '--cert-bundle', bundle,
                                                '--private-key', key,
                                                '--crl-chain', chain,
                                                '--config', conf],
                                              stdout, stderr)
        expect(stderr.string).to be_empty
        expect(exit_code).to be 0
      end
    end
  end

  it 'accepts a --config flag' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        Puppetserver::Ca::Cli.run(['import',
                                    '--config', conf,
                                    '--cert-bundle', bundle,
                                    '--private-key', key,
                                    '--crl-chain', chain],
                                    stdout,
                                    stderr)
      end
    end
  end

  describe 'validation' do
    it 'requires the --cert-bundle, --private-key, and --crl-chain options' do
      out1, err1 = StringIO.new, StringIO.new
      exit_code = Puppetserver::Ca::Cli.run(
                    ['import', '--private-key', 'foo', '--crl-chain', 'bar'],
                    out1,
                    err1)
      expect(err1.string).to include('Missing required argument')
      expect(err1.string).to match(usage)
      expect(exit_code).to be 1

      out2, err2 = StringIO.new, StringIO.new
      exit_code = Puppetserver::Ca::Cli.run(
                    ['import', '--cert-bundle', 'foo', '--crl-chain', 'bar'],
                    out2,
                    err2)
      expect(err2.string).to include('Missing required argument')
      expect(err2.string).to match(usage)
      expect(exit_code).to be 1

      out3, err3 = StringIO.new, StringIO.new
      exit_code = Puppetserver::Ca::Cli.run(
                    ['import', '--private-key', 'foo', '--cert-bundle', 'bar'],
                    out3,
                    err3)
      expect(err3.string).to include('Missing required argument')
      expect(err3.string).to match(usage)
      expect(exit_code).to be 1
    end

    it 'requires cert-bundle, private-key, and crl-chain to be readable' do
      # All errors are surfaced from validations
      Dir.mktmpdir do |tmpdir|
        exit_code = Puppetserver::Ca::Cli.run(
                      ['import',
                       '--cert-bundle', File.join(tmpdir, 'cert_bundle.pem'),
                       '--private-key', File.join(tmpdir, 'private_key.pem'),
                       '--crl-chain', File.join(tmpdir, 'crl_chain.pem')],
                      stdout, stderr)
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
          exit_code = Puppetserver::Ca::Cli.run(
                        ['import',
                         '--cert-bundle', bundle,
                         '--private-key', key,
                         '--crl-chain', chain],
                        stdout,
                        stderr)

          expect(stderr.string).to match(/Could not parse .*bundle.pem/)
          expect(stderr.string).to include('garbage')
        end
      end
    end

    it 'validates that there are certs in the bundle' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(bundle, 'w') {|f| f.puts '' }
          exit_code = Puppetserver::Ca::Cli.run(
                        ['import',
                         '--cert-bundle', bundle,
                         '--private-key', key,
                         '--crl-chain', chain],
                        stdout,
                        stderr)

          expect(stderr.string).to match(/Could not detect .*bundle.pem/)
        end
      end
    end

    it 'validates the private key' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(key, 'w') {|f| f.puts '' }
          exit_code = Puppetserver::Ca::Cli.run(
                        ['import',
                         '--cert-bundle', bundle,
                         '--private-key', key,
                         '--crl-chain', chain],
                        stdout,
                        stderr)

          expect(stderr.string).to match(/Could not parse .*key.pem/)
        end
      end
    end

    it 'validates the private key and leaf cert match' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(key, 'w') {|f| f.puts OpenSSL::PKey::RSA.new(1024).to_pem }
          exit_code = Puppetserver::Ca::Cli.run(
                        ['import',
                         '--cert-bundle', bundle,
                         '--private-key', key,
                         '--crl-chain', chain],
                        stdout,
                        stderr)

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
          exit_code = Puppetserver::Ca::Cli.run(
                        ['import',
                         '--cert-bundle', bundle,
                         '--private-key', key,
                         '--crl-chain', chain],
                        stdout,
                        stderr)

          expect(stderr.string).to match(/Could not parse .*chain.pem/)
          expect(stderr.string).to include('garbage')
        end
      end
    end

    it 'validates that there are crls in the chain, if given chain' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          File.open(chain, 'w') {|f| f.puts '' }
          exit_code = Puppetserver::Ca::Cli.run(
                        ['import',
                         '--cert-bundle', bundle,
                         '--private-key', key,
                         '--crl-chain', chain],
                        stdout,
                        stderr)

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

          exit_code = Puppetserver::Ca::Cli.run(
                        ['import',
                         '--cert-bundle', bundle,
                         '--private-key', key,
                         '--crl-chain', chain],
                        stdout,
                        stderr)

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

        exit_code = Puppetserver::Ca::Cli.run(['import',
                                                '--private-key', key_file,
                                                '--cert-bundle', bundle_file,
                                                '--crl-chain', chain_file],
                                                stdout,
                                                stderr)

        expect(stderr.string).to include('Leaf certificate could not be validated')
      end
    end

    it 'validates config from cli is readable' do
      Dir.mktmpdir do |tmpdir|
        with_files_in tmpdir do |bundle, key, chain, conf|
          FileUtils.rm conf
          exit_code = Puppetserver::Ca::Cli.run(['import',
                                                  '--config', conf,
                                                  '--cert-bundle', bundle,
                                                  '--private-key', key,
                                                  '--crl-chain', chain],
                                                  stdout,
                                                  stderr)
          expect(stderr.string).to match(/Could not read file .*puppet.conf/)
        end
      end
    end
  end

  it 'actually, honest to god, moves files' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        File.open conf, 'w' do |f|
          f.puts(<<-INI)
            [master]
              cadir = #{tmpdir}/ca
          INI
        end
        exit_code = Puppetserver::Ca::Cli.run(['import',
                                                '--cert-bundle', bundle,
                                                '--private-key', key,
                                                '--crl-chain', chain,
                                                '--config', conf],
                                                stdout,
                                                stderr)

        expect(exit_code).to eq(0)
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crl.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_key.pem'))).to be true
        expect(File.exist?(File.join(tmpdir, 'ca', 'ca_crt.pem'))).to be true
      end
    end
  end
end
