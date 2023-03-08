require 'openssl'
require 'fileutils'
require 'puppetserver/ca/utils/config'

module Utils
  module SSL

    def create_cert(subject_key, name, signer_key = nil, signer_cert = nil, not_before = Time.now - 1, not_after = Time.now + 360000, serial = rand(2**128))
      cert = OpenSSL::X509::Certificate.new

      signer_cert ||= cert
      signer_key ||= subject_key

      cert.public_key = subject_key.public_key
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
      cert.issuer = signer_cert.subject
      cert.version = 2
      cert.serial = serial
      cert.not_before = not_before
      cert.not_after = not_after
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.issuer_certificate = signer_cert
      ef.subject_certificate = cert

      [
        ["basicConstraints", "CA:TRUE", true],
        ["keyUsage", "keyCertSign, cRLSign", true],
        ["subjectKeyIdentifier", "hash", false],
        ["authorityKeyIdentifier", "keyid:always", false]
      ].each do |ext|
        extension = ef.create_extension(*ext)
        cert.add_extension(extension)
      end

      cert.sign(signer_key, OpenSSL::Digest::SHA256.new)

      return cert
    end

    def create_crl(cert, key, certs_to_revoke = [])
      crl = OpenSSL::X509::CRL.new
      crl.version = 1
      crl.issuer = cert.subject
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.issuer_certificate = cert
      ef.subject_certificate = cert
      certs_to_revoke.each do |c|
        revoked = OpenSSL::X509::Revoked.new
        revoked.serial = c.serial
        revoked.time = Time.now
        revoked.add_extension(
          OpenSSL::X509::Extension.new(
            "CRLReason",
            OpenSSL::ASN1::Enumerated(
              OpenSSL::OCSP::REVOKED_STATUS_KEYCOMPROMISE)))

        crl.add_revoked(revoked)
      end
      crl.add_extension(
        ef.create_extension(["authorityKeyIdentifier", "keyid:always", false]))
      crl.add_extension(
        OpenSSL::X509::Extension.new("crlNumber",
                                     OpenSSL::ASN1::Integer(certs_to_revoke.length)))
      crl.last_update = Time.now - 1
      crl.next_update = Time.now + 360000
      crl.sign(key, OpenSSL::Digest::SHA256.new)

      return crl
    end

    # With cadir setting saying to save all the stuff to a tempdir :)
    def with_temp_dirs(tmpdir, &block)
      fixtures_dir = File.join(tmpdir, 'fixtures')
      ca_dir = File.join(tmpdir, 'ca')
      ssl_dir = File.join(tmpdir, 'ssl')

      FileUtils.mkdir_p fixtures_dir
      FileUtils.mkdir_p ca_dir
      FileUtils.mkdir_p ssl_dir

      config_file = File.join(fixtures_dir, 'puppet.conf')

      File.open(config_file, 'w') do |f|
        f.puts <<-CONF
        [master]
          cadir = #{ca_dir}
          ssldir = #{ssl_dir}
          keylength = 512
        CONF
      end
      block.call(config_file)
    end

    def with_files_in(tmpdir, &block)
      fixtures_dir = File.join(tmpdir, 'fixtures')
      ca_dir = File.join(tmpdir, 'ca')
      ssl_dir = File.join(tmpdir, 'ssl')

      FileUtils.mkdir_p fixtures_dir
      FileUtils.mkdir_p ca_dir
      FileUtils.mkdir_p ssl_dir

      bundle_file = File.join(fixtures_dir, 'bundle.pem')
      key_file = File.join(fixtures_dir, 'key.pem')
      chain_file = File.join(fixtures_dir, 'chain.pem')
      config_file = File.join(fixtures_dir, 'puppet.conf')

      File.open(config_file, 'w') do |f|
        f.puts <<-CONF
        [master]
          cadir = #{ca_dir}
          ssldir = #{ssl_dir}
          keylength = 512
        CONF
      end

      not_before = Time.now - 1

      root_key = OpenSSL::PKey::RSA.new(512)
      root_cert = create_cert(root_key, 'foo')

      leaf_key = OpenSSL::PKey::RSA.new(512)
      File.open(key_file, 'w') do |f|
        f.puts leaf_key.to_pem
      end

      leaf_cert = create_cert(leaf_key, 'bar', root_key, root_cert)

      File.open(bundle_file, 'w') do |f|
        f.puts leaf_cert.to_pem
        f.puts root_cert.to_pem
      end

      root_crl = create_crl(root_cert, root_key)
      leaf_crl = create_crl(leaf_cert, leaf_key)

      File.open(chain_file, 'w') do |f|
        f.puts leaf_crl.to_pem
        f.puts root_crl.to_pem
      end


      block.call(bundle_file, key_file, chain_file, config_file)
    end

    def with_files_in_default_dirs(tmpdir, &block)
      fixtures_dir = File.join(tmpdir, 'fixtures')
      confdir = File.join(tmpdir, 'puppet')

      FileUtils.mkdir_p fixtures_dir
      FileUtils.mkdir_p Puppetserver::Ca::Utils::Config.default_ssldir(confdir)
      FileUtils.mkdir_p Puppetserver::Ca::Utils::Config.new_default_cadir(confdir)

      bundle_file = File.join(fixtures_dir, 'ca_crt.pem')
      key_file = File.join(fixtures_dir, 'ca_key.pem')
      chain_file = File.join(fixtures_dir, 'ca_crl.pem')
      config_file = File.join(fixtures_dir, 'puppet.conf')

      File.open(config_file, 'w') do |f|
        f.puts <<-CONF
        [master]
          confdir = #{confdir}
          keylength = 512
        CONF
      end

      not_before = Time.now - 1

      root_key = OpenSSL::PKey::RSA.new(512)
      root_cert = create_cert(root_key, 'foo')

      leaf_key = OpenSSL::PKey::RSA.new(512)
      File.open(key_file, 'w') do |f|
        f.puts leaf_key.to_pem
      end

      leaf_cert = create_cert(leaf_key, 'bar', root_key, root_cert)

      File.open(bundle_file, 'w') do |f|
        f.puts leaf_cert.to_pem
        f.puts root_cert.to_pem
      end

      root_crl = create_crl(root_cert, root_key)
      leaf_crl = create_crl(leaf_cert, leaf_key)

      File.open(chain_file, 'w') do |f|
        f.puts leaf_crl.to_pem
        f.puts root_crl.to_pem
      end


      block.call(bundle_file, key_file, chain_file, config_file)
    end

    def with_ca_in(tmpdir, &block)
      ca_dir = File.join(tmpdir, 'ca')
      ssl_dir = File.join(tmpdir, 'ssl')

      FileUtils.mkdir_p ca_dir
      FileUtils.mkdir_p ssl_dir
      FileUtils.mkdir_p "#{ca_dir}/signed"

      bundle_file = File.join(ca_dir, 'ca_crt.pem')
      key_file = File.join(ca_dir, 'ca_key.pem')
      chain_file = File.join(ca_dir, 'ca_crl.pem')
      config_file = File.join(ca_dir, 'puppet.conf')

      File.open(config_file, 'w') do |f|
        f.puts <<-CONF
        [master]
          cadir = #{ca_dir}
          cacert = #{bundle_file}
          cakey = #{key_file}
          cacrl = #{chain_file}
          ssldir = #{ssl_dir}
          keylength = 512
        CONF
      end

      not_before = Time.now - 1

      root_key = OpenSSL::PKey::RSA.new(512)
      root_cert = create_cert(root_key, 'foo')

      leaf_key = OpenSSL::PKey::RSA.new(512)
      File.open(key_file, 'w') do |f|
        f.puts leaf_key.to_pem
      end

      leaf_cert = create_cert(leaf_key, 'bar', root_key, root_cert)

      File.open(bundle_file, 'w') do |f|
        f.puts root_cert.to_pem
        f.puts leaf_cert.to_pem
      end

      root_crl = create_crl(root_cert, root_key)
      leaf_crl = create_crl(leaf_cert, leaf_key)

      File.open(chain_file, 'w') do |f|
        f.puts root_crl.to_pem
        f.puts leaf_crl.to_pem
      end


      block.call(config_file, ca_dir)
    end
  end
end
