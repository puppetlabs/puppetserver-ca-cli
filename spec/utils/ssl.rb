require 'openssl'
require 'fileutils'

module Utils
  module SSL

    PRIVATE_KEY_LENGTH = 2048
    DEFAULT_SIGNING_DIGEST = OpenSSL::Digest::SHA256.new
    DEFAULT_REVOCATION_REASON = OpenSSL::OCSP::REVOKED_STATUS_KEYCOMPROMISE
    FIVE_YEARS = 5 * 365 * 24 * 60 * 60
    CA_EXTENSIONS = [
        ['basicConstraints', 'CA:TRUE', true],
        ['keyUsage', 'keyCertSign, cRLSign', true],
        ['subjectKeyIdentifier', 'hash', false],
        ['authorityKeyIdentifier', 'keyid:always', false]
    ]
    NODE_EXTENSIONS = [
        ['keyUsage', 'digitalSignature', true],
        ['subjectKeyIdentifier', 'hash', false]
    ]
    ROOT_CA_NAME = '/CN=root-ca-\u{2070E}'
    INT_CA_NAME = '/CN=unrevoked-int-ca\u06FF\u16A0\u{2070E}'
    LEAF_CA_NAME = '/CN=leaf-ca-\u06FF'
    EXPLANATORY_TEXT = <<-EOT
# Root Issuer: #{ROOT_CA_NAME}
# Intermediate Issuer: #{INT_CA_NAME}
# Leaf Issuer: #{LEAF_CA_NAME}
    EOT

    def create_cert(subject_key, name, signer_key = nil, signer_cert = nil)
      cert = OpenSSL::X509::Certificate.new

      signer_cert ||= cert
      signer_key ||= subject_key

      cert.public_key = subject_key.public_key
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
      cert.issuer = signer_cert.subject
      cert.version = 2
      cert.serial = rand(2**128)
      cert.not_before = Time.now - 1
      cert.not_after = Time.now + 360000
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
      crl = create_crl_for(cert, key)
      certs_to_revoke.each do |c|
        crl = revoke_cert(c.serial, crl, key, OpenSSL::OCSP::REVOKED_STATUS_KEYCOMPROMISE)
      end

      return crl
    end

    def create_crl_for(ca_cert, ca_key)
      crl = OpenSSL::X509::CRL.new
      crl.version = 1
      crl.issuer = ca_cert.subject

      ef = extension_factory_for(ca_cert)
      crl.add_extension(
          ef.create_extension(["authorityKeyIdentifier", "keyid:always", false]))
      crl.add_extension(
          OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(0)))

      not_before = just_now
      crl.last_update = not_before
      crl.next_update = not_before + FIVE_YEARS
      crl.sign(ca_key, DEFAULT_SIGNING_DIGEST)

      crl
    end

    def create_csr(key, name)
      csr = OpenSSL::X509::Request.new

      csr.public_key = key.public_key
      csr.subject = OpenSSL::X509::Name.parse(name)
      csr.version = 2
      csr.sign(key, DEFAULT_SIGNING_DIGEST)

      return csr
    end

    def create_private_key(length = PRIVATE_KEY_LENGTH)
      OpenSSL::PKey::RSA.new(length)
    end

    def self_signed_ca(key, name)
      cert = OpenSSL::X509::Certificate.new

      cert.public_key = key.public_key
      cert.subject = OpenSSL::X509::Name.parse(name)
      cert.issuer = cert.subject
      cert.version = 2
      cert.serial = rand(2 ** 128)

      not_before = just_now
      cert.not_before = not_before
      cert.not_after = not_before + FIVE_YEARS

      ext_factory = extension_factory_for(cert, cert)
      CA_EXTENSIONS.each do |ext|
        extension = ext_factory.create_extension(*ext)
        cert.add_extension(extension)
      end

      cert.sign(key, DEFAULT_SIGNING_DIGEST)

      cert
    end

    def sign_csr(ca_key, ca_cert, csr, extensions = NODE_EXTENSIONS)
      cert = OpenSSL::X509::Certificate.new

      cert.public_key = csr.public_key
      cert.subject = csr.subject
      cert.issuer = ca_cert.subject
      cert.version = 2
      cert.serial = rand(2 ** 128)

      not_before = just_now
      cert.not_before = not_before
      cert.not_after = not_before + FIVE_YEARS

      ext_factory = extension_factory_for(ca_cert, cert)
      extensions.each do |ext|
        extension = ext_factory.create_extension(*ext)
        cert.add_extension(extension)
      end

      cert.sign(ca_key, DEFAULT_SIGNING_DIGEST)

      cert
    end

    def revoke_cert(serial, crl, ca_key, revocation_reason = DEFAULT_REVOCATION_REASON)
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = serial
      revoked.time = Time.now
      revoked.add_extension(
          OpenSSL::X509::Extension.new("CRLReason",
                                       OpenSSL::ASN1::Enumerated(revocation_reason)))

      crl.add_revoked(revoked)
      extensions = crl.extensions.group_by {|e| e.oid == 'crlNumber'}
      crl_number = extensions[true].first
      unchanged_exts = extensions[false]

      next_crl_number = crl_number.value.to_i + 1
      new_crl_number_ext = OpenSSL::X509::Extension.new("crlNumber",
                                                        OpenSSL::ASN1::Integer(next_crl_number))

      crl.extensions = unchanged_exts + [new_crl_number_ext]
      crl.sign(ca_key, DEFAULT_SIGNING_DIGEST)

      crl
    end

    def get_csr_extension_reqs(csr)
      ext_req_attr = csr.attributes
                         .find {|attr| attr.oid = 'extReq'}

      raw_reqs = flatten_csr_reqs(ext_req_attr.value)

      return raw_reqs.map do |ext|
        [ext[:oid], ext[:value], ext[:required]]
      end
    end

    def flatten_csr_reqs(item)
      if item.is_a?(OpenSSL::ASN1::ASN1Data)
        return flatten_csr_reqs(item.value)
      elsif item.is_a?(Array)
        oid = item.find {|entry| entry.is_a?(OpenSSL::ASN1::ObjectId)}
        value = item.find {|entry| entry.is_a?(OpenSSL::ASN1::OctetString)}
        required = item.find {|entry| entry.is_a?(OpenSSL::ASN1::Boolean)}
        if oid.nil? || value.nil?
          return item.map {|i| flatten_csr_reqs(i)}.flatten
        else
          return {
              :oid => oid.value,
              :value => value.value,
              :required => required.nil? ? false : required.value,
          }
        end
      else
        return item
      end
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

    def with_ca_in(tmpdir, &block)
      ca_dir = File.join(tmpdir, 'ca')
      ssl_dir = File.join(tmpdir, 'ssl')

      FileUtils.mkdir_p ca_dir
      FileUtils.mkdir_p ssl_dir
      FileUtils.mkdir_p "#{ca_dir}/signed"

      bundle_file = File.join(ca_dir, 'bundle.pem')
      key_file = File.join(ca_dir, 'key.pem')
      chain_file = File.join(ca_dir, 'chain.pem')
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

    private

    def just_now
      Time.now - 1
    end

    def extension_factory_for(ca, cert = nil)
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.issuer_certificate = ca
      ef.subject_certificate = cert if cert

      ef
    end

    def bundle(*items)
      items.map {|i| EXPLANATORY_TEXT + i.to_pem}.join("\n")
    end
  end
end
