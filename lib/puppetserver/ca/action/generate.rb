require 'optparse'
require 'openssl'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/host'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/config/puppet'
require 'facter'

module Puppetserver
  module Ca
    module Action
      class Generate
        include Puppetserver::Ca::Utils

        CA_EXTENSIONS = [
          ["basicConstraints", "CA:TRUE", true],
          ["keyUsage", "keyCertSign, cRLSign", true],
          ["subjectKeyIdentifier", "hash", false],
          ["nsComment", "Puppet Server Internal Certificate", false],
          ["authorityKeyIdentifier", "keyid:always", false]
        ].freeze

        SSL_SERVER_CERT = "1.3.6.1.5.5.7.3.1"
        SSL_CLIENT_CERT = "1.3.6.1.5.5.7.3.2"

        MASTER_EXTENSIONS = [
          ["basicConstraints", "CA:FALSE", true],
          ["nsComment", "Puppet Server Internal Certificate", false],
          ["authorityKeyIdentifier", "keyid:always", false],
          ["extendedKeyUsage", "#{SSL_SERVER_CERT}, #{SSL_CLIENT_CERT}", true],
          ["keyUsage", "keyEncipherment, digitalSignature", true],
          ["subjectKeyIdentifier", "hash", false]
        ].freeze

        # Make the certificate valid as of yesterday, because so many people's
        # clocks are out of sync.  This gives one more day of validity than people
        # might expect, but is better than making every person who has a messed up
        # clock fail, and better than having every cert we generate expire a day
        # before the user expected it to when they asked for "one year".
        CERT_VALID_FROM = (Time.now - (60*60*24)).freeze

        SUMMARY = "Generate a root and intermediate signing CA for Puppet Server"
        BANNER = <<-BANNER
Usage:
  puppetserver ca generate [--help]
  puppetserver ca generate [--config PATH]
  puppetserver ca generate [--subject-alt-names ALTNAME1[,ALTNAME2...]]

Description:
Generate a root and intermediate signing CA for Puppet Server
and store generated CA keys, certs, and crls on disk.

The `--subject-alt-names` flag can be used to add SANs to the
certificate generated for the Puppet master. Multiple names can be
listed as a comma separated string. These can be either DNS names or
IP addresses, differentiated by prefixes: `DNS:foo.bar.com,IP:123.456.789`.
Names with no prefix will be treated as DNS names.

To determine the target location, the default puppet.conf
is consulted for custom values. If using a custom puppet.conf
provide it with the --config flag

Options:
BANNER

        def initialize(logger)
          @logger = logger
        end

        def run(input)
          # Validate config_path provided
          config_path = input['config']
          if config_path
            errors = FileSystem.validate_file_paths(config_path)
            return 1 if CliParsing.handle_errors(@logger, errors)
          end

          # Load, resolve, and validate puppet config settings
          settings_overrides = {}
          settings_overrides[:certname] = input['certname'] unless input['certname'].empty?
          settings_overrides[:ca_name] = input['ca_name'] unless input['ca_name'].empty?
          settings_overrides[:subject_alt_names] = input['subject_alt_names'] unless input['subject_alt_names'].empty?
          puppet = Config::Puppet.parse(config_path: config_path, cli_overrides: settings_overrides)
          return 1 if CliParsing.handle_errors(@logger, puppet.errors)

          # Load most secure signing digest we can for cers/crl/csr signing.
          signer = SigningDigest.new
          return 1 if CliParsing.handle_errors(@logger, signer.errors)

          # Generate root and intermediate ca and put all the certificates, crls,
          # and keys where they should go.
          errors = generate_pki(puppet.settings, signer.digest)
          return 1 if CliParsing.handle_errors(@logger, errors)

          @logger.inform "Generation succeeded. Find your files in #{puppet.settings[:cadir]}"
          return 0
        end

        def generate_pki(settings, signing_digest)
          valid_until = Time.now + settings[:ca_ttl]
          host = Puppetserver::Ca::Host.new(signing_digest)
          subject_alt_names = munge_alt_names(settings[:subject_alt_names])

          root_key = host.create_private_key(settings[:keylength])
          root_cert = self_signed_ca(root_key, settings[:root_ca_name], valid_until, signing_digest)
          root_crl = create_crl_for(root_cert, root_key, valid_until, signing_digest)

          int_key = host.create_private_key(settings[:keylength])
          int_csr = host.create_csr(settings[:ca_name], int_key)
          int_cert = sign_intermediate(root_key, root_cert, int_csr, valid_until, signing_digest)
          int_crl = create_crl_for(int_cert, int_key, valid_until, signing_digest)

          master_key = host.create_private_key(settings[:keylength])
          master_csr = host.create_csr(settings[:certname], master_key)
          master_cert = sign_master_cert(int_key, int_cert, master_csr,
                                         valid_until, signing_digest,
                                         subject_alt_names)

          FileSystem.ensure_dir(settings[:cadir])
          FileSystem.ensure_dir(settings[:certdir])
          FileSystem.ensure_dir(settings[:privatekeydir])
          FileSystem.ensure_dir(settings[:publickeydir])

          public_files = [
            [settings[:cacert], [int_cert, root_cert]],
            [settings[:cacrl], [int_crl, root_crl]],
            [settings[:hostcert], master_cert],
            [settings[:localcacert], [int_cert, root_cert]],
            [settings[:localcacrl], [int_crl, root_crl]],
            [settings[:hostpubkey], master_key.public_key],
            [settings[:capub], int_key.public_key],
            [settings[:cert_inventory], inventory_entry(master_cert)],
            [settings[:serial], "0x0002"],
          ]

          private_files = [
            [settings[:hostprivkey], master_key],
            [settings[:rootkey], root_key],
            [settings[:cakey], int_key],
          ]

          errors = FileSystem.check_for_existing_files(public_files.map(&:first))
          errors += FileSystem.check_for_existing_files(private_files.map(&:first))

          if !errors.empty?
            instructions = <<-ERR
If you would really like to replace your CA, please delete the existing files first.
Note that any certificates that were issued by this CA will become invalid if you
replace it!
ERR
            errors << instructions
            return errors
          end

          public_files.each do |location, content|
            FileSystem.write_file(location, content, 0644)
          end

          private_files.each do |location, content|
            FileSystem.write_file(location, content, 0640)
          end

          return []
        end

        def self_signed_ca(key, name, valid_until, signing_digest)
          cert = OpenSSL::X509::Certificate.new

          cert.public_key = key.public_key
          cert.subject = OpenSSL::X509::Name.new([["CN", name]])
          cert.issuer = cert.subject
          cert.version = 2
          cert.serial = 1

          cert.not_before = CERT_VALID_FROM
          cert.not_after  = valid_until

          ef = extension_factory_for(cert, cert)
          CA_EXTENSIONS.each do |ext|
            extension = ef.create_extension(*ext)
            cert.add_extension(extension)
          end

          cert.sign(key, signing_digest)

          cert
        end

        def inventory_entry(cert)
          "0x%04x %s %s %s" % [cert.serial, format_time(cert.not_before),
                               format_time(cert.not_after), cert.subject]
        end

        def format_time(time)
          time.strftime('%Y-%m-%dT%H:%M:%S%Z')
        end

        def extension_factory_for(ca, cert = nil)
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.issuer_certificate  = ca
          ef.subject_certificate = cert if cert

          ef
        end

        def create_crl_for(ca_cert, ca_key, valid_until, signing_digest)
          crl = OpenSSL::X509::CRL.new
          crl.version = 1
          crl.issuer = ca_cert.subject

          ef = extension_factory_for(ca_cert)
          crl.add_extension(
            ef.create_extension(["authorityKeyIdentifier", "keyid:always", false]))
          crl.add_extension(
            OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(0)))

          crl.last_update = CERT_VALID_FROM
          crl.next_update = valid_until
          crl.sign(ca_key, signing_digest)

          crl
        end

        def sign_intermediate(ca_key, ca_cert, csr, valid_until, signing_digest)
          cert = OpenSSL::X509::Certificate.new

          cert.public_key = csr.public_key
          cert.subject = csr.subject
          cert.issuer = ca_cert.subject
          cert.version = 2
          cert.serial = 2

          cert.not_before = CERT_VALID_FROM
          cert.not_after = valid_until

          ef = extension_factory_for(ca_cert, cert)
          CA_EXTENSIONS.each do |ext|
            extension = ef.create_extension(*ext)
            cert.add_extension(extension)
          end

          cert.sign(ca_key, signing_digest)

          cert
        end

        def sign_master_cert(int_key, int_cert, csr, valid_until, signing_digest, subject_alt_names)
          cert = OpenSSL::X509::Certificate.new
          cert.public_key = csr.public_key
          cert.subject = csr.subject
          cert.issuer = int_cert.subject
          cert.version = 2
          cert.serial = 1
          cert.not_before = CERT_VALID_FROM
          cert.not_after = valid_until

          ef = extension_factory_for(int_cert, cert)
          MASTER_EXTENSIONS.each do |ext|
            extension = ef.create_extension(*ext)
            cert.add_extension(extension)
          end

          if !subject_alt_names.empty?
            alt_names_ext = ef.create_extension("subjectAltName", subject_alt_names, false)
            cert.add_extension(alt_names_ext)
          end

          cert.sign(int_key, signing_digest)
          cert
        end

        def munge_alt_names(names)
          raw_names = names.split(/\s*,\s*/).map(&:strip)
          munged_names = raw_names.map do |name|
            # Prepend the DNS tag if no tag was specified
            if !name.start_with?("IP:") && !name.start_with?("DNS:")
              "DNS:#{name}"
            else
              name
            end
          end.sort.uniq.join(", ")
        end

        def parse(cli_args)
          results = {}
          parser = self.class.parser(results)
          errors = CliParsing.parse_with_errors(parser, cli_args)
          errors_were_handled = CliParsing.handle_errors(@logger, errors, parser.help)
          exit_code = errors_were_handled ? 1 : nil
          return results, exit_code
        end

        def self.parser(parsed = {})
          parsed['subject_alt_names'] = ''
          parsed['ca_name'] = ''
          parsed['certname'] = ''
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this generate specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
            opts.on('--subject-alt-names NAME1[,NAME2]',
                    'Subject alternative names for the master cert') do |sans|
              parsed['subject_alt_names'] = sans
            end
            opts.on('--ca-name NAME',
                    'Common name to use for the CA signing cert') do |name|
              parsed['ca_name'] = name
            end
            opts.on('--certname NAME',
                    'Common name to use for the master cert') do |name|
              parsed['certname'] = name
            end
          end
        end
      end
    end
  end
end
