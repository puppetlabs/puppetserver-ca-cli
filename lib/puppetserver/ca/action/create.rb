require 'puppetserver/ca/utils'
require 'puppetserver/ca/host'
require 'puppetserver/ca/puppet_config'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/utils/http_client'
require 'puppetserver/utils/signing_digest'
require 'json'

module Puppetserver
  module Ca
    module Action
      class Create

        include Puppetserver::Utils

        # Only allow printing ascii characters, excluding /
        VALID_CERTNAME = /\A[ -.0-~]+\Z/
        CERTNAME_BLACKLIST = %w{--all --config}

        SUMMARY = "Create a new certificate signed by the CA"
        BANNER = <<-BANNER
Usage:
  puppetserver ca create [--help]
  puppetserver ca create [--config] --certname CERTNAME[,ADDLCERTNAME]

Description:
Creates a new certificate signed by the intermediate CA
and stores generated keys and certs on disk.

To determine the target location, the default puppet.conf
is consulted for custom values. If using a custom puppet.conf
provide it with the --config flag

Options:
BANNER
        def initialize(logger)
          @logger = logger
        end

        def self.parser(parsed = {})
          parsed['certnames'] = []
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--certname FOO,BAR', Array,
                 'One or more comma separated certnames') do |certs|
              parsed['certnames'] += certs
            end
            opts.on('--help', 'Display this create specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
          end
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = Utils.parse_with_errors(parser, args)

          if results['certnames'].empty?
            errors << '    At least one certname is required to create'
          else
            results['certnames'].each do |certname|
              if CERTNAME_BLACKLIST.include?(certname)
                errors << "    Cannot manage cert named `#{certname}` from " +
                          "the CLI, if needed use the HTTP API directly"
              end

              if certname.match(/\p{Upper}/)
                errors << "    Certificate names must be lower case"
              end

              unless certname =~ VALID_CERTNAME
                errors << "  Certname #{certname} must not contain unprintable or non-ASCII characters"
              end
            end
          end

          errors_were_handled = Utils.handle_errors(@logger, errors, parser.help)

          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end

        def run(input)
          certnames = input['certnames']
          config_path = input['config']

          # Validate config_path provided
          if config_path
            errors = FileUtilities.validate_file_paths(config_path)
            return 1 if Utils.handle_errors(@logger, errors)
          end

          # Load, resolve, and validate puppet config settings
          puppet = PuppetConfig.parse(config_path)
          return 1 if Utils.handle_errors(@logger, puppet.errors)

          # Load most secure signing digest we can for csr signing.
          signer = SigningDigest.new
          return 1 if Utils.handle_errors(@logger, signer.errors)

          # Make sure we have all the directories where we will be writing files
          FileUtilities.ensure_dir(puppet.settings[:certdir])
          FileUtilities.ensure_dir(puppet.settings[:privatekeydir])
          FileUtilities.ensure_dir(puppet.settings[:publickeydir])

          # Generate and save certs and associated keys
          all_passed = generate_certs(certnames, puppet.settings, signer.digest)
          return all_passed ? 0 : 1
        end

        # Create csrs and keys, then submit them to CA, request for the CA to sign
        # them, download the signed certificates from the CA, and finally save
        # the signed certs and associated keys. Returns true if all certs were
        # successfully created and saved.
        def generate_certs(certnames, settings, digest)
          passed = certnames.map do |certname|
            key, csr = generate_key_csr(certname, settings, digest)
            return false unless submit_certificate_request(certname, csr.to_s, settings)
            return false unless sign_cert(certname, settings)
            if download_cert(certname, settings)
              save_keys(key, certname, settings)
              true
            else
              false
            end
          end
          passed.all?
        end

        def generate_key_csr(certname, settings, digest)
          host = Puppetserver::Ca::Host.new(digest)
          private_key = host.create_private_key(settings[:keylength])
          csr = host.create_csr(certname, private_key)

          return private_key, csr
        end

        def http_client(settings)
          @client ||= HttpClient.new(settings)
        end

        # Make an HTTP request to submit certificate requests to CA
        # @param certname [String] the name of the certificate to fetch
        # @param csr [String] string version of a OpenSSL::X509::Request
        # @param settings [Hash] a hash of config settings
        # @return [Boolean] success of all csrs being submitted to CA
        def submit_certificate_request(certname, csr, settings)
          client = http_client(settings)
          url = client.make_ca_url(settings[:ca_server],
                         settings[:ca_port],
                         'certificate_request',
                         certname)

          client.with_connection(url) do |connection|
            result = connection.put(csr, url)
            check_submit_result(result, certname)
          end
        end

        def check_submit_result(result, certname)
          case result.code
          when '200', '204'
            @logger.inform "Successfully submitted certificate request for #{certname}"
            return true
          else
            @logger.err 'Error:'
            @logger.err "    When certificate request submitted for #{certname}:"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return false
          end
        end

        # Make an HTTP request to CA to sign the named certificates
        # @param certname [String] the name of the certificate to have signed
        # @param settings [Hash] a hash of config settings
        # @return [Boolean] the success of certificates being signed
        def sign_cert(certname, settings)
          client = http_client(settings)

          url = client.make_ca_url(settings[:ca_server],
                         settings[:ca_port],
                         'certificate_status',
                         certname)

          client.with_connection(url) do |connection|
            body = JSON.dump({desired_state: 'signed'})
            result = connection.put(body, url)
            check_sign_result(result, certname)
          end
        end

        def check_sign_result(result, certname)
          case result.code
          when '204'
            @logger.inform "Successfully signed certificate request for #{certname}"
            return true
          else
            @logger.err 'Error:'
            @logger.err "    When signing request submitted for #{certname}:"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return false
          end
        end

        # Make an HTTP request to fetch the named certificates from CA
        # @param certname [String] the name of the certificate to fetch
        # @param settings [Hash] a hash of config settings
        # @return [Boolean] the success of certificate being downloaded
        def download_cert(certname, settings)
          client = http_client(settings)
          url = client.make_ca_url(settings[:ca_server],
                         settings[:ca_port],
                         'certificate',
                         certname)
          client.with_connection(url) do |connection|
            result = connection.get(url)
            if downloaded = check_download_result(result, certname)
              save_file(result.body, certname, settings[:certdir], "Certificate")
              @logger.inform "Successfully downloaded and saved certificate #{certname} to #{settings[:certdir]}/#{certname}.pem"
            end
            downloaded
          end
        end

        def check_download_result(result, certname)
          case result.code
          when '200'
            return true
          when '404'
            @logger.err 'Error:'
            @logger.err "    Signed certificate #{certname} could not be found on the CA"
            return false
          else
            @logger.err 'Error:'
            @logger.err "    When download requested for certificate #{certname}:"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return false
          end
        end

        def save_keys(key, certname, settings)
          public_key = key.public_key
          save_file(key, certname, settings[:privatekeydir], "Private key")
          save_file(public_key, certname, settings[:publickeydir], "Public key")
          @logger.inform "Successfully saved private key for #{certname} to #{settings[:privatekeydir]}/#{certname}.pem"
          @logger.inform "Successfully saved public key for #{certname} to #{settings[:publickeydir]}/#{certname}.pem"
        end


        def save_file(content, certname, dir, type)
          location = File.join(dir, "#{certname}.pem")
          @logger.warn "#{type} #{certname}.pem already exists, overwriting" if File.exist?(location)
          FileUtilities.write_file(location, content, 0640)
        end
      end
    end
  end
end
