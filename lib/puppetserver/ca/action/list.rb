require 'json'
require 'optparse'

require 'puppetserver/ca/errors'
require 'puppetserver/ca/certificate_authority'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'

module Puppetserver
  module Ca
    module Action
      class List

        include Puppetserver::Ca::Utils

        SUMMARY = 'List certificates and CSRs'
        BANNER = <<-BANNER
Usage:
  puppetserver ca list [--help]
  puppetserver ca list [--config]
  puppetserver ca list [--all]
  puppetserver ca list --certname NAME[,NAME]

Description:
  List outstanding certificate requests. If --all is specified, signed and
  revoked certificates will be listed as well.

Options:
      BANNER

        BODY = JSON.dump({desired_state: 'signed'})

        def initialize(logger)
          @logger = logger
        end

        def self.parser(parsed = {})
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--config CONF', 'Custom path to Puppet\'s config file') do |conf|
              parsed['config'] = conf
            end
            opts.on('--help', 'Display this command-specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--all', 'List all certificates') do |a|
              parsed['all'] = true
            end
            opts.on('--certname NAME[,NAME]', Array, 'List the specified cert(s)') do |cert|
              parsed['certname'] = cert
            end
          end
        end

        def run(input)
          config = input['config']
          certnames = input['certname'] || []
          all = input['all']

          if all && certnames.any?
            Errors.handle_with_usage(@logger, ['Cannot combine use of --all and --certname'])
            return 1
          end

          if config
            errors = FileSystem.validate_file_paths(config)
            return 1 if Errors.handle_with_usage(@logger, errors)
          end

          puppet = Config::Puppet.parse(config)
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          filter_names = certnames.any? \
            ? lambda { |x| certnames.include?(x['name']) }
            : lambda { |x| true }

          all_certs = get_all_certs(puppet.settings).select { |cert| filter_names.call(cert) }
          requested, signed, revoked = separate_certs(all_certs)
          missing = certnames - all_certs.map { |cert| cert['name'] }

          (all || certnames.any?) \
            ? output_certs_by_state(requested, signed, revoked, missing)
            : output_certs_by_state(requested)

          return missing.any? \
            ? 1
            : 0
        end

        def output_certs_by_state(requested, signed = [], revoked = [], missing = [])
          if revoked.empty? && signed.empty? && requested.empty? && missing.empty?
            @logger.inform "No certificates to list"
            return
          end

          unless requested.empty?
            @logger.inform "Requested Certificates:"
            output_certs(requested)
          end

          unless signed.empty?
            @logger.inform "Signed Certificates:"
            output_certs(signed)
          end

          unless revoked.empty?
            @logger.inform "Revoked Certificates:"
            output_certs(revoked)
          end

          unless missing.empty?
            @logger.inform "Missing Certificates:"
            missing.each do |name|
              @logger.inform "    #{name}"
            end
          end
        end

        def output_certs(certs)
          padded = 0
          certs.each do |cert|
            cert_size = cert["name"].size
            padded = cert_size if cert_size > padded
          end

          certs.each do |cert|
            # In newer versions of the CA api we return subjcet_alt_names
            # in addition to dns_alt_names, this field includes DNS alt
            # names but also IP alt names.
            alt_names = cert["subject_alt_names"] || cert["dns_alt_names"]
            @logger.inform "    #{cert["name"]}".ljust(padded + 6) + " (SHA256) " + " #{cert["fingerprints"]["SHA256"]}" +
                               (alt_names.empty? ? "" : "\talt names: #{alt_names}")
            end
        end

        def separate_certs(all_certs)
          certs = all_certs.group_by { |v| v["state"]}
          requested = certs.fetch("requested", [])
          signed = certs.fetch("signed", [])
          revoked = certs.fetch("revoked", [])
          return requested, signed, revoked
        end

        def get_all_certs(settings)
          result = Puppetserver::Ca::CertificateAuthority.new(@logger, settings).get_certificate_statuses
          result ? JSON.parse(result.body) : []
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = CliParsing.parse_with_errors(parser, args)

          errors_were_handled = Errors.handle_with_usage(@logger, errors, parser.help)

          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end
      end
    end
  end
end
