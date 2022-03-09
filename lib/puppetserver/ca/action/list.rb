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
        VALID_FORMAT = ['text', 'json']

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
            opts.on('--format FORMAT', "Valid formats are: 'text' (default), 'json'") do |f|
              parsed['format'] = f
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
          output_format = input['format'] || "text"
          missing = []

          unless VALID_FORMAT.include?(output_format)
            Errors.handle_with_usage(@logger, ["Unknown format flag '#{output_format}'. Valid formats are '#{VALID_FORMAT.join("', '")}'."])
            return 1
          end

          if all && certnames.any?
            Errors.handle_with_usage(@logger, ['Cannot combine use of --all and --certname.'])
            return 1
          end

          if config
            errors = FileSystem.validate_file_paths(config)
            return 1 if Errors.handle_with_usage(@logger, errors)
          end

          puppet = Config::Puppet.parse(config, @logger)
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          if certnames.any?
            filter_names = lambda { |x| certnames.include?(x['name']) }
          else
            filter_names = lambda { |x| true }
          end

          if (all || certnames.any?)
            found_certs = get_certs_or_csrs(puppet.settings)
            if found_certs.nil?
               # nil is different from no certs found
               @logger.inform('Error while getting certificates')
               return 1
            end
            all_certs = found_certs.select { |cert| filter_names.call(cert) }
            requested, signed, revoked = separate_certs(all_certs)
            missing = certnames - all_certs.map { |cert| cert['name'] }
            output_certs_by_state(all, output_format, requested, signed, revoked, missing)
          else
            all_csrs = get_certs_or_csrs(puppet.settings, "requested")
            if all_csrs.nil?
               # nil is different from no certs found
               @logger.inform('Error while getting certificates')
               return 1
            end
            output_certs_by_state(all, output_format, all_csrs)
          end

          return missing.any? ? 1 : 0
        end

        def output_certs_by_state(all, output_format, requested, signed = [], revoked = [], missing = [])
          if output_format == 'json'
            output_certs_json_format(all, requested, signed, revoked, missing)
          else
            output_certs_text_format(requested, signed, revoked, missing)
          end
        end

        def output_certs_json_format(all, requested, signed, revoked, missing)
          grouped_cert = {}

          if all
            grouped_cert = { "requested" => requested,
                             "signed" => signed,
                             "revoked" => revoked }.to_json
            @logger.inform(grouped_cert)
          else
            grouped_cert["requested"] = requested unless requested.empty?
            grouped_cert["signed"] = signed unless signed.empty?
            grouped_cert["revoked"] = revoked unless revoked.empty?
            grouped_cert["missing"] = missing unless missing.empty?

            # If neither the '--all' flag or the '--certname' flag was passed in
            # and the requested cert array is empty, we output a JSON object
            # with an empty 'requested' key. Otherwise, we display
            # any of the classes that are currently in grouped_cert
            if grouped_cert.empty?
              @logger.inform({ "requested" => requested }.to_json)
            else
              @logger.inform(grouped_cert.to_json)
            end
          end
        end

        def output_certs_text_format(requested, signed, revoked, missing)
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
          cert_column_width = certs.map { |c| c['name'].size }.max

          certs.each do |cert|
            @logger.inform(format_cert(cert, cert_column_width))
          end
        end

        def format_cert(cert, cert_column_width)
          [
            format_cert_and_sha(cert, cert_column_width),
            format_alt_names(cert),
            format_authorization_extensions(cert)
          ].compact.join("\t")
        end

        def format_cert_and_sha(cert, cert_column_width)
          justified_certname = cert['name'].ljust(cert_column_width + 6)
          sha = cert['fingerprints']['SHA256']
          "    #{justified_certname} (SHA256)  #{sha}"
        end

        def format_alt_names(cert)
          # In newer versions of the CA api we return subject_alt_names
          # in addition to dns_alt_names, this field includes DNS alt
          # names but also IP alt names.
          alt_names = cert['subject_alt_names'] || cert['dns_alt_names']
          "alt names: #{alt_names}" unless alt_names.empty?
        end

        def format_authorization_extensions(cert)
          auth_exts = cert['authorization_extensions']
          return nil if auth_exts.nil? || auth_exts.empty?

          values = auth_exts.map { |ext, value| "#{ext}: #{value}" }.join(', ')
          "authorization extensions: [#{values}]"
        end

        def separate_certs(all_certs)
          certs = all_certs.group_by { |v| v["state"]}
          requested = certs.fetch("requested", [])
          signed = certs.fetch("signed", [])
          revoked = certs.fetch("revoked", [])
          return requested, signed, revoked
        end

        def get_certs_or_csrs(settings, queried_state = nil)
          query = queried_state ? { :state => queried_state } : {}
          result = Puppetserver::Ca::CertificateAuthority.new(@logger, settings).get_certificate_statuses(query)

          if result.nil?
            # nil returned from an errored lookup
            return nil
          elsif result
            # values from a legit lookup
            return JSON.parse(result.body)
          else
            # empty result from a legit lookup
            return []
          end
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = CliParsing.parse_with_errors(parser, args)

          errors_were_handled = Errors.handle_with_usage(@logger, errors, parser.help)

          if errors_were_handled
            exit_code = 1
          else
            exit_code = nil
          end
          return results, exit_code
        end
      end
    end
  end
end
