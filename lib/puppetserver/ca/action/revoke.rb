require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/config/combined'
require 'puppetserver/ca/certificate_authority'

require 'optparse'

module Puppetserver
  module Ca
    module Action
      class Revoke

        include Puppetserver::Ca::Utils

        CERTNAME_BLACKLIST = %w{--all --config}

        SUMMARY = 'Revoke a given certificate'
        BANNER = <<-BANNER
Usage:
  puppetserver ca revoke [--help]
  puppetserver ca revoke [--config] --certname CERTNAME[,ADDLCERTNAME]

Description:
Given one or more valid certnames, instructs the CA to revoke them over
HTTPS using the local agent's PKI

Options:
BANNER

        def self.parser(parsed = {})
          parsed['certnames'] = []
          OptionParser.new do |o|
            o.banner = BANNER
            o.on('--certname foo,bar', Array,
                 'One or more comma separated certnames') do |certs|
              parsed['certnames'] += certs
            end
            o.on('--config PUPPET.CONF', 'Custom path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
            o.on('--help', 'Displays this revoke specific help output') do |help|
              parsed['help'] = true
            end
          end
        end

        def initialize(logger)
          @logger = logger
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = CliParsing.parse_with_errors(parser, args)

          results['certnames'].each do |certname|
            if CERTNAME_BLACKLIST.include?(certname)
              errors << "    Cannot manage cert named `#{certname}` from " +
                        "the CLI, if needed use the HTTP API directly"
            end
          end

          if results['certnames'].empty?
            errors << '  At least one certname is required to revoke'
          end

          errors_were_handled = CliParsing.handle_errors(@logger, errors, parser.help)

          # if there is an exit_code then Cli will return it early, so we only
          # return an exit_code if there's an error
          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end

        def run(args)
          certnames = args['certnames']
          config_file = args['config']

          if config_file
            errors = FileSystem.validate_file_paths(config_file)
            return 1 if CliParsing.handle_errors(@logger, errors)
          end

          config = Config::Combined.new(config_file)
          return 1 if CliParsing.handle_errors(@logger, config.errors)

          passed = revoke_certs(certnames, config.settings)

          return passed ? 0 : 1
        end

        def revoke_certs(certnames, settings)
          ca = Puppetserver::Ca::CertificateAuthority.new(@logger, settings)
          ca.revoke_certs(certnames)
        end
      end
    end
  end
end
