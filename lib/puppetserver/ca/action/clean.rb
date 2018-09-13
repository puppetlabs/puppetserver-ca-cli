require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/action/revoke'
require 'puppetserver/ca/certificate_authority'

require 'optparse'

module Puppetserver
  module Ca
    module Action
      class Clean

        include Puppetserver::Ca::Utils

        CERTNAME_BLACKLIST = %w{--all --config}

        SUMMARY = 'Revoke cert(s) and remove related files from CA'
        BANNER = <<-BANNER
Usage:
  puppetserver ca clean [--help]
  puppetserver ca clean [--config] --certname NAME[,NAME]

Description:
Given one or more valid certnames, instructs the CA to revoke certificates
matching the given certnames if they exist, and then remove files pertaining
to them (keys, cert, and certificate request) over HTTPS using the local
agent's PKI

Options:
BANNER

        def self.parser(parsed = {})
          parsed['certnames'] = []
          OptionParser.new do |o|
            o.banner = BANNER
            o.on('--certname NAME[,NAME]', Array,
                 'One or more comma separated certnames') do |certs|
              parsed['certnames'] += certs
            end
            o.on('--config CONF', 'Custom path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
            o.on('--help', 'Display this clean specific help output') do |help|
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
            errors << '  At least one certname is required to clean'
          end

          errors_were_handled = CliParsing.handle_errors(@logger, errors, parser.help)

          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end

        def run(args)
          certnames = args['certnames']
          config = args['config']

          if config
            errors = FileSystem.validate_file_paths(config)
            return 1 if CliParsing.handle_errors(@logger, errors)
          end

          puppet = Config::Puppet.parse(config)
          return 1 if CliParsing.handle_errors(@logger, puppet.errors)

          result = clean_certs(certnames, puppet.settings)
          case result
          when :success
            return 0
          when :invalid
            return 24
          when :not_found, :error
            return 1
          end
        end

        def clean_certs(certnames, settings)
          ca = Puppetserver::Ca::CertificateAuthority.new(@logger, settings)
          ca.clean_certs(certnames)
        end
      end
    end
  end
end
