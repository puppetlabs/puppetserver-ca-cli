require 'optparse'

require 'puppetserver/ca/certificate_authority'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'

module Puppetserver
  module Ca
    module Action
      class Revoke

        include Puppetserver::Ca::Utils

        CERTNAME_BLACKLIST = %w{--all --config}

        SUMMARY = 'Revoke certificate(s)'
        BANNER = <<-BANNER
Usage:
  puppetserver ca revoke [--help]
  puppetserver ca revoke [--config] --certname NAME[,NAME]

Description:
  Given one or more valid certnames, instructs the CA to revoke them over
  HTTPS using the local agent's PKI

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

          errors_were_handled = Errors.handle_with_usage(@logger, errors, parser.help)

          # if there is an exit_code then Cli will return it early, so we only
          # return an exit_code if there's an error
          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end

        def run(args)
          certnames = args['certnames']
          config = args['config']

          if config
            errors = FileSystem.validate_file_paths(config)
            return 1 if Errors.handle_with_usage(@logger, errors)
          end

          puppet = Config::Puppet.parse(config, @logger)
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          result =  revoke_certs(certnames, puppet.settings)

          case result
          when :success
            return 0
          when :invalid
            return 24
          when :not_found, :error
            return 1
          end
        end

        def revoke_certs(certnames, settings)
          ca = Puppetserver::Ca::CertificateAuthority.new(@logger, settings)
          ca.revoke_certs(certnames)
        end
      end
    end
  end
end
