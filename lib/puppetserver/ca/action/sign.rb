require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/certificate_authority'

require 'optparse'
require 'openssl'
require 'net/https'

module Puppetserver
  module Ca
    module Action
      class Sign

        include Puppetserver::Ca::Utils

        SUMMARY = 'Sign a given certificate'
        BANNER = <<-BANNER
Usage:
  puppetserver ca sign [--help]
  puppetserver ca sign [--config] --certname CERTNAME[,CERTNAME]
  puppetserver ca sign  --all

Description:
Given a comma-separated list of valid certnames, instructs the CA to sign each cert.

Options:
      BANNER

        def self.parser(parsed = {})
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--certname x,y,z', Array, 'the name(s) of the cert(s) to be signed') do |cert|
              parsed['certname'] = cert
            end
            opts.on('--config PUPPET.CONF', 'Custom path to Puppet\'s config file') do |conf|
              parsed['config'] = conf
            end
            opts.on('--help', 'Display this command specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--all', 'Operate on all certnames') do |a|
              parsed['all'] = true
            end
          end
        end

        def initialize(logger)
          @logger = logger
        end

        def run(input)
          config = input['config']

          if config
            errors = FileSystem.validate_file_paths(config)
            return 1 if CliParsing.handle_errors(@logger, errors)
          end

          puppet = Config::Puppet.parse(config_path: config)
          return 1 if CliParsing.handle_errors(@logger, puppet.errors)

          ca = Puppetserver::Ca::CertificateAuthority.new(@logger, puppet.settings)

          if input['all']
            requested_certnames = get_all_pending_certs(ca)
            if requested_certnames.nil?
              return 1
            end
          else
            requested_certnames = input['certname']
          end

          success = ca.sign_certs(requested_certnames)
          return success ? 0 : 1
        end

        def get_all_pending_certs(ca)
          if result = ca.get_certificate_statuses
            select_pending_certs(result.body)
          end
        end

        def select_pending_certs(get_result)
          requested_certnames = JSON.parse(get_result).select{|e| e["state"] == "requested"}.map{|e| e["name"]}

          if requested_certnames.empty?
            @logger.err 'Error:'
            @logger.err "    No waiting certificate requests to sign"
            return nil
          end

          return requested_certnames
        end

        def check_flag_usage(results)
          if results['certname'] && results['all']
            '--all and --certname cannot be used together'
          elsif !results['certname'] && !results['all']
            'No arguments given'
          elsif results['certname'] && results['certname'].include?('--all')
            'Cannot use --all with --certname. If you actually have a certificate request ' +
                            'for a certifcate named --all, you need to use the HTTP API.'
          end
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = CliParsing.parse_with_errors(parser, args)

          if err = check_flag_usage(results)
            errors << err
          end

          errors_were_handled = CliParsing.handle_errors(@logger, errors, parser.help)

          exit_code = errors_were_handled ? 1 : nil

          return results, exit_code
        end
      end
    end
  end
end
