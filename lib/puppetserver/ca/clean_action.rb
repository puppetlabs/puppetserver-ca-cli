require 'puppetserver/ca/utils'
require 'puppetserver/utils/http_client'
require 'puppetserver/utils/file_utilities'
require 'puppetserver/ca/puppet_config'
require 'puppetserver/ca/revoke_action'

require 'optparse'
require 'json'

module Puppetserver
  module Ca
    class CleanAction

      include Puppetserver::Utils

      CERTNAME_BLACKLIST = %w{--all --config}

      SUMMARY = 'Clean files from the CA for certificate(s)'
      BANNER = <<-BANNER
Usage:
  puppetserver ca clean [--help]
  puppetserver ca clean [--config] --certname CERTNAME[,ADDLCERTNAME]

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
          o.on('--certname foo,bar', Array,
               'One or more comma separated certnames') do |certs|
            parsed['certnames'] += certs
          end
          o.on('--config PUPPET.CONF', 'Custom path to puppet.conf') do |conf|
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

        errors = Utils.parse_with_errors(parser, args)

        results['certnames'].each do |certname|
          if CERTNAME_BLACKLIST.include?(certname)
            errors << "    Cannot manage cert named `#{certname}` from " +
                      "the CLI, if needed use the HTTP API directly"
          end
        end

        if results['certnames'].empty?
          errors << '  At least one certname is required to clean'
        end

        errors_were_handled = Utils.handle_errors(@logger, errors, parser.help)

        exit_code = errors_were_handled ? 1 : nil

        return results, exit_code
      end

      def run(args)
        certnames = args['certnames']
        config = args['config']

        if config
          errors = FileUtilities.validate_file_paths(config)
          return 1 if Utils.handle_errors(@logger, errors)
        end

        puppet = PuppetConfig.parse(config)
        return 1 if Utils.handle_errors(@logger, puppet.errors)

        passed = clean_certs(certnames, puppet.settings)

        return passed ? 0 : 1
      end

      def clean_certs(certnames, settings)
        client = HttpClient.new(settings)

        url = client.make_ca_url(settings[:ca_server],
                                 settings[:ca_port],
                                 'certificate_status')

        results = client.with_connection(url) do |connection|
          certnames.map do |certname|
            url.resource_name = certname
            revoke_result = connection.put(RevokeAction::REQUEST_BODY, url)
            revoked = check_revocation(revoke_result, certname)

            cleaned = nil
            unless revoked == :error
              clean_result = connection.delete(url)
              cleaned = check_result(clean_result, certname)
            end

            cleaned == :success && [:success, :not_found].include?(revoked)
          end
        end

        return results.all?
      end

      # possibly logs the action, always returns a status symbol 👑
      def check_revocation(result, certname)
        case result.code
        when '200', '204'
          @logger.inform "Revoked certificate for #{certname}"
          return :success
        when '404'
          return :not_found
        else
          @logger.err 'Error:'
          @logger.err "    Failed revoking certificate for #{certname}"
          @logger.err "    Received code: #{result.code}, body: #{result.body}"
          return :error
        end
      end

      # logs the action and returns a status symbol 👑
      def check_result(result, certname)
        case result.code
        when '200', '204'
          @logger.inform "Cleaned files related to #{certname}"
          return :success
        when '404'
          @logger.err 'Error:'
          @logger.err "    Could not find files for #{certname}"
          return :not_found
        else
          @logger.err 'Error:'
          @logger.err "    When cleaning #{certname} received:"
          @logger.err "      code: #{result.code}"
          @logger.err "      body: #{result.body.to_s}" if result.body
          return :error
        end
      end
    end
  end
end
