require 'puppetserver/ca/utils'
require 'puppetserver/utils/http_client'
require 'puppetserver/utils/file_utilities'
require 'puppetserver/ca/puppet_config'

require 'optparse'
require 'json'

module Puppetserver
  module Ca
    class RevokeAction

      include Puppetserver::Utils

      REQUEST_BODY = JSON.dump({ desired_state: 'revoked' })
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

        errors = Utils.parse_with_errors(parser, args)

        results['certnames'].each do |certname|
          if CERTNAME_BLACKLIST.include?(certname)
            errors << "    Cannot manage cert named `#{certname}` from " +
                      "the CLI, if needed use the HTTP API directly"
          end
        end

        if results['certnames'].empty?
          errors << '  At least one certname is required to revoke'
        end

        errors_were_handled = Utils.handle_errors(@logger, errors, parser.help)

        # if there is an exit_code then Cli will return it early, so we only
        # return an exit_code if there's an error
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

        passed = revoke_certs(certnames, puppet.settings)

        return passed ? 0 : 1
      end

      def revoke_certs(certnames, settings)
        client = HttpClient.new(settings)

        url = client.make_ca_url(settings[:ca_server],
                                 settings[:ca_port],
                                 'certificate_status')

        # results will be a list of trues & falses based on the success
        # of revocations
        results = client.with_connection(url) do |connection|
          certnames.map do |certname|
            url.resource_name = certname
            result = connection.put(REQUEST_BODY, url)

            check_result(result, certname)
          end
        end

        return results.all?
      end

      # logs the action and returns a boolean for success/failure
      def check_result(result, certname)
        case result.code
        when '200', '204'
          @logger.inform "Revoked certificate for #{certname}"
          return true
        when '404'
          @logger.err 'Error:'
          @logger.err "    Could not find certificate for #{certname}"
          return false
        else
          @logger.err 'Error:'
          @logger.err "    When revoking #{certname} received:"
          @logger.err "      code: #{result.code}"
          @logger.err "      body: #{result.body.to_s}" if result.body
          return false
        end
      end
    end
  end
end
