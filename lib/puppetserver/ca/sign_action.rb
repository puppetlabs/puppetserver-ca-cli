require 'puppetserver/ca/utils'
require 'puppetserver/utils/http_client'
require 'puppetserver/utils/file_utilities'
require 'puppetserver/ca/puppet_config'
require 'optparse'
require 'openssl'
require 'net/https'
require 'json'

module Puppetserver
  module Ca
    class SignAction

      include Puppetserver::Utils

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
      BODY = JSON.dump({desired_state: 'signed'})

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
          errors = FileUtilities.validate_file_paths(config)
          return 1 if Utils.handle_errors(@logger, errors)
        end

        puppet = PuppetConfig.parse(config)
        return 1 if Utils.handle_errors(@logger, puppet.errors)

        if input['all']
          requested_certnames = get_all_pending_certs(puppet.settings)
          if requested_certnames.nil?
            return 1
          end
        else
          requested_certnames = input['certname']
        end

        success = sign_requested_certs(requested_certnames, puppet.settings)
        return success ? 0 : 1
      end

      def http_client(settings)
        @client ||= HttpClient.new(settings)
      end

      def get_certificate_statuses(settings)
        client = http_client(settings)
        url = client.make_ca_url(settings[:ca_server],
                                 settings[:ca_port],
                                 'certificate_statuses',
                                 'any_key')
        client.with_connection(url) do |connection|
          connection.get(url)
        end
      end

      def sign_certs(certnames,settings)
        results = {}
        client = http_client(settings)
        url = client.make_ca_url(settings[:ca_server],
                                 settings[:ca_port],
                                 'certificate_status')
        client.with_connection(url) do |connection|
          certnames.each do |certname|
            url.resource_name = certname
            results[certname] = connection.put(BODY, url)
          end
        end
        return results
      end

      def get_all_certs(settings)
        result = get_certificate_statuses(settings)

        unless result.code == 200
            @logger.err 'Error:'
            @logger.err "    #{result.inspect}"
            return nil
        end
        return result
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

      def get_all_pending_certs(settings)
        result = get_all_certs(settings)
        if result
          select_pending_certs(result.body)
        end
      end

      def sign_requested_certs(certnames,settings)
        success = true
        results = sign_certs(certnames, settings)
        results.each do |certname, result|
          case result.code
          when '204'
            @logger.inform "Signed certificate for #{certname}"
          when '404'
            @logger.err 'Error:'
            @logger.err "    Could not find certificate for #{certname}"
            success = false
          else
            @logger.err 'Error:'
            @logger.err "    When download requested for #{result.inspect}"
            @logger.err "    code: #{result.code}"
            @logger.err "    body: #{result.body.to_s}" if result.body
            success = false
          end
        end
        return success
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

        errors = Utils.parse_with_errors(parser, args)

        if check_flag_usage(results)
          errors << check_flag_usage(results)
        end

        errors_were_handled = Utils.handle_errors(@logger, errors, parser.help)

        exit_code = errors_were_handled ? 1 : nil

        return results, exit_code
      end
    end
  end
end
