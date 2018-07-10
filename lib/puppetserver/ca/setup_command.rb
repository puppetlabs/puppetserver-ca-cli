require 'optparse'
require 'puppetserver/ca/x509_loader'
require 'puppetserver/ca/puppet_config'

module Puppetserver
  module Ca
    class SetupCommand

      def initialize(logger)
        @logger = logger
      end

      def run!(input)
        bundle_path = input['cert-bundle']
        key_path = input['private-key']
        chain_path = input['crl-chain']
        config_path = input['config']

        files = [bundle_path, key_path, chain_path, config_path].compact

        errors = validate_file_paths(files)
        return 1 if log_possible_errors(errors)

        unless chain_path
          @logger.err 'Warning:'
          @logger.err '    No CRL chain given'
          @logger.err '    Full CRL chain checking will not be possible'
          @logger.err ''
        end


        loader = X509Loader.new(bundle_path, key_path, chain_path)
        return 1 if log_possible_errors(loader.errors)

        puppet = PuppetConfig.parse(config_path)
        return 1 if log_possible_errors(puppet.errors)


        File.open(puppet.settings[:cacert], 'w') do |f|
          loader.certs.each do |cert|
            f.puts cert.to_pem
          end
        end

        File.open(puppet.settings[:cakey], 'w') do |f|
          f.puts loader.key.to_pem
        end

        File.open(puppet.settings[:cacrl], 'w') do |f|
          loader.crls.each do |crl|
            f.puts crl.to_pem
          end
        end

        return 0
      end

      def log_possible_errors(maybe_errors)
        errors = Array(maybe_errors).compact
        unless errors.empty?
          @logger.err "Error:"
          errors.each do |message|
            @logger.err "    #{message}"
          end
          return true
        end
      end

      def parse(cli_args)
        parser, inputs = parse_inputs(cli_args)
        exit_code = validate_inputs(inputs, parser.help)

        return inputs, exit_code
      end

      def validate_inputs(input, usage)
        exit_code = nil

        if input['cert-bundle'].nil? || input['private-key'].nil?
          @logger.err 'Error:'
          @logger.err 'Missing required argument'
          @logger.err '    Both --cert-bundle and --private-key are required'
          @logger.err ''
          @logger.err usage
          exit_code = 1
        end

        exit_code
      end

      def parse_inputs(inputs)
        parsed = {}

        parser = self.class.parser(parsed)

        parser.parse(inputs)

        return parser, parsed
      end

      def self.parser(parsed = {})
        OptionParser.new do |opts|
          opts.banner = 'Usage: puppetserver ca setup [options]'
          opts.on('--help', 'This setup specific help output') do |help|
            parsed['help'] = true
          end
          opts.on('--version', 'Output the version') do |v|
            parsed['version'] = true
          end
          opts.on('--config CONF', 'Path to puppet.conf') do |conf|
            parsed['config'] = conf
          end
          opts.on('--private-key KEY', 'Path to PEM encoded key') do |key|
            parsed['private-key'] = key
          end
          opts.on('--cert-bundle BUNDLE', 'Path to PEM encoded bundle') do |bundle|
            parsed['cert-bundle'] = bundle
          end
          opts.on('--crl-chain [CHAIN]', 'Path to PEM encoded chain') do |chain|
            parsed['crl-chain'] = chain
          end
        end
      end

      def validate_file_paths(one_or_more_paths)
        errors = []
        Array(one_or_more_paths).each do |path|
          if !File.exist?(path) || !File.readable?(path)
            errors << "Could not read file '#{path}'"
          end
        end

        errors
      end
    end
  end
end
