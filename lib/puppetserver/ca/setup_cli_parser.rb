require 'optparse'

module Puppetserver
  module Ca
    class SetupCliParser
      def self.parse(cli_args, out, err)
        parser, inputs = parse_inputs(cli_args)
        exit_code = validate_inputs(inputs, parser.help, out, err)

        return inputs, exit_code
      end

      def self.validate_inputs(input, usage, out, err)
        exit_code = nil

        if input['help']
          out.puts usage
          exit_code = 0
        elsif input['version']
          out.puts Puppetserver::Ca::VERSION
          exit_code = 0
        elsif input['cert-bundle'].nil? || input['private-key'].nil?
          err.puts 'Error:'
          err.puts 'Missing required argument'
          err.puts '    Both --cert-bundle and --private-key are required'
          err.puts ''
          err.puts usage
          exit_code = 1
        end

        exit_code
      end

      def self.parse_inputs(inputs)
        parsed = {}

        parser = OptionParser.new do |opts|
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

        parser.parse(inputs)

        return parser, parsed
      end
    end
  end
end
