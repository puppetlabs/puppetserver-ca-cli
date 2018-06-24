require 'optparse'
require 'openssl'
require 'puppetserver/ca/version'

# Option parser declares several default options that,
# unless overridden will raise a SystemExit. We delete
# version and help here as that behavior was breaking
# test driving those flags.
OptionParser::Officious.delete('version')
OptionParser::Officious.delete('help')

module Puppetserver
  module Ca
    class Cli
      VALID_COMMANDS = ['setup']

      def self.run!(cli_args = ARGV, out = STDOUT, err = STDERR)

        if VALID_COMMANDS.include?(cli_args.first)
          case cli_args.shift
          when 'setup'
            setup_parser, input = parse_setup_inputs(cli_args)

            if input['help']
              out.puts setup_parser.help
            elsif input['version']
              out.puts Puppetserver::Ca::VERSION
              return 0
            else
              if input['cert-bundle'] && input['private-key']
                files = input.values_at('cert-bundle', 'private-key')
                files << input['crl-chain'] if input['crl-chain']

                errors = validate_file_paths(files)

                unless errors.empty?
                  err.puts 'Error:'
                  errors.each {|error| err.puts "    #{error}" }
                  err.puts ''
                  return 1
                end

                unless input['crl-chain']
                  err.puts 'Warning:'
                  err.puts '    No CRL chain given'
                  err.puts '    Full CRL chain checking will not be possible'
                  err.puts ''
                end

                certs = parse_certs(input['cert-bundle'])

                if certs.empty?
                  err.puts "Could not parse #{input['cert-bundle']}"
                  return 1
                end

                # do stuff
                return 0
              else
                err.puts 'Error: missing required argument'
                err.puts '    Both --cert-bundle and --private-key are required'
                err.puts ''
              end
              err.puts setup_parser.help
              return 1
            end
          end
        else
          general_parser, input = parse_general_inputs(cli_args)

          if input['help']
            out.puts general_parser.help
          elsif input['version']
            out.puts Puppetserver::Ca::VERSION
          else
            err.puts general_parser.help
            return 1
          end
        end

        return 0
      end

      def self.validate_file_paths(paths)
        paths.map do |path|
          if !File.exist?(path) || !File.readable?(path)
            "Could not read file '#{path}'"
          end
        end.compact
      end

      def self.parse_general_inputs(inputs)
        parsed = {}
        general_parser = OptionParser.new do |opts|
          opts.banner = 'Usage: puppetserver ca <command> [options]'
          opts.on('--help', 'This general help output') do |help|
            parsed['help'] = true
          end
          opts.on('--version', 'Output the version') do |v|
            parsed['version'] = true
          end
        end

        general_parser.parse(inputs)

        return general_parser, parsed
      end

      def self.parse_setup_inputs(inputs)
        parsed = {}

        setup_parser = OptionParser.new do |opts|
          opts.banner = 'Usage: puppetserver ca setup [options]'
          opts.on('--help', 'This setup specific help output') do |help|
            parsed['help'] = true
          end
          opts.on('--version', 'Output the version') do |v|
            parsed['version'] = true
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

        setup_parser.parse(inputs)

        return setup_parser, parsed
      end

      def self.parse_certs(bundle)
        bundle_string = File.read(bundle)
        cert_strings = bundle_string.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
        begin
          certs = cert_strings.map do |cert_string|
            OpenSSL::X509::Certificate.new(cert_string)
          end
        rescue OpenSSL::X509::CertificateError
          certs = []
        end

        return certs
      end
    end
  end
end
