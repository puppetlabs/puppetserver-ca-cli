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
        input = {}
        general_parser = OptionParser.new do |opts|
          opts.banner = 'Usage: puppetserver ca <command> [options]'
          opts.on('--help', 'This general help output') do |help|
            input['help'] = true
          end
          opts.on('--version', 'Output the version') do |v|
            input['version'] = true
          end
        end

        setup_parser = OptionParser.new do |opts|
          opts.banner = 'Usage: puppetserver ca setup [options]'
          opts.on('--help', 'This setup specific help output') do |help|
            input['help'] = true
          end
          opts.on('--version', 'Output the version') do |v|
            input['version'] = true
          end
          opts.on('--private-key KEY', 'Path to PEM encoded key') do |key|
            input['private-key'] = key
          end
          opts.on('--cert-bundle BUNDLE', 'Path to PEM encoded bundle') do |bundle|
            input['cert-bundle'] = bundle
          end
          opts.on('--crl-chain [CHAIN]', 'Path to PEM encoded chain') do |chain|
            input['crl-chain'] = chain
          end
        end

        if VALID_COMMANDS.include?(cli_args.first)
          case cli_args.shift
          when 'setup'
            setup_parser.parse(cli_args)

            if input['help']
              out.puts setup_parser.help
            elsif input['version']
              out.puts Puppetserver::Ca::VERSION
              return 0
            else
              if input['cert-bundle'] && input['private-key']
                errors = []
                bundle = input['cert-bundle']
                if !File.exist?(bundle) || !File.readable?(bundle)
                  errors << "Could not read file '#{bundle}'"
                end

                key = input['private-key']
                if !File.exist?(key) || !File.readable?(bundle)
                  errors << "Could not read file '#{key}'"
                end

                chain = input['crl-chain']
                if chain && (!File.exist?(chain) || !File.readable?(chain))
                  errors << "Could not read file '#{chain}'"
                end

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

                bundle_string = File.read(bundle)
                cert_strings = bundle_string.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
                begin
                  certs = cert_strings.map do |cert_string|
                    OpenSSL::X509::Certificate.new(cert_string)
                  end
                rescue OpenSSL::X509::CertificateError
                end

                if certs.empty?
                  err.puts "Could not parse #{bundle}"
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
          general_parser.parse(cli_args)

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
    end
  end
end
