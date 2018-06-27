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
    class PuppetParser
      def self.parse(string)
        results = {}
        current_section = :main
        string.each_line do |line|
          case line
          when /^\s*\[(\w+)\].*/
            current_section = $1.to_sym
          when /^\s*(\w+)\s*=\s*([^\s{#]+).*$/
            results[current_section] ||= {}
            results[current_section][$1.to_sym] = $2
          end
        end

        results
      end
    end

    class CAError < StandardError
      attr_reader :messages
      def initialize(*args)
        @messages = []
        super
      end

      def add_message(msg)
        @messages << msg
      end
    end

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

    class Cli
      VALID_COMMANDS = ['setup']

      def self.run!(cli_args = ARGV, out = STDOUT, err = STDERR)

        if VALID_COMMANDS.include?(cli_args.first)
          case cli_args.shift
          when 'setup'
            input, exit_code = SetupCliParser.parse(cli_args, out, err)

            return exit_code if exit_code

            begin
              if input['config']
                validate_file_paths(input['config'])
              end

              files = input.values_at('cert-bundle', 'private-key')
              files << input['crl-chain'] if input['crl-chain']

              validate_file_paths(files)

              certs = parse_certs(input['cert-bundle'])
              key = parse_key(input['private-key'])
              validate_cert_and_key(key, certs.first)

              crls = nil
              if input['crl-chain']
                crls = parse_crls(input['crl-chain'])
                validate_crl_and_cert(crls.first, certs.first)
              else
                err.puts 'Warning:'
                err.puts '    No CRL chain given'
                err.puts '    Full CRL chain checking will not be possible'
                err.puts ''
              end

              validate_full_chain(certs, crls)

              # do stuff
              return 0

            rescue CAError => e
              err.puts "Error:"
              err.puts "    #{e.to_s}" unless e.to_s.empty?
              e.messages.each do |message|
                err.puts "    #{message}"
              end
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

      def self.validate_file_paths(one_or_more_paths)
        error = CAError.new("")
        Array(one_or_more_paths).each do |path|
          if !File.exist?(path) || !File.readable?(path)
            error.add_message "Could not read file '#{path}'"
          end
        end

        raise error unless error.messages.empty?
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

      def self.parse_certs(bundle)
        error = CAError.new("Could not parse #{bundle}")

        bundle_string = File.read(bundle)
        cert_strings = bundle_string.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
        certs = cert_strings.map do |cert_string|
          begin
            OpenSSL::X509::Certificate.new(cert_string)
          rescue OpenSSL::X509::CertificateError
            error.add_message "Could not parse entry:\n#{cert_string}"
          end
        end

        if certs.empty?
          error.add_message "Could not detect any certs within #{bundle}"
        end

        raise error unless error.messages.empty?

        return certs
      end

      def self.parse_key(key_path)
        begin
          OpenSSL::PKey.read(File.read(key_path))
        rescue ArgumentError => e
          raise CAError.new("Could not parse #{key_path}")
        end
      end

      def self.validate_cert_and_key(key, cert)
        unless cert.check_private_key(key)
          raise CAError.new('Private key and certificate do not match')
        end
      end

      def self.parse_crls(chain)
        error = CAError.new("Could not parse #{chain}")

        chain_string = File.read(chain)
        crl_strings = chain_string.scan(/-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m)
        crls = crl_strings.map do |crl_string|
          begin
            OpenSSL::X509::CRL.new(crl_string)
          rescue OpenSSL::X509::CRLError
            error.add_message "Could not parse entry:\n#{crl_string}"
          end
        end

        if crls.empty?
          error.add_message "Could not detect any crls within #{chain}"
        end

        raise error unless error.messages.empty?

        return crls
      end

      def self.validate_crl_and_cert(crl, cert)
        unless crl.issuer == cert.subject
          raise CAError.new('Leaf CRL was not issued by leaf certificate')
        end
      end

      def self.validate_full_chain(certs, crls)
        store = OpenSSL::X509::Store.new
        certs.each {|cert| store.add_cert(cert) }
        if crls
          store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
          crls.each {|crl| store.add_crl(crl) }
        end

        unless store.verify(certs.first)
          raise CAError.new('Leaf certificate could not be validated')
        end
      end
    end
  end
end
