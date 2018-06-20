require 'optparse'

module Puppetserver
  module CA
    class CLI
      VALID_COMMANDS = ['setup']

      def self.run!(cli_args = ARGV, out = STDOUT, err = STDERR)
        input = {}
        general_parser = OptionParser.new do |opts|
          opts.banner = 'usage: puppetserver ca <command> [options]'
          opts.on('--help', 'This general help output') do |help|
            input['help'] = true
          end
        end

        setup_parser = OptionParser.new do |opts|
          opts.banner = 'usage: puppetserver ca setup [options]'
          opts.on('--help', 'This setup specific help output') do |help|
            input['help'] = true
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
            setup_parser.parse!(cli_args)
            if input['help']
              out.puts setup_parser.help
            else
              if input['cert-bundle'] && input['private-key']
                unless input['crl-chain']
                  err.puts 'Warning:'
                  err.puts '  No CRL chain given'
                  err.puts '  Full CRL chain checking will not be possible'
                end
                # do stuff
              else
                err.puts "Warning: missing required argument"
                err.puts "  Both --cert-bundle and --private-key are required"
              end
              err.puts setup_parser.help
              return 1
            end
          end
        else
          general_parser.parse!(cli_args)

          if input['help']
            out.puts general_parser.help
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
