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
        end

        if VALID_COMMANDS.include?(cli_args.first)
          case cli_args.shift
          when 'setup'
            setup_parser.parse!(cli_args)
            if input['help']
              out.puts setup_parser.help
            else
              out.puts setup_parser.help
              return 1
            end
          end
        else
          general_parser.parse!(cli_args)

          if input['help']
            out.puts general_parser.help
          else
            out.puts general_parser.help
            return 1
          end
        end

        return 0
      end
    end
  end
end
