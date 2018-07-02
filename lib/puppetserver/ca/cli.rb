require 'optparse'
require 'puppetserver/ca/version'
require 'puppetserver/ca/setup_command'

module Puppetserver
  module Ca
    class Cli
      VALID_COMMANDS = ['setup']

      def self.run!(cli_args = ARGV, out = STDOUT, err = STDERR)

        if VALID_COMMANDS.include?(cli_args.first)
          case cli_args.shift
          when 'setup'
            command = SetupCommand.new(out, err)
            input, exit_code = command.parse(cli_args)

            if exit_code
              return exit_code
            else
              return command.run!(input)
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
    end
  end
end
