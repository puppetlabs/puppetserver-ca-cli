require 'optparse'
require 'puppetserver/ca/version'
require 'puppetserver/ca/setup_command'
require 'puppetserver/ca/logger'

module Puppetserver
  module Ca
    class Cli
      VALID_COMMANDS = {'setup' => SetupCommand}

      def self.run!(cli_args = ARGV, out = STDOUT, err = STDERR)
        logger = Puppetserver::Ca::Logger.new(:info, out, err)
        parser, general_options, unparsed = parse_general_inputs(cli_args)

        if general_options['version']
          logger.inform Puppetserver::Ca::VERSION
          return 0
        end

        subcommand = VALID_COMMANDS[unparsed.first]

        if general_options['help']
          if subcommand
            logger.inform subcommand.parser.help
          else
            logger.inform parser.help
          end

          return 0
        end

        if subcommand
          command = subcommand.new(logger)
          input, exit_code = command.parse(unparsed)

          if exit_code
            return exit_code
          else
            return command.run!(input)
          end
        else
          logger.warn parser.help
          return 1
        end
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

        unparsed = []
        nonopts = []
        
        begin
          general_parser.order!(inputs) do |nonopt|
            nonopts << nonopt
          end
        rescue OptionParser::InvalidOption => e
          unparsed += e.args
          unparsed << inputs.shift unless inputs.first =~ /^-{1,2}/
          retry
        end

        return general_parser, parsed, nonopts + unparsed
      end
    end
  end
end
