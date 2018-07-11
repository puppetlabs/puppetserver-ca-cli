require 'optparse'
require 'puppetserver/ca/version'
require 'puppetserver/ca/setup_command'
require 'puppetserver/ca/logger'

module Puppetserver
  module Ca
    class Cli
      BANNER= <<-BANNER
Usage: puppetserver ca <command> [options]

Manage the Private Key Infrastructure for
Puppet Server's built-in Certificate Authority
BANNER

      VALID_COMMANDS = {'setup' => SetupCommand}

      COMMAND_LIST = "\nAvailable Sub-Commands:\n" +
        VALID_COMMANDS.map do |command, cls|
          "    #{command}\t#{cls::SUMMARY}"
        end.join("\n")

      COMMAND_OPTIONS = "\nSub-Command Options:\n" +
        VALID_COMMANDS.map do |command, cls|
          "  #{command}:\n" +
          cls.parser.summarize.
            select{|line| line =~ /^\s*--/ }.
            reject{|line| line =~ /--help|--version/ }.join('')
        end.join("\n")


      def self.run!(cli_args = ARGV, out = STDOUT, err = STDERR)
        logger = Puppetserver::Ca::Logger.new(:info, out, err)
        parser, general_options, unparsed = parse_general_inputs(cli_args)

        if general_options['version']
          logger.inform Puppetserver::Ca::VERSION
          return 0
        end

        subcommand = VALID_COMMANDS[unparsed.shift]

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
          opts.banner = BANNER
          opts.separator COMMAND_LIST
          opts.separator "\nGeneral Options:"

          opts.on('--help', 'Display this general help output') do |help|
            parsed['help'] = true
          end
          opts.on('--version', 'Display the version') do |v|
            parsed['version'] = true
          end

          opts.separator COMMAND_OPTIONS
          opts.separator "\nSee `puppetserver ca <command> --help` for detailed info"

        end

        unparsed, nonopts = [], []

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
