require 'optparse'
require 'puppetserver/ca/version'
require 'puppetserver/ca/setup_action'
require 'puppetserver/ca/logger'

module Puppetserver
  module Ca
    class Cli
      BANNER= <<-BANNER
Usage: puppetserver ca <action> [options]

Manage the Private Key Infrastructure for
Puppet Server's built-in Certificate Authority
BANNER

      VALID_ACTIONS = {'setup' => SetupAction}

      ACTION_LIST = "\nAvailable Actions:\n" +
        VALID_ACTIONS.map do |action, cls|
          "    #{action}\t#{cls::SUMMARY}"
        end.join("\n")

      ACTION_OPTIONS = "\nAction Options:\n" +
        VALID_ACTIONS.map do |action, cls|
          "  #{action}:\n" +
          cls.parser.summarize.
            select{|line| line =~ /^\s*--/ }.
            reject{|line| line =~ /--help|--version/ }.join('')
        end.join("\n")


      def self.run(cli_args = ARGV, out = STDOUT, err = STDERR)
        logger = Puppetserver::Ca::Logger.new(:info, out, err)
        parser, general_options, unparsed = parse_general_inputs(cli_args)

        if general_options['version']
          logger.inform Puppetserver::Ca::VERSION
          return 0
        end

        action_argument = unparsed.shift
        action_class = VALID_ACTIONS[action_argument]

        if general_options['help']
          if action_class
            logger.inform action_class.parser.help
          else
            logger.inform parser.help
          end

          return 0
        end

        if action_class
          action = action_class.new(logger)
          input, exit_code = action.parse(unparsed)

          if exit_code
            return exit_code
          else
            return action.run(input)
          end
        else
          logger.warn "Unknown action: #{action_argument}"
          logger.warn parser.help
          return 1
        end
      end

      def self.parse_general_inputs(inputs)
        parsed = {}
        general_parser = OptionParser.new do |opts|
          opts.banner = BANNER
          opts.separator ACTION_LIST
          opts.separator "\nGeneral Options:"

          opts.on('--help', 'Display this general help output') do |help|
            parsed['help'] = true
          end
          opts.on('--version', 'Display the version') do |v|
            parsed['version'] = true
          end

          opts.separator ACTION_OPTIONS
          opts.separator "\nSee `puppetserver ca <action> --help` for detailed info"

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
