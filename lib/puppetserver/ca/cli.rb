require 'optparse'
require 'puppetserver/ca/version'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/action/clean'
require 'puppetserver/ca/action/create'
require 'puppetserver/ca/action/import'
require 'puppetserver/ca/action/generate'
require 'puppetserver/ca/action/revoke'
require 'puppetserver/ca/action/list'
require 'puppetserver/ca/sign_action'
require 'puppetserver/ca/utils'


module Puppetserver
  module Ca
    class Cli
      BANNER= <<-BANNER
Usage: puppetserver ca <action> [options]

Manage the Private Key Infrastructure for
Puppet Server's built-in Certificate Authority
BANNER

      VALID_ACTIONS = {
        'clean'    => Action::Clean,
        'create'   => Action::Create,
        'generate' => Action::Generate,
        'import'   => Action::Import,
        'list'     => Action::List,
        'revoke'   => Action::Revoke,
        'sign'     => SignAction
      }

      ACTION_LIST = "\nAvailable Actions:\n" +
        VALID_ACTIONS.map do |action, cls|
          "    #{action}\t#{cls::SUMMARY}"
        end.join("\n")

      ACTION_OPTIONS = "\nAction Options:\n" +
        VALID_ACTIONS.map do |action, cls|
          action_summary = cls.parser.summarize.
                             select{|line| line =~ /^\s*--/ }.
                             reject{|line| line =~ /--help|--version/ }
          summary = action_summary.empty? ? '      N/A' : action_summary.join('')

          "  #{action}:\n" + summary
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

        all,_,_,_ = Utils.parse_without_raising(general_parser, inputs)

        return general_parser, parsed, all
      end
    end
  end
end
