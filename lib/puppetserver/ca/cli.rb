require 'optparse'

require 'puppetserver/ca/action/clean'
require 'puppetserver/ca/action/delete'
require 'puppetserver/ca/action/generate'
require 'puppetserver/ca/action/import'
require 'puppetserver/ca/action/enable'
require 'puppetserver/ca/action/list'
require 'puppetserver/ca/action/revoke'
require 'puppetserver/ca/action/setup'
require 'puppetserver/ca/action/sign'
require 'puppetserver/ca/action/prune'
require 'puppetserver/ca/action/migrate'
require 'puppetserver/ca/errors'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/version'


module Puppetserver
  module Ca
    class Cli
      BANNER= <<-BANNER
Usage: puppetserver ca <action> [options]

Manage the Private Key Infrastructure for
Puppet Server's built-in Certificate Authority
BANNER

      ADMIN_ACTIONS = {
        'import'   => Action::Import,
        'setup'    => Action::Setup,
        'enable'   => Action::Enable,
        'migrate'  => Action::Migrate,
        'prune'    => Action::Prune
      }

      MAINT_ACTIONS = {
        'clean'    => Action::Clean,
        'delete'   => Action::Delete,
        'generate' => Action::Generate,
        'list'     => Action::List,
        'revoke'   => Action::Revoke,
        'sign'     => Action::Sign
      }

      VALID_ACTIONS = ADMIN_ACTIONS.merge(MAINT_ACTIONS).sort.to_h

      ACTION_LIST = "\nAvailable Actions:\n\n" +
        "  Certificate Actions (requires a running Puppet Server):\n\n" +
        MAINT_ACTIONS.map do |action, cls|
          "    #{action}\t#{cls::SUMMARY}"
        end.join("\n") + "\n\n" +
        "  Administrative Actions (requires Puppet Server to be stopped):\n\n" +
        ADMIN_ACTIONS.map do |action, cls|
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
        parser, general_options, unparsed = parse_general_inputs(cli_args)
        level = general_options.delete('verbose') ? :debug : :info

        logger = Puppetserver::Ca::Logger.new(level, out, err)

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
            begin
              return action.run(input)
            rescue Puppetserver::Ca::Error => e
              logger.err "Fatal error when running action '#{action_argument}'"
              logger.err "  Error: " + e.message

              return 1
            end
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
          opts.on('--verbose', 'Display low-level information') do |verbose|
            parsed['verbose'] = true
          end

          opts.separator ACTION_OPTIONS
          opts.separator "\nSee `puppetserver ca <action> --help` for detailed info"

        end

        all,_,_,_ = Utils::CliParsing.parse_without_raising(general_parser, inputs)

        return general_parser, parsed, all
      end
    end
  end
end
