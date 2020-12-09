require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/utils/http_client'
require 'puppetserver/ca/utils/config'

module Puppetserver
  module Ca
    module Action
      class Migrate
        include Puppetserver::Ca::Utils
        PUPPETSERVER_CA_DIR = Puppetserver::Ca::Utils::Config.new_default_cadir

        SUMMARY = "Migrate the existing CA directory to #{PUPPETSERVER_CA_DIR}"
        BANNER = <<-BANNER
Usage:
  puppetserver ca migrate [--help]
  puppetserver ca migrate [--config PATH]

Description:
  Migrate an existing CA directory to #{PUPPETSERVER_CA_DIR}. This is for
  upgrading from Puppet Platform 6.x to Puppet 7. Use the currently configured
  puppet.conf file in your installation, or supply one using the `--config` flag.
Options:
BANNER

        def initialize(logger)
          @logger = logger
        end

        def run(input)
          config_path = input['config']
          puppet = Config::Puppet.new(config_path)
          puppet.load(logger: @logger, ca_dir_warn: false)
          return 1 if HttpClient.check_server_online(puppet.settings, @logger)

          errors = FileSystem.check_for_existing_files(PUPPETSERVER_CA_DIR)
          if !errors.empty?
            instructions = <<-ERR
Migration will not overwrite the directory at #{PUPPETSERVER_CA_DIR}. Have you already
run this migration tool? Is this a puppet 7 installation? It is likely that you have
already successfully run the migration or do not need to run it.
ERR
            errors << instructions
            Errors.handle_with_usage(@logger, errors)
            return 1
          end

          current_cadir = puppet.settings[:cadir]
          if FileSystem.check_for_existing_files(current_cadir).empty?
            error_message = <<-ERR
No CA dir found at #{current_cadir}. Please check the configured cadir setting in your
puppet.conf file and verify its contents.
ERR
            Errors.handle_with_usage(@logger, [error_message])
            return 1
          end

          migrate(current_cadir)

          @logger.inform <<-SUCCESS_MESSAGE
CA dir successfully migrated to #{PUPPETSERVER_CA_DIR}. Symlink placed at #{current_cadir}
for backwards compatibility. The puppetserver can be safely restarted now.
SUCCESS_MESSAGE
          return 0
        end

        def migrate(old_cadir, new_cadir=PUPPETSERVER_CA_DIR)
          FileUtils.mv(old_cadir, new_cadir)
          FileSystem.forcibly_symlink(new_cadir, old_cadir)
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)
          errors = CliParsing.parse_with_errors(parser, args)
          errors_were_handled = Errors.handle_with_usage(@logger, errors, parser.help)
          exit_code = errors_were_handled ? 1 : nil
          return results, exit_code
        end

        def self.parser(parsed = {})
          OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on('--help', 'Display this command-specific help output') do |help|
              parsed['help'] = true
            end
            opts.on('--config CONF', 'Path to puppet.conf') do |conf|
              parsed['config'] = conf
            end
          end
        end

      end
    end
  end
end
