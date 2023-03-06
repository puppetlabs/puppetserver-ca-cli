require 'openssl'
require 'optparse'
require 'time'
require 'puppetserver/ca/certificate_authority'
require 'puppetserver/ca/config/puppet'
require 'puppetserver/ca/errors'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/utils/file_system'
require 'puppetserver/ca/utils/inventory'
require 'puppetserver/ca/x509_loader'

module Puppetserver
  module Ca
    module Action
      class Delete

        include Puppetserver::Ca::Utils

        CERTNAME_BLOCKLIST = %w{--config --expired --revoked --all}

        SUMMARY = 'Delete certificate(s)'
        BANNER = <<-BANNER
Usage:
  puppetserver ca delete [--help]
  puppetserver ca delete [--config CONF] [--expired] [--revoked]
                         [--certname NAME[,NAME]] [--all]

Description:
  Deletes signed certificates from disk. Once a certificate is
  signed and delivered to a node, it no longer necessarily needs
  to be stored on disk.

Options:
BANNER

        def initialize(logger)
          @logger = logger
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
            opts.on('--expired', 'Delete expired signed certificates') do |expired|
              parsed['expired'] = true
            end
            opts.on('--revoked', 'Delete signed certificates that have already been revoked') do |revoked|
              parsed['revoked'] = true
            end
            opts.on('--certname NAME[,NAME]', Array,
              'One or more comma-separated certnames for which to delete signed certificates') do |certs|
              parsed['certname'] = [certs].flatten
            end
            opts.on('--all', 'Delete all signed certificates on disk') do |all|
              parsed['all'] = true
            end
          end
        end

        def parse(args)
          results = {}
          parser = self.class.parser(results)

          errors = CliParsing.parse_with_errors(parser, args)

          if results['certname']
            results['certname'].each do |certname|
              if CERTNAME_BLOCKLIST.include?(certname)
                errors << "    Cannot manage cert named `#{certname}` from "+
                          "the CLI. If needed, use the HTTP API directly."
              end
            end
          end

          unless results['help'] || results['expired'] || results['revoked'] || results['certname'] || results['all']
            errors << '  Must pass one of the valid flags to determine which certs to delete'
          end

          errors_were_handled = Errors.handle_with_usage(@logger, errors, parser.help)

          exit_code = errors_were_handled ? 1 : nil
          return results, exit_code
        end

        def run(args)
          config = args['config']

          # Validate the config path
          if config
            errors = FileSystem.validate_file_paths(config)
            return 1 if Errors.handle_with_usage(@logger, errors)
          end

          # Validate puppet config setting
          puppet = Config::Puppet.parse(config, @logger)
          settings = puppet.settings
          return 1 if Errors.handle_with_usage(@logger, puppet.errors)

          # Validate that we are offline
          return 1 if HttpClient.check_server_online(settings, @logger)

          # Perform the desired action, keeping track if any errors occurred
          errored = false
          deleted_count = 0
          inventory_file_path = File.join(settings[:cadir], 'inventory.txt')

          if args['expired']
            # Delete expired certs found in inventory first since this is cheaper.
            # Then, look for any certs not in the inventory, check if they
            # are expired, then delete those.
            inventory, err = Inventory.parse_inventory_file(inventory_file_path, @logger)
            errored ||= err
            expired_in_inventory = inventory.select { |k,v| v[:not_after] < Time.now }.map(&:first)
            count, err = delete_certs(settings[:cadir], expired_in_inventory)
            deleted_count += count
            errored ||= err
            other_certs_to_check = find_certs_not_in_inventory(settings[:cadir], inventory.map(&:first))
            count, err = delete_expired_certs(settings[:cadir], other_certs_to_check)
            deleted_count += count
            errored ||= err
          end

          if args['certname']
            count, errored = delete_certs(settings[:cadir], args['certname'])
            deleted_count += count
          end

          plural = deleted_count == 1 ? "" : "s"
          @logger.inform("#{deleted_count} certificate#{plural} deleted.")
          # If encountered non-fatal errors (an invalid entry in inventory.txt, cert not existing on disk)
          # return 24. Returning 1 should be for fatal errors where we could not do any part of the action.
          return errored ? 24 : 0
        end

        def find_certs_not_in_inventory(cadir, inventory_certnames)
          all_cert_files = Dir.glob("#{cadir}/signed/*.pem").map { |f| File.basename(f, '.pem') }
          all_cert_files - inventory_certnames
        end

        def delete_certs(cadir, certnames)
          deleted = 0
          errored = false
          certnames.each do |cert|
            path = "#{cadir}/signed/#{cert}.pem"
            if File.exist?(path)
              @logger.inform("Deleting certificate at #{path}")
              File.delete(path)
              deleted += 1
            else
              @logger.err("Could not find certificate file at #{path}")
              errored = true
            end
          end
          [deleted, errored]
        end

        def delete_expired_certs(cadir, certnames)
          deleted = 0
          errored = false
          files = certnames.map { |c| "#{cadir}/signed/#{c}.pem" }
          files.each do |f|
            # Shouldn't really be possible since we look for certs on disk
            # before calling this function, but just in case.
            unless File.exist?(f)
              @logger.err("Could not find certificate file at #{f}")
              errored = true
              next
            end
            begin
              cert = OpenSSL::X509::Certificate.new(File.read(f))
            rescue OpenSSL::X509::CertificateError
              @logger.err("Error reading certificate at #{f}")
              errored = true
              next
            end
            if cert.not_after < Time.now
              @logger.inform("Deleting certificate at #{f}")
              File.delete(f)
              deleted += 1
            end
          end
          [deleted, errored]
        end
      end
    end
  end
end