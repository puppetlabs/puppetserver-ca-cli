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

        SUMMARY = 'Delete signed certificate(s) from disk'
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

          if results['all'] && (results['expired'] || results['revoked'] || results['certname'])
            errors << '  The --all flag must not be used with --expired, --revoked, or --certname'
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
          cadir = settings[:cadir]
          inventory_file_path = File.join(cadir, 'inventory.txt')

          # Because --revoke has a potentially fatal error it can throw,
          # process it first.
          if args['revoked']
            loader = X509Loader.new(settings[:cacert], settings[:cakey], settings[:cacrl])
            verified_crls = loader.crls.select { |crl| crl.verify(loader.key) }
            unless verified_crls.length == 1
              @logger.err("Could not identify Puppet's CRL. Aborting delete action.")
              return 1
            end
            crl = verified_crls.first

            # First, search the inventory for the revoked serial. 
            # If it matches the current serial for the cert, delete the cert.
            # If it is an old serial for the certname, verify the file on disk
            #   is not the serial that was revoked, and then ignore it. If the
            #   file on disk does match that serial, delete it.
            # If it isn't in the inventory, fall back to searching every cert on
            #   disk for the given serial.
            inventory, err = Inventory.parse_inventory_file(inventory_file_path, @logger)
            revoked_serials = crl.revoked.map { |r| r.serial.to_i }
            to_delete = []
            revoked_serials.each do |revoked_serial|
              current_serial = inventory.find { |k,v| v[:serial] == revoked_serial }
              old_serial = inventory.find { |k,v| v[:old_serials].include?(revoked_serial) }
              if current_serial
                @logger.debug("#{revoked_serial} is the current serial for #{current_serial.first}")
                to_delete << current_serial.first
              elsif old_serial
                @logger.debug("#{revoked_serial} appears to be an old serial for #{old_serial.first}. Verifying cert on disk is not the revoked serial.")
                begin
                  serial = get_cert_serial("#{cadir}/signed/#{old_serial.first}.pem")
                  # This should never happen unless someone has messed with
                  # the inventory.txt file or replaced the cert on disk with
                  # an old one.
                  to_delete << old_serial.first if serial == revoked_serial
                rescue Exception => e
                  @logger.err("Error reading serial from certificate for #{old_serial.first} with exception #{e}")
                  errored = true
                end
              else
                @logger.debug("Could not find #{revoked_serial} in inventory.txt. Searching certs on disk for this serial.")
                begin
                  certname = find_cert_with_serial(cadir, revoked_serial)
                  if certname
                    to_delete << certname
                  else
                    @logger.err("Could not find serial #{revoked_serial} in inventory.txt or in any certificate file currently on disk.")
                    errored = true
                  end
                rescue Exception => e
                  @logger.err("Error reading serial from certificates when trying to find certificate with serial #{revoked_serial} with exception #{e}")
                  errored = true
                end
              end
            end
            # Because the CRL will likely contain certs that no longer exist on disk,
            # don't show an error if we can't find the file.
            count, err = delete_certs(cadir, to_delete, false)
            errored ||= err
            deleted_count += count
          end

          if args['expired']
            # Delete expired certs found in inventory first since this is cheaper.
            # Then, look for any certs not in the inventory, check if they
            # are expired, then delete those.
            inventory, err = Inventory.parse_inventory_file(inventory_file_path, @logger)
            errored ||= err
            expired_in_inventory = inventory.select { |k,v| v[:not_after] < Time.now }.map(&:first)
            # Don't print errors if the cert is not found, since the inventory
            # file can contain old entries that have already been deleted.
            count, err = delete_certs(cadir, expired_in_inventory, false)
            deleted_count += count
            errored ||= err
            other_certs_to_check = find_certs_not_in_inventory(cadir, inventory.map(&:first))
            count, err = delete_expired_certs(cadir, other_certs_to_check)
            deleted_count += count
            errored ||= err
          end

          if args['certname']
            count, errored = delete_certs(cadir, args['certname'])
            deleted_count += count
          end

          if args['all']
            certnames = Dir.glob("#{cadir}/signed/*.pem").map{ |c| File.basename(c, '.pem') }
            # Since we don't run this with any other flags, we can set these variables directly
            deleted_count, errored = delete_certs(cadir, certnames)
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

        def delete_certs(cadir, certnames, error_on_not_found = true)
          deleted = 0
          errored = false
          certnames.each do |cert|
            path = "#{cadir}/signed/#{cert}.pem"
            if File.exist?(path)
              @logger.inform("Deleting certificate at #{path}")
              File.delete(path)
              deleted += 1
            else
              if error_on_not_found
                @logger.err("Could not find certificate file at #{path}")
                errored = true
              end
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

        def get_cert_serial(file)
          cert = OpenSSL::X509::Certificate.new(File.read(file))
          cert.serial.to_i
        end

        def find_cert_with_serial(cadir, serial)
          files = Dir.glob("#{cadir}/signed/*.pem")
          files.each do |f|
            begin
              s = get_cert_serial(f)
              return File.basename(f, '.pem') if s == serial # Remove .pem
            rescue Exception => e
              @logger.debug("Error reading certificate at #{f} with exception #{e}. Skipping this file.")
            end
          end
          return nil
        end
      end
    end
  end
end
