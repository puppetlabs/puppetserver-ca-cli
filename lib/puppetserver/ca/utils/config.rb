require 'puppetserver/ca/utils/file_system'

module Puppetserver
  module Ca
    module Utils
      module Config

        def self.running_as_root?
          !Gem.win_platform? && Process::UID.eid == 0
        end

        def self.munge_alt_names(names)
          raw_names = names.split(/\s*,\s*/).map(&:strip)
          munged_names = raw_names.map do |name|
            # Prepend the DNS tag if no tag was specified
            if !name.start_with?("IP:") && !name.start_with?("DNS:")
              "DNS:#{name}"
            else
              name
            end
          end.sort.uniq.join(", ")
        end

        def self.puppet_confdir
          if running_as_root?
            '/etc/puppetlabs/puppet'
          else
            "#{ENV['HOME']}/.puppetlabs/etc/puppet"
          end
        end

        def self.puppetserver_confdir(puppet_confdir)
          File.join(File.dirname(puppet_confdir), 'puppetserver')
        end

        def self.default_ssldir(confdir = puppet_confdir)
          File.join(confdir, 'ssl')
        end

        def self.old_default_cadir(confdir = puppet_confdir)
          File.join(confdir, 'ssl', 'ca')
        end

        def self.new_default_cadir(confdir = puppet_confdir)
          File.join(puppetserver_confdir(confdir), 'ca')
        end

        def self.symlink_to_old_cadir(current_cadir, puppet_confdir)
          old_cadir = old_default_cadir(puppet_confdir)
          new_cadir = new_default_cadir(puppet_confdir)
          return if current_cadir != new_cadir
          # This is only run on setup/import, so there should be no files in the
          # old cadir, so it should be safe to forcibly remove it (which we need
          # to do in order to create a symlink).
          Puppetserver::Ca::Utils::FileSystem.forcibly_symlink(new_cadir, old_cadir)
        end

      end
    end
  end
end
