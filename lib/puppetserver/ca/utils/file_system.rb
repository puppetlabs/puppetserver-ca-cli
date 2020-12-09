require 'etc'
require 'fileutils'

module Puppetserver
  module Ca
    module Utils
      class FileSystem

        DIR_MODES = {
          :ssldir => 0771,
          :cadir => 0755,
          :certdir => 0755,
          :privatekeydir => 0750,
          :publickeydir => 0755,
          :signeddir => 0755
        }

        def self.instance
          @instance ||= new
        end

        def self.write_file(*args)
          instance.write_file(*args)
        end

        def self.ensure_dirs(one_or_more_dirs)
          Array(one_or_more_dirs).each do |directory|
            instance.ensure_dir(directory)
          end
        end

        def self.validate_file_paths(one_or_more_paths)
          errors = []
          Array(one_or_more_paths).each do |path|
            if !File.exist?(path) || !File.readable?(path)
              errors << "Could not read file '#{path}'"
            end
          end

          errors
        end

        def self.check_for_existing_files(one_or_more_paths)
          errors = []
          Array(one_or_more_paths).each do |path|
            if File.exist?(path)
              errors << "Existing file at '#{path}'"
            end
          end
          errors
        end

        def self.forcibly_symlink(source, link_target)
          FileUtils.remove_dir(link_target, true)
          FileUtils.symlink(source, link_target)
          # Ensure the symlink has the same ownership as the source.
          # This requires using `FileUtils.chown` rather than `File.chown`, as
          # the latter will update the ownership of the source rather than the
          # link itself.
          # Symlink permissions are ignored in favor of the source's permissions,
          # so we don't have to change those.
          source_info = File.stat(source)
          FileUtils.chown(source_info.uid, source_info.gid, link_target)
        end

        def initialize
          @user, @group = find_user_and_group
        end

        def find_user_and_group
          if !running_as_root?
            return Process.euid, Process.egid
          else
            if pe_puppet_exists?
              return 'pe-puppet', 'pe-puppet'
            else
              return 'puppet', 'puppet'
            end
          end
        end

        def running_as_root?
          !Gem.win_platform? && Process.euid == 0
        end

        def pe_puppet_exists?
          !!(Etc.getpwnam('pe-puppet') rescue nil)
        end

        def write_file(path, one_or_more_objects, mode)
          File.open(path, 'w', mode) do |f|
            Array(one_or_more_objects).each do |object|
              f.puts object.to_s
            end
          end
          FileUtils.chown(@user, @group, path)
        end

        # Warning: directory mode should be specified in DIR_MODES above
        def ensure_dir(directory)
          if !File.exist?(directory)
            FileUtils.mkdir_p(directory, mode: DIR_MODES[directory])
            FileUtils.chown(@user, @group, directory)
          end
        end
      end
    end
  end
end
