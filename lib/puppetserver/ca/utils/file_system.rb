require 'fileutils'
require 'etc'

module Puppetserver
  module Ca
    module Utils
      class FileSystem

        def self.instance
          @instance ||= new
        end

        def self.write_file(*args)
          instance.write_file(*args)
        end

        def self.ensure_dir(setting)
          instance.ensure_dir(setting)
        end

        def self.ensure_file(location, content, mode)
          if !File.exist?(location)
            instance.write_file(location, content, mode)
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

        def ensure_dir(setting)
          if !File.exist?(setting)
            FileUtils.mkdir_p(setting, mode: 0750)
            FileUtils.chown(@user, @group, setting)
          end
        end
      end
    end
  end
end
