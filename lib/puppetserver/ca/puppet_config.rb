
module Puppetserver
  module Ca
    # Provides an interface for asking for Puppet[ Server] settings w/o loading
    # either Puppet or Puppet Server. Includes a simple ini parser that will
    # ignore Puppet's more complicated conventions.
    class PuppetConfig

      attr_reader :errors, :ca_cert_path, :ca_key_path, :ca_crl_path
      def initialize(file_path_override = nil)
        @using_default_location = !file_path_override
        @config_path = file_path_override || user_specific_conf_file
        @results = {}
        @errors = []
      end

      # Return the correct confdir. We check for being root (user id == 0)
      # on *nix, else the user path. We do not include a check for running
      # as Adminstrator since non-development scenarios for Puppet Server
      # on Windows are unsupported.
      def user_specific_conf_dir
        if Gem.win_platform? && Process::UID.eid == 0
          '/etc/puppetlabs/puppet'
        else
          "#{ENV['HOME']}/.puppetlabs/etc/puppet"
        end
      end

      def user_specific_conf_file
        user_specific_conf_dir + '/puppet.conf'
      end

      def load
        unless @using_default_location && !File.exist?(@config_path)
          @results = parse_text(File.read(@config_path))
        end

        @results[:main] ||= {}
        @results[:master] ||= {}

        overrides = @results[:main].merge(@results[:master])

        @ca_cert_path, @ca_key_path, @ca_crl_path = resolve_settings(overrides)
      end

      # Resolve the cacert, cakey, and cacrl settings.
      def resolve_settings(overrides = {})
        unresolved_setting = /\$[a-z_]+/

        settings = Hash.new {|h, k| k }
        confdir = user_specific_conf_dir
        settings['$confdir'] = confdir

        ssldir = overrides.fetch(:ssldir, '$confdir/ssl')
        settings['$ssldir'] = ssldir.sub('$confdir', confdir)

        cadir = overrides.fetch(:cadir, '$ssldir/ca')
        settings['$cadir'] = cadir.sub(unresolved_setting, settings)

        cacert = overrides.fetch(:cacert, '$cadir/ca_crt.pem')
        cakey = overrides.fetch(:cakey, '$cadir/ca_key.pem')
        cacrl = overrides.fetch(:cacrl, '$cadir/ca_crl.pem')

        values = [cacert, cakey, cacrl].map do |setting|
          setting.sub(unresolved_setting, settings)
        end

        values.each do |value|
          if match = value.match(unresolved_setting)
            @errors << "Could not parse #{match[0]} in #{value}, " +
                       'valid settings to be interpolated are ' +
                       '$confdir, $ssldir, $cadir'
          end
        end

        return *values
      end

      # Parse an inifile formatted String. Only captures \word character
      # class keys/section names but nearly any character values (excluding
      # leading whitespace) up to one of whitespace, opening curly brace, or
      # hash sign (Our concern being to capture filesystem path values).
      # Put values without a section into :main.
      #
      # Return Hash of Symbol section names with Symbol setting keys and
      # String values.
      def parse_text(text)
        res = {}
        current_section = :main
        text.each_line do |line|
          case line
          when /^\s*\[(\w+)\].*/
            current_section = $1.to_sym
          when /^\s*(\w+)\s*=\s*([^\s{#]+).*$/
            # Using a Hash with a default key breaks RSpec expectations.
            res[current_section] ||= {}
            res[current_section][$1.to_sym] = $2
          end
        end

        res
      end
    end
  end
end
