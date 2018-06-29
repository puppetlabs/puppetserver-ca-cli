
module Puppetserver
  module Ca
    class PuppetConfig

      attr_reader :errors, :ca_cert_path, :ca_key_path, :ca_crl_path
      def initialize(file_path_override = nil)
        @using_default_location = !file_path_override
        @config_path = file_path_override || user_specific_conf_file
        @results = {}
        @errors = []
      end

      def user_specific_conf_dir
        if Process::UID.eid == 0
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

        @ca_cert_path, @ca_key_path, @ca_crl_path = resolve_settings(@results)
      end

      def resolve_settings(overrides)
        unresolved_setting = /\$[a-z_]+/
        master = overrides[:master] || {}
        main = overrides[:main] || {}
        pick = ->(key, default) { master[key] || main[key] || default }

        settings = Hash.new {|h, k| k }
        confdir = user_specific_conf_dir
        settings['$confdir'] = confdir

        ssldir = pick.call(:ssldir, '$confdir/ssl')
        settings['$ssldir'] = ssldir.sub('$confdir', confdir)

        cadir = pick.call(:cadir, '$ssldir/ca')
        settings['$cadir'] = cadir.sub(unresolved_setting, settings)

        cacert = pick.call(:cacert, '$cadir/ca_crt.pem')
        cakey = pick.call(:cakey, '$cadir/ca_key.pem')
        cacrl = pick.call(:cacrl, '$cadir/ca_crl.pem')

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

      def parse_text(text)
        res = {}
        current_section = :main
        text.each_line do |line|
          case line
          when /^\s*\[(\w+)\].*/
            current_section = $1.to_sym
          when /^\s*(\w+)\s*=\s*([^\s{#]+).*$/
            res[current_section] ||= {}
            res[current_section][$1.to_sym] = $2
          end
        end

        res
      end
    end
  end
end
