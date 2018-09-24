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

      end
    end
  end
end
