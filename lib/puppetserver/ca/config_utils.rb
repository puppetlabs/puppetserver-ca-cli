module Puppetserver
  module Ca
    module ConfigUtils

      def running_as_root?
        !Gem.win_platform? && Process::UID.eid == 0
      end

    end
  end
end
