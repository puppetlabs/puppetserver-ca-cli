module Puppetserver
  module Ca
    class Error < StandardError; end
    class FileNotFound < Error; end
    class InvalidX509Object < Error; end
    class ConnectionFailed < Error; end

    module Errors
    end
  end
end
