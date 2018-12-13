module Puppetserver
  module Ca
    class Error < StandardError
      attr_reader :wrapped

      def wrap(ex)
        @wrapped = ex
      end
    end

    class FileNotFound < Error; end
    class InvalidX509Object < Error; end
    class ConnectionFailed < Error; end

    module Errors
      def self.handle_with_usage(log, errors, usage = nil)
        unless errors.empty?
          log.err 'Error:'
          errors.each {|e| log.err e }

          if usage
            log.err ''
            log.err usage
          end

          return true
        else
          return false
        end
      end
    end
  end
end
