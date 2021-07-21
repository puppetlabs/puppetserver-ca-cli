module Puppetserver
  module Ca
    class Logger
      LEVELS = {error: 1, warning: 2, info: 3, debug: 4}

      def initialize(level = :info, out = STDOUT, err = STDERR)
        @level = LEVELS[level]
        if @level.nil?
          raise ArgumentError, "Unknown log level #{level}"
        end

        @out = out
        @err = err
      end

      def level
        @level
      end

      def debug?
        return @level >= LEVELS[:debug]
      end

      def debug(text)
        if debug?
          @out.puts(text)
        end
      end

      def inform(text)
        if @level >= LEVELS[:info]
          @out.puts(text)
        end
      end

      def warn(text)
        if @level >= LEVELS[:warning]
          @err.puts(text)
        end
      end

      def err(text)
        if @level >= LEVELS[:error]
          @err.puts(text)
        end
      end
    end
  end
end
