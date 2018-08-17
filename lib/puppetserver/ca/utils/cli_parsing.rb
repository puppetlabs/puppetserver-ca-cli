module Puppetserver
  module Ca
    module Utils
      def self.parse_without_raising(parser, args)
        all, not_flags, malformed_flags, unknown_flags = [], [], [], []

        begin
          # OptionParser calls this block when it finds a value that doesn't
          # start with one or two dashes and doesn't follow a flag that
          # consumes a value.
          parser.order!(args) do |not_flag|
            not_flags << not_flag
            all << not_flag
          end
        rescue OptionParser::MissingArgument => e
          malformed_flags += e.args
          all += e.args

          retry
        rescue OptionParser::ParseError => e
          flag = e.args.first
          unknown_flags << flag
          all << flag

          if does_not_contain_argument(flag) &&
              args.first &&
              next_arg_is_not_another_flag(args.first)

            value = args.shift
            unknown_flags << value
            all << value
          end

          retry
        end

        return all, not_flags, malformed_flags, unknown_flags
      end

      def self.parse_with_errors(parser, args)
        errors = []

        _, non_flags, malformed_flags, unknown_flags = parse_without_raising(parser, args)

        malformed_flags.each {|f| errors << "    Missing argument to flag `#{f}`" }
        unknown_flags.each   {|f| errors << "    Unknown flag or argument `#{f}`" }
        non_flags.each       {|f| errors << "    Unknown input `#{f}`" }

        errors
      end

      def self.handle_errors(log, errors, usage = nil)
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

    private

      # eg. --flag=argument-to-flag
      def self.does_not_contain_argument(flag)
        !flag.include?('=')
      end

      def self.next_arg_is_not_another_flag(maybe_an_arg)
        !maybe_an_arg.start_with?('-')
      end
    end
  end
end
