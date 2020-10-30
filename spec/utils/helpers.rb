
module Utils
  module Helpers
    def self.remove_cadir_deprecation(io)
      io.string.each_line.reject do |line|
        line =~ /migrate out from the puppet confdir to the \/etc\/puppetlabs\/puppetserver\/ca/
      end
    end
  end
end
