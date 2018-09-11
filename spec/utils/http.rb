require 'spec_helper'

module Utils
  module Http
    Result = Struct.new(:code, :body)
  end
end
