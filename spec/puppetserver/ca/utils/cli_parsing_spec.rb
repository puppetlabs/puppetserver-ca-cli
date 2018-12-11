require 'spec_helper'
require 'puppetserver/ca/utils/cli_parsing'
require 'puppetserver/ca/logger'

RSpec.describe Puppetserver::Ca::Utils::CliParsing do
  subject { Puppetserver::Ca::Utils::CliParsing }

  let(:parser) do
    OptionParser.new do |o|
      o.on('-f FOO', 'Fizz.')
    end
  end

  let(:args) { %w{blah -b --this non-sense --other=thing random -f} }

  describe 'parse_without_raising' do
    before do
      @consumed_args = args.dup
      @all, @not_flags, @malformed_flags, @unknown_flags =
        subject.parse_without_raising(parser, @consumed_args)
    end

    it 'separates out flags called without required arguments' do
      expect(@malformed_flags).to eq(['-f'])
    end

    it 'separates out unknown flags and their arguments' do
      expect(@unknown_flags).to eq(['-b', '--this', 'non-sense', '--other=thing'])
    end

    it 'spearates out non flag parameters' do
      expect(@not_flags).to eq(['blah', 'random'])
    end

    it 'saves items in the order they were passed' do
      expect(@all).to eq(args)
    end
  end

  describe 'parse_with_errors' do
    it 'returns meaningful errors' do
      errors = subject.parse_with_errors(parser, args)
      expect(errors).to include('    Missing argument to flag `-f`')
      expect(errors).to include('    Unknown flag or argument `--this`')
      expect(errors).to include('    Unknown flag or argument `non-sense`')
      expect(errors).to include('    Unknown input `blah`')
    end
  end
end
