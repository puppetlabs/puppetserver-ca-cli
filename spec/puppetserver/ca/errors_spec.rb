require 'spec_helper'

RSpec.describe Puppetserver::Ca::Errors do

  describe 'handle with usage' do
    let(:stdout) { StringIO.new }
    let(:stderr) { StringIO.new }
    let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

    it 'logs errors at error level' do
      subject.handle_with_usage(logger, ['foo'])
      expect(stdout.string).to be_empty
      expect(stderr.string).to match(/^Error.*foo$/m)
    end

    it 'returns true if errors have been handled' do
      expect(subject.handle_with_usage(logger, [])).to be(false)
      expect(subject.handle_with_usage(logger, ['foo'])).to be(true)
    end

    it 'optionally prints a usage, if given' do
      subject.handle_with_usage(logger, ['foo'], 'Use it')
      expect(stderr.string).to include('Use it')
    end
  end
end
