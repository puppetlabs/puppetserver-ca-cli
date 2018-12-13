require 'spec_helper'

require 'puppetserver/ca/errors'
require 'puppetserver/ca/logger'

# NOTE: There's two top level describes here, one for custom error
# functionality and one for the Errors help module.

RSpec.describe Puppetserver::Ca::Error do
  it 'can wrap an exception' do
    orig = StandardError.new('wrapped exception')
    ex = Puppetserver::Ca::Error.create(orig, 'wrapper exception')
    expect {
      ex.wrap(orig)
      expect(ex.wrapped).to be(orig)
    }.not_to raise_error
  end

end

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
