require 'spec_helper'
require 'puppetserver/ca/utils/config'

RSpec.describe 'Puppetserver::Ca::Utils::Config' do
  describe '.munge_alt_names' do
    it 'prepends DNS: to unprefixed names and sorts/dedupes' do
      expect(Puppetserver::Ca::Utils::Config.munge_alt_names('foo.com,IP:10.0.0.1,DNS:foo.com')).
        to eq('DNS:foo.com, IP:10.0.0.1')
    end

    it 'returns an empty string for an empty string' do
      expect(Puppetserver::Ca::Utils::Config.munge_alt_names('')).to eq('')
    end

    # PE-44595: a puppet.conf key that is present but has no value
    # (`dns_alt_names =`) can be read as nil, so munge_alt_names must tolerate
    # nil rather than crashing with `undefined method 'split' for nil`.
    it 'returns an empty string for nil instead of crashing' do
      expect { Puppetserver::Ca::Utils::Config.munge_alt_names(nil) }.not_to raise_error
      expect(Puppetserver::Ca::Utils::Config.munge_alt_names(nil)).to eq('')
    end
  end
end
