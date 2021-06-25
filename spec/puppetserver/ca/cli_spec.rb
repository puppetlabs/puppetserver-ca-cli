require 'spec_helper'
require 'shared_examples/cli_parsing'

require 'puppetserver/ca/cli'

RSpec.describe Puppetserver::Ca::Cli do
  describe 'general options' do
    include_examples 'basic cli args',
      nil,
      /.*Usage: puppetserver ca <action> .*Display this general help output.*/m
  end

  describe 'the clean action' do
    include_examples 'basic cli args',
      'clean',
      /.*Usage:.* puppetserver ca clean.*Display this command-specific help output.*/m
  end

  describe 'the enable action' do
    include_examples 'basic cli args',
      'enable',
      /.*Usage:.* puppetserver ca enable.*Display this command-specific help output.*/m
  end

  describe 'the generate action' do
    include_examples 'basic cli args',
      'generate',
      /.*Usage:.* puppetserver ca generate.*Display this command-specific help output.*/m
  end

  describe 'the setup action' do
    include_examples 'basic cli args',
      'setup',
      /.*Usage:.* puppetserver ca setup.*Display this command-specific help output.*/m
  end

  describe 'the import action' do
    include_examples 'basic cli args',
      'import',
      /.*Usage:.* puppetserver ca import.*Display this command-specific help output.*/m
  end

  describe 'the list action' do
    include_examples 'basic cli args',
      'list',
       /.*Usage:.* puppetserver ca list.* Display this command-specific help output/m
  end

  describe 'the revoke action' do
    include_examples 'basic cli args',
      'revoke',
      /.*Usage:.* puppetserver ca revoke.*instructs the CA to revoke.*/m
  end

  describe 'the sign action' do
    include_examples 'basic cli args',
      'sign',
      /.*Usage.* puppetserver ca sign.*Display this command-specific help output.*/m
  end

  # This test is a representation of what to expect when the verbose flag
  # is raised with an action. We're using the 'clean' action as an example 
  it 'raise the verbose flag' do
    args = ['--verbose', 'clean'].compact
    action_class = Puppetserver::Ca::Cli::VALID_ACTIONS[args[1]]
    expect(action_class).to receive(:new).and_wrap_original do |original, logger|
      expect(logger.level).to eq(4)
      original.call(logger)
    end
    Puppetserver::Ca::Cli.run(args, StringIO.new, StringIO.new)
  end
end
