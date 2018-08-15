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
      /.*Usage:.* puppetserver ca clean.*Display this clean specific help output.*/m
  end

  describe 'the create action' do
    include_examples 'basic cli args',
      'create',
      /.*Usage:.* puppetserver ca create.*Display this create specific help output.*/m
  end

  describe 'the generate action' do
    include_examples 'basic cli args',
      'generate',
      /.*Usage:.* puppetserver ca generate.*Display this generate specific help output.*/m
  end

  describe 'the import action' do
    include_examples 'basic cli args',
      'import',
      /.*Usage:.* puppetserver ca import.*Display this import specific help output.*/m
  end

  describe 'the list action' do
    include_examples 'basic cli args',
      'list',
       /.*Usage:.* puppetserver ca list.* Display this command specific help output/m
  end

  describe 'the revoke action' do
    include_examples 'basic cli args',
      'revoke',
      /.*Usage:.* puppetserver ca revoke.*instructs the CA to revoke.*/m
  end

  describe 'the sign action' do
    include_examples 'basic cli args',
      'sign',
      /.*Usage.* puppetserver ca sign.*Display this command specific help output.*/m
  end
end
