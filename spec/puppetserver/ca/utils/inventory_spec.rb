require 'spec_helper'
require 'puppetserver/ca/utils/inventory'

RSpec.describe Puppetserver::Ca::Utils::Inventory do
  def timefmt(time)
    time.utc.strftime("%Y-%m-%dT%H:%M:%SUTC")
  end

  def write_inventory(dir, contents)
    File.write("#{dir}/inventory.txt", contents)
  end

  describe 'parse_inventory_file' do
    let(:inventory) { 
      t = Time.parse("2023-01-11 09:00:00.000000000 +0000")
      not_before_unexpired = t - 1
      not_after_unexpired = t + 360000
      not_before_expired = t - 100
      not_after_expired = t - 1
      # Real inventory won't have an extra newline, but putting it here to ensure
      # it ignores it correctly.
      <<~INV
      0x0001 #{timefmt(not_before_expired)} #{timefmt(not_after_expired)} /CN=foo
      0x0002 #{timefmt(not_before_expired)} #{timefmt(not_after_expired)} /CN=bar
      0x0003 #{timefmt(not_before_unexpired)} #{timefmt(not_after_unexpired)} /CN=bar

      INV
    }
    let(:logger) { double }
    let(:correct) { 
      t = Time.parse("2023-01-11 09:00:00.000000000 +0000")
      {
        'foo' => {
          :serial => 1,
          :not_before => t - 100,
          :not_after => t - 1,
          :old_serials => [],
        },
        'bar' => {
          :serial => 3,
          :not_before => t - 1,
          :not_after => t + 360000,
          :old_serials => [2],
        }
      }
    }

    it 'handles when inventory.txt does not exist' do
      Dir.mktmpdir do |tmpdir|
        expect(logger).to receive(:err).with("Could not find inventory at #{tmpdir}/inventory.txt")
        expect(subject.parse_inventory_file("#{tmpdir}/inventory.txt", logger)).to eq([{}, true])
      end
    end

    it 'handles an inventory.txt with an invalid line' do
      Dir.mktmpdir do |tmpdir|
        write_inventory(tmpdir, inventory)
        File.write("#{tmpdir}/inventory.txt", "This is a bad inventory line", mode: 'a')
        expect(logger).to receive(:err).with(/Invalid entry found in inventory.txt/)
        expect(subject.parse_inventory_file("#{tmpdir}/inventory.txt", logger)).to eq([correct, true])
      end
    end

    it 'handles an inventory.txt line with an invalid serial' do 
      Dir.mktmpdir do |tmpdir|
        write_inventory(tmpdir, inventory)
        File.write("#{tmpdir}/inventory.txt", "0xlolwut #{timefmt(Time.now)} #{timefmt(Time.now)} /CN=badnode", mode: 'a')
        expect(logger).to receive(:err).with(/Invalid serial found in inventory.txt line/)
        expect(subject.parse_inventory_file("#{tmpdir}/inventory.txt", logger)).to eq([correct, true])
      end
    end

    it 'handles an inventory.txt line with an invalid not_before' do 
      Dir.mktmpdir do |tmpdir|
        write_inventory(tmpdir, inventory)
        File.write("#{tmpdir}/inventory.txt", "0x0004 lolwut #{timefmt(Time.now)} /CN=badnode", mode: 'a')
        expect(logger).to receive(:err).with(/Invalid not_before time found in inventory.txt line/)
        expect(subject.parse_inventory_file("#{tmpdir}/inventory.txt", logger)).to eq([correct, true])
      end
    end

    it 'handles an inventory.txt line with an invalid not_after' do 
      Dir.mktmpdir do |tmpdir|
        write_inventory(tmpdir, inventory)
        File.write("#{tmpdir}/inventory.txt", "0x0004 #{timefmt(Time.now)} lolwut /CN=badnode", mode: 'a')
        expect(logger).to receive(:err).with(/Invalid not_after time found in inventory.txt line/)
        expect(subject.parse_inventory_file("#{tmpdir}/inventory.txt", logger)).to eq([correct, true])
      end
    end

    it 'handles an inventory.txt line with an invalid certname designation' do 
      Dir.mktmpdir do |tmpdir|
        write_inventory(tmpdir, inventory)
        File.write("#{tmpdir}/inventory.txt", "0x0004 #{timefmt(Time.now)} #{timefmt(Time.now)} lolwut", mode: 'a')
        expect(logger).to receive(:err).with(/Invalid certname found in inventory.txt line/)
        expect(subject.parse_inventory_file("#{tmpdir}/inventory.txt", logger)).to eq([correct, true])
      end
    end
  end
end