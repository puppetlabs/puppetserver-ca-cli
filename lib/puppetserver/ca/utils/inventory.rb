require 'time'

module Puppetserver
  module Ca
    module Utils
      module Inventory

        # Note that the inventory file may have multiple entries for the same certname,
        # so it should only provide the latest cert for the given certname.
        def self.parse_inventory_file(path, logger)
          unless File.exist?(path)
            logger.err("Could not find inventory at #{path}")
            return [{}, true]
          end
          inventory = {}
          errored = false
          File.readlines(path).each do |line|
            # Shouldn't be any blank lines, but skip them if there are
            next if line.strip.empty?
            
            items = line.strip.split
            if items.count != 4
              logger.err("Invalid entry found in inventory.txt: #{line}")
              errored = true
              next
            end
            unless items[0].match(/^(?:0x)?[A-Fa-f0-9]+$/)
              logger.err("Invalid serial found in inventory.txt line: #{line}")
              errored = true
              next
            end
            serial = items[0].hex
            not_before = nil
            not_after = nil
            begin
              not_before = Time.parse(items[1])
            rescue ArgumentError
              logger.err("Invalid not_before time found in inventory.txt line: #{line}")
              errored = true
              next
            end
            begin
              not_after = Time.parse(items[2])
            rescue ArgumentError
              logger.err("Invalid not_after time found in inventory.txt line: #{line}")
              errored = true
              next
            end
            unless items[3].start_with?('/CN=')
              logger.err("Invalid certname found in inventory.txt line: #{line}")
              errored = true
              next
            end
            certname = items[3][4..-1]

            if !inventory.keys.include?(certname) 
              inventory[certname] = {
                :serial => serial,
                :old_serials => [],
                :not_before => not_before,
                :not_after => not_after,
              }
            else
              if not_after >= inventory[certname][:not_after]
                # This is a newer cert than the one we currently have recorded,
                # so save the previous serial in :old_serials
                inventory[certname][:old_serials] << inventory[certname][:serial]
                inventory[certname][:serial] = serial
                inventory[certname][:not_before] = not_before
                inventory[certname][:not_after] = not_after
              else
                # This somehow is an older cert (shouldn't really be possible as we just append
                # to the file with each new cert and we are reading it order)
                inventory[certname][:old_serials] << serial
              end
            end
          end
          [inventory, errored]
        end
      end
    end
  end
end

