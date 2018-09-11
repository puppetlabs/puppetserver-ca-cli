require 'puppetserver/ca/action/import'
require 'utils/ssl'

def mode(file)
  File.stat(file).mode.to_s(8)[-3..-1]
end

RSpec.shared_examples 'properly sets up ca and ssl dir' do |action_class|
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }

  it 'creates all files with correct permissions' do
    Dir.mktmpdir do |tmpdir|
      with_files_in tmpdir do |bundle, key, chain, conf|
        importing = action_class == Puppetserver::Ca::Action::Import

        subject = action_class.new(logger)

        shared_flags = {'config' => conf, 'subject-alt-names' => '', 'certname' => 'foocert'}
        import_flags = {'cert-bundle' => bundle, 'private-key' => key, 'crl-chain' => chain}
        flags = importing ? shared_flags.merge(import_flags) : shared_flags.merge({'ca-name' => ''})

        exit_code = subject.run(flags)

        expect(exit_code).to eq(0)

        files = [['ca', 'ca_crt.pem', '644'],
                 ['ca', 'ca_crl.pem', '644'],
                 ['ca', 'ca_key.pem', '640'],
                 ['ca', 'infra_crl.pem', '644'],
                 ['ca', 'inventory.txt', '644'],
                 ['ca', 'infra_inventory.txt', '644'],
                 ['ca', 'serial', '644'],
                 ['ca', 'infra_serials', '644'],
                 ['ssl', 'certs', 'foocert.pem', '644'],
                 ['ssl', 'private_keys', 'foocert.pem', '640'],
                 ['ssl', 'public_keys', 'foocert.pem', '644']]


        files.each do |args|
          perms = args.pop
          file = File.join(tmpdir, *args)
          expect(File.exist?(file)).to be(true), "#{file} does not exit"
          expect(mode(file)).to eq(perms)
        end

        unless importing
          file = File.join(tmpdir, 'ca', 'root_key.pem')
          expect(File.exist?(file)).to be true
          expect(mode(file)).to eq('640')
        end
      end
    end
  end
end
