require 'puppetserver/ca/action/list'
require 'puppetserver/ca/cli'
require 'puppetserver/ca/logger'

RSpec.describe 'Puppetserver::Ca::Action::List' do
  let(:err)    { StringIO.new }
  let(:out)    { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, out, err) }
  let(:action) { Puppetserver::Ca::Action::List.new(logger) }
  let(:result) {[{"name"=>"foo", "state"=>"signed", "subject_alt_names"=>["DNS:foo", "DNS:bar"],
                  "authorization_extensions"=>{"pp_cli_auth"=>"true"},
                  "fingerprint"=>"three", "fingerprints"=>{"SHA1"=>"two", "SHA256"=>"three", "SHA512"=>"four", "default"=>"five"}},
                 {"name"=>"baz", "state"=>"requested", "subject_alt_names"=>["DNS:baz", "DNS:bar"],
                  "authorization_extensions"=>{"pp_cli_auth"=>"true", "pp_provisioner"=>"true"},
                  "fingerprint"=>"two", "fingerprints"=>{"SHA1"=>"one", "SHA256"=>"two", "SHA512"=>"three", "default"=>"four"}},
                 {"name"=>"foobar", "state"=>"revoked", "subject_alt_names"=>["DNS:foobar", "DNS:barfoo"],
                  "authorization_extensions"=>{},
                  "fingerprint"=>"onetwo", "fingerprints"=>{"SHA1"=>"one", "SHA256"=>"onetwo", "SHA512"=>"three", "default"=>"four"}}]}

  describe 'error handling' do
    it 'logs when no certs are found' do
      allow(action).to receive(:get_all_certs).and_return([])
      exit_code = action.run({})
      expect(exit_code).to eq(0)
      expect(out.string).to include('No certificates to list')
    end

    it 'logs requested certs' do
      allow(action).to receive(:get_all_certs).and_return(result)
      exit_code = action.run({})
      expect(exit_code).to eq(0)
      expect(out.string).to match(/Requested Certificates:.*baz.*\(SHA256\).*two.*alt names:.*"DNS:baz", "DNS:bar".*/m)
      expect(out.string).not_to match(/Signed Certificates:.*foo.*\(SHA256\).*three.*alt names:.*"DNS:foo", "DNS:bar".*/m)
      expect(out.string).not_to match(/Revoked Certificates:.*foobar.*\(SHA256\).*onetwo.*alt names:.*"DNS:foobar", "DNS:barfoo".*/m)
    end

    it 'logs requested, signed, and revoked certs with --all flag' do
      allow(action).to receive(:get_all_certs).and_return(result)
      exit_code = action.run({'all' => true})
      expect(exit_code).to eq(0)
      expect(out.string).to match(/Requested Certificates:.*baz.*\(SHA256\).*two.*alt names:.*"DNS:baz", "DNS:bar".*authorization extensions: \[pp_cli_auth: true, pp_provisioner: true\].*/m)
      expect(out.string).to match(/Signed Certificates:.*foo.*\(SHA256\).*three.*alt names:.*"DNS:foo", "DNS:bar".*authorization extensions: \[pp_cli_auth: true\].*/m)
      expect(out.string).to match(/Revoked Certificates:.*foobar.*\(SHA256\).*onetwo.*alt names:.*"DNS:foobar", "DNS:barfoo".*/m)
    end

    it 'logs requested certs with --certs flag' do
      allow(action).to receive(:get_all_certs).and_return(result)
      exit_code = action.run({'certname' => ['foo','baz']})
      expect(exit_code).to eq(0)
      expect(out.string).to match(/Requested Certificates:.*baz.*\(SHA256\).*two.*alt names:.*"DNS:baz", "DNS:bar".*/m)
      expect(out.string).to match(/Signed Certificates:.*foo.*\(SHA256\).*three.*alt names:.*"DNS:foo", "DNS:bar".*/m)
      expect(out.string).to_not match(/Revoked Certificates:.*foobar.*\(SHA256\).*onetwo.*alt names:.*"DNS:foobar", "DNS:barfoo".*/m)
    end

    it 'logs a non-existent cert as missing when requested with --certs flag' do
      allow(action).to receive(:get_all_certs).and_return(result)
      exit_code = action.run({'certname' => ['fake']})
      expect(exit_code).to eq(1)
      expect(out.string).to match(/Missing Certificates:.*fake.*/m)
    end

    it 'errors when any requested certs are missing with --certs flag' do
      allow(action).to receive(:get_all_certs).and_return(result)
      exit_code = action.run({'certname' => ['foo','fake']})
      expect(exit_code).to eq(1)
      expect(out.string).to match(/Signed Certificates:.*foo.*\(SHA256\).*three.*alt names:.*"DNS:foo", "DNS:bar".*/m)
      expect(out.string).to match(/Missing Certificates:.*fake.*/m)
    end
  end
end
