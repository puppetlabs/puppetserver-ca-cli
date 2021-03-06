require 'puppetserver/ca/action/sign'
require 'puppetserver/ca/cli'
require 'puppetserver/ca/logger'

RSpec.describe 'Puppetserver::Ca::SignAction' do
  let(:err)    { StringIO.new }
  let(:out)    { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, out, err) }
  let(:action) { Puppetserver::Ca::Action::Sign.new(logger) }

  describe 'validation' do
    it 'does not expect an argument' do
      _, exit_code = action.parse(['--all', 'foo'])
      expect(err.string).to match(/Error:.*Unknown input.*foo/m)
      expect(exit_code).to eq(1)
    end

    it 'does not allow --all with a valid certname call' do
      _, exit_code = action.parse(['--certname', 'foo', '--all'])
      expect(err.string).to include('--all and --certname cannot be used together')
      expect(exit_code).to eq(1)
    end

    it 'errors without any arguments' do
      _, exit_code = action.parse([])
      expect(err.string).to include('No arguments given')
      expect(exit_code).to eq(1)
    end

    it 'errors without a certname' do
      _, exit_code = action.parse(['--certname'])
      expect(err.string).to match(/Error:.*Missing argument to flag/m)
      expect(exit_code).to eq(1)
    end

    it 'does not allow --certname and --all' do
      _, exit_code = action.parse(['--certname', '--all'])
      expect(err.string).to match(/Cannot use --all.*HTTP API/)
      expect(exit_code).to eq(1)
    end

    it 'works with a single cert' do
      results, exit_code = action.parse(['--certname', 'foo'])
      expect(results['certname']).to eq(['foo'])
      expect(exit_code).to eq(nil)
    end

    it 'works with a comma separated list of certs' do
      results, exit_code = action.parse(['--certname', 'foo,bar,baz'])
      expect(results['certname']).to eq(['foo','bar','baz'])
      expect(exit_code).to eq(nil)
    end

    it 'works with a single cert and ttl' do
      results, exit_code = action.parse(['--certname', 'foo', '--ttl', 'ttl-value'])
      expect(results['ttl']).to eq('ttl-value')
      expect(exit_code).to eq(nil)
    end
  end

  describe 'error handling' do
    let(:response)      { Struct.new(:code, :body) }
    let(:success)       { response.new('204', nil) }
    let(:get_success)   { response.new('200', 'Stuff') }
    let(:not_found)     { response.new('404', 'Not Found') }
    let(:empty)         { response.new('404', '[]') }

    let(:connection) { double }

    before do
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:with_connection).and_yield(connection)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:make_store)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:load_cert)
      allow_any_instance_of(Puppetserver::Ca::Utils::HttpClient).
        to receive(:load_key)
    end

    it 'logs and exits with zero with successful PUT' do
      allow(connection).to receive(:put).and_return(success)
      exit_code = action.run({'certname' => ['foo']})
      expect(exit_code).to eq(0)
      expect(out.string).to include('signed certificate request for foo')
    end

    it 'logs and exits with zero with successful PUT with a custom ttl' do
      allow(connection).to receive(:put).with(/3600/, any_args).and_return(success)
      exit_code = action.run({'certname' => ['foo'], 'ttl' => '1h'})
      expect(exit_code).to eq(0)
      expect(out.string).to include('signed certificate request for foo')
    end

    it 'fails when an invalid ttl is specified' do
      exit_code = action.run({'certname' => ['foo'], 'ttl' => '1x'})
      expect(exit_code).to eq(1)
      expect(err.string).to match(/Error.* invalid ttl value/m)
      expect(connection).to_not receive(:put)
    end

    it 'logs and exits with zero with successful GET and PUT' do
      allow(connection).to receive(:put).and_return(success)
      allow(connection).to receive(:get).and_return(get_success)
      allow(action).to receive(:select_pending_certs).and_return(['ulla'])
      exit_code = action.run({'all' => true})
      expect(exit_code).to eq(0)
      expect(out.string).to include('signed certificate request for ulla')
    end

    it 'fails when GET request errors' do
      allow(connection).to receive(:get).and_return(not_found)
      exit_code = action.run({'all' => true})
      expect(exit_code).to eq(1)
    end

    it 'returns 24 when no pending certs' do
      allow_any_instance_of(Puppetserver::Ca::CertificateAuthority).
        to receive(:get_certificate_statuses).and_return(empty)
      exit_code = action.run({'all' => true})
      expect(exit_code).to eq(24)
      expect(err.string).to include('No waiting certificate requests to sign')
    end

    it 'continues signing certs after failed request' do
      allow(connection).to receive(:put).and_return(success, not_found, success)
      exit_code = action.run({'certname' => ['foo','bar','baz']})
      expect(exit_code).to eq(1)
      expect(out.string).to match(/signed certificate request for foo.*signed certificate request for baz/m)
      expect(err.string).to include('Could not find certificate request for bar')
    end
  end
end
