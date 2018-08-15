require 'puppetserver/ca/sign_action'
require 'puppetserver/ca/cli'
require 'puppetserver/ca/logger'

RSpec.describe 'Puppetserver::Ca::SignAction' do
  let(:err)    { StringIO.new }
  let(:out)    { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, out, err) }
  let(:action) { Puppetserver::Ca::SignAction.new(logger) }

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
  end

  describe 'error handling' do
    let(:response)  { Struct.new(:code, :body) }
    let(:success)   { response.new('204', nil) }
    let(:not_found) { response.new('404', 'Not Found') }
    let(:empty)     { response.new('404', '[]') }

    it 'logs and exits with zero with successful PUT' do
      allow(action).to receive(:sign_certs).and_return({'foo' => success})
      exit_code = action.run({'certname' => ['foo']})
      expect(exit_code).to eq(0)
      expect(out.string).to include('Signed certificate for foo')
    end

    it 'fails when PUT request errors' do
      allow(action).to receive(:get_certificate_statuses).and_return(not_found)
      exit_code = action.run({'all' => true})
      expect(exit_code).to eq(1)
    end

    it 'fails when no pending certs' do
      allow(action).to receive(:get_all_certs).and_return(empty)
      exit_code = action.run({'all' => true})
      expect(exit_code).to eq(1)
      expect(err.string).to include('No waiting certificate requests to sign')
    end

    it 'continues signing certs after failed request' do
      allow(action).to receive(:sign_certs).and_return({'foo' => success, 'bar' => not_found, 'baz' => success})
      exit_code = action.run({'certname' => ['foo','bar','baz']})
      expect(exit_code).to eq(1)
      expect(out.string).to match(/Signed certificate for foo.*Signed certificate for baz/m)
      expect(err.string).to include('Could not find certificate for bar')
    end
  end
end
