require 'puppetserver/ca/action/sign'
require 'puppetserver/ca/cli'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/http_client'

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
    let(:status_url)    { Puppetserver::Ca::Utils::HttpClient::URL.new('https','localhost','8140','status','v1','services') }
    let(:bulk_sign_url) { Puppetserver::Ca::Utils::HttpClient::URL.new('https','localhost','8140','puppet-ca','v1','sign', nil, {}) }
    let(:bulk_sign_all_url) { Puppetserver::Ca::Utils::HttpClient::URL.new('https','localhost','8140','puppet-ca','v1','sign','all', {}) }
    let(:status_old_server) { response.new('200', '{"ca":{"service_version":"7.4.1"}}') }
    let(:status_new_server) { response.new('200', '{"ca":{"service_version":"8.4.1"}}') }
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

    describe 'bulk signing available' do
      before { allow(connection).to receive(:get).with(status_url).and_return(status_new_server) }

      describe 'using --certname' do
        it 'uses /certificate_status endpoint when specifying TTL' do
          allow(connection).to receive(:put).with(/3600/, any_args).and_return(success)
          exit_code = action.run({'certname' => ['foo'], 'ttl' => '1h'})
          expect(exit_code).to eq(0)
          expect(out.string).to include('signed certificate request for foo')
        end

        it 'uses the /sign endpoint' do
          result = response.new('200', '{"signed":["foo","bar"],"no-csr":[],"signing-errors":[]}')
          allow(connection).to receive(:post).with("{\"certnames\":[\"foo\", \"bar\"]}", bulk_sign_url, {}).and_return(result)
          exit_code = action.run({'certname' => ['foo','bar']})
          expect(exit_code).to eq(0)
          expect(out.string).to match(/Successfully signed the following.*foo.*bar/m)
        end

        it 'handles no CSR being present' do
          result = response.new('200', '{"signed":["foo"],"no-csr":["bar"],"signing-errors":[]}')
          allow(connection).to receive(:post).with("{\"certnames\":[\"foo\", \"bar\"]}", bulk_sign_url, {}).and_return(result)
          exit_code = action.run({'certname' => ['foo','bar']})
          expect(exit_code).to eq(1)
          expect(out.string).to match(/Successfully signed the following.*foo/m)
          expect(err.string).to match(/No certificate request.*bar/m)
        end

        it 'handles an error signing a cert' do
          result = response.new('200', '{"signed":["foo"],"no-csr":[],"signing-errors":["bar"]}')
          allow(connection).to receive(:post).with("{\"certnames\":[\"foo\", \"bar\"]}", bulk_sign_url, {}).and_return(result)
          exit_code = action.run({'certname' => ['foo','bar']})
          expect(exit_code).to eq(1)
          expect(out.string).to match(/Successfully signed the following.*foo/m)
          expect(err.string).to match(/Error encountered when attempting to sign.*bar/m)
        end

        it 'handles no body in the response' do
          result = response.new('200', nil)
          allow(connection).to receive(:post).with("{\"certnames\":[\"foo\", \"bar\"]}", bulk_sign_url, {}).and_return(result)
          exit_code = action.run({'certname' => ['foo','bar']})
          expect(exit_code).to eq(1)
          expect(err.string).to match(/Response from \/sign endpoint did not include a body/m)
        end

        it 'handles a non-JSON response' do
          result = response.new('200', 'nu uh, not gonna sign nuthin')
          allow(connection).to receive(:post).with("{\"certnames\":[\"foo\", \"bar\"]}", bulk_sign_url, {}).and_return(result)
          exit_code = action.run({'certname' => ['foo','bar']})
          expect(exit_code).to eq(1)
          expect(err.string).to match(/Unable to parse the response from the \/sign endpoint/m)
        end

        it 'handles a non-200 response' do
          result = response.new('404', 'Not found')
          allow(connection).to receive(:post).with("{\"certnames\":[\"foo\", \"bar\"]}", bulk_sign_url, {}).and_return(result)
          exit_code = action.run({'certname' => ['foo','bar']})
          expect(exit_code).to eq(1)
          expect(err.string).to match(/When attempting to sign certificate requests.*404.*Not found/m)
        end
      end

      describe 'using --all' do
        it 'uses /certificate_status endpoint when specifying TTL and --all' do
          allow(connection).to receive(:put).with(/3600/, any_args).and_return(success)
          allow(connection).to receive(:get).and_return(get_success)
          allow(action).to receive(:select_pending_certs).and_return(['ulla'])
          exit_code = action.run({'all' => true, 'ttl' => '1h'})
          expect(exit_code).to eq(0)
          expect(out.string).to include('signed certificate request for ulla')
        end

        it 'uses /sign/all when specifying --all' do
          result = response.new('200', '{"signed":["foo","bar"],"no-csr":[],"signing-errors":[]}')
          allow(connection).to receive(:post).with("{}", bulk_sign_all_url, {}).and_return(result)
          exit_code = action.run({'all' => true})
          expect(exit_code).to eq(0)
          expect(out.string).to match(/Successfully signed the following.*foo.*bar/m)
        end

        it 'handles no CSRs waiting to be signed when specifying --all' do
          result = response.new('200', '{"signed":[],"no-csr":[],"signing-errors":[]}')
          allow(connection).to receive(:post).with("{}", bulk_sign_all_url, {}).and_return(result)
          exit_code = action.run({'all' => true})
          expect(exit_code).to eq(24)
          expect(err.string).to match(/No waiting certificate requests to sign/)
        end

        it 'handles an error signing a cert' do
          result = response.new('200', '{"signed":["foo"],"no-csr":[],"signing-errors":["bar"]}')
          allow(connection).to receive(:post).with("{}", bulk_sign_all_url, {}).and_return(result)
          exit_code = action.run({'all' => true})
          expect(exit_code).to eq(1)
          expect(out.string).to match(/Successfully signed the following.*foo/m)
          expect(err.string).to match(/Error encountered when attempting to sign.*bar/m)
        end

        it 'handles no body in the response' do
          result = response.new('200', nil)
          allow(connection).to receive(:post).with("{}", bulk_sign_all_url, {}).and_return(result)
          exit_code = action.run({'all' => true})
          expect(exit_code).to eq(1)
          expect(err.string).to match(/Response from \/sign\/all endpoint did not include a body/m)
        end

        it 'handles a non-JSON response' do
          result = response.new('200', 'nu uh, not gonna sign nuthin')
          allow(connection).to receive(:post).with("{}", bulk_sign_all_url, {}).and_return(result)
          exit_code = action.run({'all' => true})
          expect(exit_code).to eq(1)
          expect(err.string).to match(/Unable to parse the response from the \/sign\/all endpoint/m)
        end

        it 'handles a non-200 response' do
          result = response.new('404', 'Not found')
          allow(connection).to receive(:post).with("{}", bulk_sign_all_url, {}).and_return(result)
          exit_code = action.run({'all' => true})
          expect(exit_code).to eq(1)
          expect(err.string).to match(/When attempting to sign all certificate requests.*404.*Not found/m)
        end
      end
    end


    describe 'bulk signing unavailable' do
      before { allow(connection).to receive(:get).with(status_url).and_return(status_old_server) }

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
end
