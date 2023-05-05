require 'spec_helper'
require 'utils/ssl'

require 'fileutils'

require 'puppetserver/ca/utils/http_client'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/action/setup'

RSpec.describe Puppetserver::Ca::Utils::HttpClient do
  include Utils::SSL

  Result = Struct.new(:code, :body)

  let(:log_level) { :info }

  before do
    @stdout = StringIO.new
    @stderr = StringIO.new
    @logger = Puppetserver::Ca::Logger.new(log_level, @stdout, @stderr)
  end

  it 'creates a store that can validate connections to CA' do
    Dir.mktmpdir do |tmpdir|
      with_ca_in(tmpdir) do |config, confdir|
        settings = Puppetserver::Ca::Config::Puppet.new(config).load(cli_overrides: {
          :hostcert    => "#{tmpdir}/hostcert.pem",
          :hostprivkey => "#{tmpdir}/hostkey.pem",
          :confdir     => confdir
        }, logger: @logger)

        setup_action = Puppetserver::Ca::Action::Setup.new(@logger)

        signer = Puppetserver::Ca::Utils::SigningDigest.new
        setup_action.generate_pki(settings, signer.digest)

        loader = Puppetserver::Ca::X509Loader.new(settings[:cacert], settings[:cakey], settings[:cacrl])
        cakey = loader.key
        cacert = loader.cert

        hostkey = OpenSSL::PKey::RSA.new(512)
        hostcert = create_cert(hostkey, 'foobar', cakey, cacert)
        File.write("#{tmpdir}/hostcert.pem", hostcert)
        File.write("#{tmpdir}/hostkey.pem", hostkey)

        FileUtils.cp(settings[:cacert], settings[:localcacert])
        FileUtils.cp(settings[:cacrl], settings[:hostcrl])

        client = Puppetserver::Ca::Utils::HttpClient.new(@logger, settings)
        store = client.store

        expect(store.verify(hostcert)).to be(true)
        expect(store.verify(cacert)).to be(true)
      end
    end
  end

  it 'create a URL with query params correctly' do
    query = { :state => "requested" }
    url = Puppetserver::Ca::Utils::HttpClient::URL.new('https', 'localhost', '8140',
                                                       'puppet-ca', 'v1', 'certificate_statuses', 'any_key', query)
    result = url.to_uri
    expect(result.to_s).to eq("https://localhost:8140/puppet-ca/v1/certificate_statuses/any_key?state=requested")
  end

  it 'creates valid default headers for HTTP requests when token file is not present' do
    Dir.mktmpdir do |tmpdir|
      with_ca_in(tmpdir) do |config, confdir|
        settings = Puppetserver::Ca::Config::Puppet.new(config).load(cli_overrides: {}, logger: @logger, ca_dir_warn: false)

        FileUtils.mkdir_p(settings[:certdir])
        FileUtils.cp(settings[:cacert], settings[:localcacert])
        FileUtils.cp(settings[:cacrl], settings[:hostcrl])

        url = Puppetserver::Ca::Utils::HttpClient::URL.new('https', 'localhost', '8140',
                                                           'puppet-ca', 'v1', 'certificate_status', 'any_key', {"desired_state" => "signed"})
        unauthed_client = Puppetserver::Ca::Utils::HttpClient.new(@logger, settings, with_client_cert: false)

        base_headers = { 'User-Agent'   => 'PuppetserverCaCli',
                         'Content-Type' => 'application/json',
                         'Accept'       => 'application/json' }

        auth_header = 'X-Authentication'
        token = 'foo'

        # Here we create a mock Net::HTTP::Connection object and validate the HTTP method the client created has the correct headers
        mock_unauthed_conn = double('connection')
        allow(mock_unauthed_conn).to receive(:request) do |http_method|
          headers = http_method.each_header.map {|h,v| [h.downcase, v]}.to_h

          base_headers.each_pair do |header, value|
            expect(headers[header.downcase]).to eq(value)
          end

          expect(headers[auth_header.downcase]).to eq(nil)

          Result.new(200, 'foo body')
        end

        # This bypasses the actual HTTP request and allows us to insert our mock Net::HTTP::Connection object.
        # The mock stdlib connection object will then be wrapped by our client & custom connection object.
        allow(Net::HTTP).to receive(:start) do |host, port, use_ssl:, cert_store:, cert:, key:, &request|
          request.call(mock_unauthed_conn)
        end

        # This receives our custom connection object and triggers the above expectations.
        unauthed_client.with_connection(url) do |connection|
          result = connection.put('input body', url, {})
          expect(result.body).to eq('foo body')
        end
      end
    end
  end

  it 'creates valid default headers for HTTP requests when token file is present' do
    Dir.mktmpdir do |tmpdir|
      with_ca_in(tmpdir) do |config, confdir|
        settings = Puppetserver::Ca::Config::Puppet.new(config).load(cli_overrides: {}, logger: @logger, ca_dir_warn: false)

        FileUtils.mkdir_p(settings[:certdir])
        FileUtils.cp(settings[:cacert], settings[:localcacert])
        FileUtils.cp(settings[:cacrl], settings[:hostcrl])

        url = Puppetserver::Ca::Utils::HttpClient::URL.new('https', 'localhost', '8140',
                                                           'puppet-ca', 'v1', 'certificate_status', 'any_key', {"desired_state" => "signed"})

        base_headers = { 'User-Agent'   => 'PuppetserverCaCli',
                         'Content-Type' => 'application/json',
                         'Accept'       => 'application/json' }

        auth_header = 'X-Authentication'
        token = 'foo'

        Dir.mkdir("#{tmpdir}/.puppetlabs")
        File.write("#{tmpdir}/.puppetlabs/token", token)

        env = ENV.to_h.dup
        env['HOME'] = tmpdir
        stub_const('ENV', env)

        authed_client = Puppetserver::Ca::Utils::HttpClient.new(@logger, settings, with_client_cert: false)

        # See the previous test for why this is necessary
        mock_authed_conn = double('connection')
        allow(mock_authed_conn).to receive(:request) do |http_method|
          headers = http_method.each_header.map {|h,v| [h.downcase, v]}.to_h

          base_headers.each_pair do |header, value|
            expect(headers[header.downcase]).to eq(value)
          end

          expect(headers[auth_header.downcase]).to eq(token)

          Result.new(200, 'bar body')
        end

        # See the previous test for why this is necessary
        allow(Net::HTTP).to receive(:start) do |host, port, use_ssl:, cert_store:, cert:, key:, &request|
          request.call(mock_authed_conn)
        end

        # See the previous test for why this is necessary
        authed_client.with_connection(url) do |connection|
          result = connection.put('input body', url, {})
          expect(result.body).to eq('bar body')
        end
      end
    end
  end
end
