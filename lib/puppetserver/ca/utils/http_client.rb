require 'net/https'
require 'openssl'
require 'uri'

require 'puppetserver/ca/errors'

module Puppetserver
  module Ca
    module Utils
      # Utilities for doing HTTPS against the CA that wraps Net::HTTP constructs
      class HttpClient

        DEFAULT_HEADERS = {
          'User-Agent'   => 'PuppetserverCaCli',
          'Content-Type' => 'application/json',
          'Accept'       => 'application/json'
        }

        attr_reader :store

        # Not all connections require a client cert to be present.
        # For example, when querying the status endpoint.
        def initialize(logger, settings, with_client_cert: true)
          @logger = logger
          @store = make_store(settings[:localcacert],
                              settings[:certificate_revocation],
                              settings[:hostcrl])

          if with_client_cert
            @cert = load_cert(settings[:hostcert])
            @key = load_key(settings[:hostprivkey])
          else
            @cert = nil
            @key = nil
          end
        end

        def load_cert(path)
          load_with_errors(path, 'hostcert') do |content|
            OpenSSL::X509::Certificate.new(content)
          end
        end

        def load_key(path)
          load_with_errors(path, 'hostprivkey') do |content|
            OpenSSL::PKey.read(content)
          end
        end

        # Takes an instance URL (defined lower in the file), and creates a
        # connection. The given block is passed our own Connection object.
        # The Connection object should have HTTP verbs defined on it that take
        # a body (and optional overrides). Returns whatever the block given returned.
        def with_connection(url, &block)
          request = ->(conn) { block.call(Connection.new(conn, url, @logger)) }

          begin
            Net::HTTP.start(url.host, url.port,
                            use_ssl: true, cert_store: @store,
                            cert: @cert, key: @key,
                            &request)
          rescue StandardError => e
            raise ConnectionFailed.create(e,
                    "Failed connecting to #{url.full_url}\n" +
                    "  Root cause: #{e.message}")
          end
        end

        private

       def load_with_errors(path, setting, &block)
          begin
            content = File.read(path)
            block.call(content)
          rescue Errno::ENOENT => e
            raise FileNotFound.create(e,
                    "Could not find '#{setting}' at '#{path}'")

          rescue OpenSSL::OpenSSLError => e
            raise InvalidX509Object.create(e,
                    "Could not parse '#{setting}' at '#{path}'.\n" +
                    "  OpenSSL returned: #{e.message}")
          end
       end

        # Helper class that wraps a Net::HTTP connection, a HttpClient::URL
        # and defines methods named after HTTP verbs that are called on the
        # saved connection, returning a Result.
        class Connection
          def initialize(net_http_connection, url_struct, logger)
            @conn = net_http_connection
            @url = url_struct
            @logger = logger
          end

          def get(url_overide = nil, headers = {})
            url = url_overide || @url
            headers = DEFAULT_HEADERS.merge(headers)

            @logger.debug("Making a GET request at #{url.full_url}")

            request = Net::HTTP::Get.new(url.to_uri, headers)
            result = @conn.request(request)
            Result.new(result.code, result.body)

          end

          def put(body, url_override = nil, headers = {})
            url = url_override || @url
            headers = DEFAULT_HEADERS.merge(headers)

            @logger.debug("Making a PUT request at #{url.full_url}")

            request = Net::HTTP::Put.new(url.to_uri, headers)
            request.body = body
            result = @conn.request(request)

            Result.new(result.code, result.body)
          end

          def delete(url_override = nil, headers = {})
            url = url_override || @url
            headers = DEFAULT_HEADERS.merge(headers)

            @logger.debug("Making a DELETE request at #{url.full_url}")

            result = @conn.request(Net::HTTP::Delete.new(url.to_uri, headers))

            Result.new(result.code, result.body)
          end
        end

        # Just provide the bits of Net::HTTPResponse we care about
        Result = Struct.new(:code, :body)

        # Like URI, but not... maybe of suspicious value
        URL = Struct.new(:protocol, :host, :port,
                         :endpoint, :version,
                         :resource_type, :resource_name, :query) do
                def full_url
                  url = protocol + '://' + host + ':' + port + '/' +
                        [endpoint, version, resource_type, resource_name].join('/')

                  url = url + "?" + URI.encode_www_form(query) unless query.nil? || query.empty?
                  return url
                end

                def to_uri
                  URI(full_url)
                end
              end

        def make_store(bundle, crl_usage, crls = nil)
          store = OpenSSL::X509::Store.new
          store.purpose = OpenSSL::X509::PURPOSE_ANY
          store.add_file(bundle)

          if crl_usage != :ignore

            flags = OpenSSL::X509::V_FLAG_CRL_CHECK
            if crl_usage == :chain
              flags |= OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
            end

            store.flags = flags
            delimiter = /-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m
            File.read(crls).scan(delimiter).each do |crl|
              store.add_crl(OpenSSL::X509::CRL.new(crl))
            end
          end

          store
        end

        # Queries the simple status endpoint for the status of the CA service.
        # Returns true if it receives back a response of "running", and false if
        # no connection can be made, or a different response is received.
        def self.check_server_online(settings, logger)
          status_url = URL.new('https', settings[:ca_server], settings[:ca_port], 'status', 'v1', 'simple', 'ca')
          begin
            # Generating certs offline is necessary if the server cert has been destroyed
            # or compromised. Since querying the status endpoint does not require a client cert, and
            # we commonly won't have one, don't require one for creating the connection.
            # Additionally, we want to ensure the server is stopped before migrating the CA dir to
            # avoid issues with writing to the CA dir and moving it.
            self.new(logger, settings, with_client_cert: false).with_connection(status_url) do |conn|
              result = conn.get
              if result.body == "running"
                logger.err "Puppetserver service is running. Please stop it before attempting to run this command."
                true
              else
                false
              end
            end
          rescue Puppetserver::Ca::ConnectionFailed => e
            if e.wrapped.is_a? Errno::ECONNREFUSED
              return false
            else
              raise e
            end
          end
        end

      end
    end
  end
end
