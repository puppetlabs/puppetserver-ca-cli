require 'openssl'
require 'net/https'

module Puppetserver
  module Utils
    # Utilities for doing HTTPS against the CA that wraps Net::HTTP constructs
    module HttpUtilities

      HEADERS = {
        'User-Agent'   => 'PuppetserverCaCli',
        'Content-Type' => 'application/json',
        'Accept'       => 'application/json'
      }

      # Returns a URI-like wrapper around CA specific urls
      def self.make_ca_url(host, port, resource_type = nil, certname = nil)
        URL.new('https', host, port, 'puppet-ca', 'v1', resource_type, certname)
      end

      # Takes an instance URL (defined lower in the file), a
      # PuppetConfig#settings hash and creates a connection, the given block
      # is passed our own Connection object. The Connection object should
      # have HTTP verbs defined on it that take a body (and optional
      # overrides). Returns whatever the block given returned.
      def self.with_connection(url, settings, &block)
        store = make_store(settings[:cacert],
                           settings[:hostcert],
                           settings[:hostcrl])

        request = ->(conn) { block.call(Connection.new(conn, url)) }

        Net::HTTP.start(url.host, url.port,
                        use_ssl: true, cert_store: store,
                        &request)
      end


    private

      # Helper class that wraps a Net::HTTP connection, a HttpUtilities::URL
      # and defines methods named after HTTP verbs that are called on the
      # saved connection, returning a Result.
      class Connection
        def initialize(net_http_connection, url_struct)
          @conn = net_http_connection
          @url = url_struct
        end

        def put(body, url_override = nil)
          url = url_override || @url

          request = Net::HTTP::Put.new(url.to_uri, HEADERS)
          request.body = body
          result = @conn.request(request)

          Result.new(result.code, result.body)
        end
      end

      # Just provide the bits of Net::HTTPResponse we care about
      Result = Struct.new(:code, :body)

      # Like URI, but not... maybe of suspicious value
      URL = Struct.new(:protocol, :host, :port,
                       :endpoint, :version,
                       :resource_type, :resource_name) do
              def full_url
                protocol + '://' + host + ':' + port + '/' +
                [endpoint, version, resource_type, resource_name].join('/')
              end

              def to_uri
                URI(full_url)
              end
            end

      def self.make_store(cacert, cert, crl)
        store = OpenSSL::X509::Store.new
        store.add_file(cacert)
        store.add_file(cert)
        store.add_file(crl)

        store
      end
    end
  end
end

