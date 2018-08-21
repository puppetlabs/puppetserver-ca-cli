require 'puppetserver/ca/utils/http_client'

require 'json'

module Puppetserver
  module Ca
    class CertificateAuthority

      include Puppetserver::Ca::Utils

      REVOKE_BODY = JSON.dump({ desired_state: 'revoked' })
      SIGN_BODY =   JSON.dump({ desired_state: 'signed' })

      def initialize(logger, settings)
        @logger = logger
        @client = HttpClient.new(settings)
        @ca_server = settings[:ca_server]
        @ca_port = settings[:ca_port]
      end

      # Returns a URI-like wrapper around CA specific urls
      def make_ca_url(resource_type = nil, certname = nil)
        HttpClient::URL.new('https', @ca_server, @ca_port, 'puppet-ca', 'v1', resource_type, certname)
      end

      def sign_certs(certnames)
        put(certnames,
            resource_type: 'certificate_status',
            body: SIGN_BODY,
            type: :sign)
      end

      def revoke_certs(certnames)
        put(certnames,
            resource_type: 'certificate_status',
            body: REVOKE_BODY,
            type: :revoke)
      end

      def submit_certificate_request(certname, csr)
        put([certname],
            resource_type: 'certificate_request',
            body: csr.to_pem,
            headers: {'Content-Type' => 'text/plain'},
            type: :submit)
      end

      # Make an HTTP PUT request to CA
      # @param resource_type [String] the resource type of url
      # @param certnames [Array] array of certnames
      # @param body [JSON/String] body of the put request
      # @param type [Symbol] type of error processing to perform on result
      # @return [Boolean] whether all requests were successful
      def put(certnames, resource_type:, body:, type:, headers: nil)
        url = make_ca_url(resource_type)
        results = @client.with_connection(url) do |connection|
          certnames.map do |certname|
            url.resource_name = certname
            result = connection.put(body, url, headers)
            process_results(type, certname, result)
          end
        end

        results.all?
      end

      # logs the action and returns true/false for success
      def process_results(type, certname, result)
        case type
        when :sign
          case result.code
          when '204'
            @logger.inform "Successfully signed certificate request for #{certname}"
            return true
          when '404'
            @logger.err 'Error:'
            @logger.err "    Could not find certificate request for #{certname}"
            return false
          else
            @logger.err 'Error:'
            @logger.err "    When signing request submitted for #{certname}:"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return false
          end
        when :revoke
          case result.code
          when '200', '204'
            @logger.inform "Revoked certificate for #{certname}"
            return true
          when '404'
            @logger.err 'Error:'
            @logger.err "    Could not find certificate for #{certname}"
            return false
          else
            @logger.err 'Error:'
            @logger.err "    When revoking #{certname} received:"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return false
          end
        when :submit
          case result.code
          when '200', '204'
            @logger.inform "Successfully submitted certificate request for #{certname}"
            return true
          else
            @logger.err 'Error:'
            @logger.err "    When certificate request submitted for #{certname}:"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return false
          end
        end
      end

      # Make an HTTP request to CA to clean the named certificates
      # @param certnames [Array] the name of the certificate(s) to have cleaned
      # @return [Boolean] whether all certificate cleaning and revocation was successful
      def clean_certs(certnames)
        url = make_ca_url('certificate_status')

        results = @client.with_connection(url) do |connection|
          certnames.map do |certname|
            url.resource_name = certname
            revoke_result = connection.put(REVOKE_BODY, url)
            revoked = check_revocation(certname, revoke_result)

            cleaned = nil
            unless revoked == :error
              clean_result = connection.delete(url)
              cleaned = check_clean(certname, clean_result)
            end

            cleaned == :success && [:success, :not_found].include?(revoked)
          end
        end

        return results.all?
      end

      # possibly logs the action, always returns a status symbol 👑
      def check_revocation(certname, result)
        case result.code
        when '200', '204'
          @logger.inform "Revoked certificate for #{certname}"
          return :success
        when '404'
          return :not_found
        else
          @logger.err 'Error:'
          @logger.err "    Failed revoking certificate for #{certname}"
          @logger.err "    Received code: #{result.code}, body: #{result.body}"
          return :error
        end
      end

      # logs the action and returns a status symbol 👑
      def check_clean(certname, result)
        case result.code
        when '200', '204'
          @logger.inform "Cleaned files related to #{certname}"
          return :success
        when '404'
          @logger.err 'Error:'
          @logger.err "    Could not find files for #{certname}"
          return :not_found
        else
          @logger.err 'Error:'
          @logger.err "    When cleaning #{certname} received:"
          @logger.err "      code: #{result.code}"
          @logger.err "      body: #{result.body.to_s}" if result.body
          return :error
        end
      end

      # Returns nil for errors, else the result of the GET request
      def get_certificate_statuses
        result = get('certificate_statuses', 'any_key')

        unless result.code == '200'
          @logger.err 'Error:'
          @logger.err "    code: #{result.code}"
          @logger.err "    body: #{result.body}" if result.body
          return nil
        end

        result
      end

      # Returns nil for errors, else the result of the GET request
      def get_certificate(certname)
        result = get('certificate', certname)

        case result.code
        when '200'
          return result
        when '404'
          @logger.err 'Error:'
          @logger.err "    Signed certificate #{certname} could not be found on the CA"
          return nil
        else
          @logger.err 'Error:'
          @logger.err "    When download requested for certificate #{certname}:"
          @logger.err "      code: #{result.code}"
          @logger.err "      body: #{result.body.to_s}" if result.body
          return nil
        end
      end

      # Make an HTTP GET request to CA
      # @param resource_type [String] the resource type of url
      # @param resource_name [String] the resource name of url
      # @return [Struct] an instance of the Result struct with :code, :body
      def get(resource_type, resource_name)
        url = make_ca_url(resource_type, resource_name)
        @client.with_connection(url) do |connection|
          connection.get(url)
        end
      end
    end
  end
end
