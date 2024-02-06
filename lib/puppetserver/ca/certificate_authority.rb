require 'json'

require 'puppetserver/ca/utils/http_client'

module Puppetserver
  module Ca
    class CertificateAuthority

      include Puppetserver::Ca::Utils

      # Taken from puppet/lib/settings/duration_settings.rb
      UNITMAP = {
        # 365 days isn't technically a year, but is sufficient for most purposes
        "y" => 365 * 24 * 60 * 60,
        "d" => 24 * 60 * 60,
        "h" => 60 * 60,
        "m" => 60,
        "s" => 1
      }

      REVOKE_BODY = JSON.dump({ desired_state: 'revoked' })

      def initialize(logger, settings)
        @logger = logger
        @client = HttpClient.new(@logger, settings)
        @ca_server = settings[:ca_server]
        @ca_port = settings[:ca_port]
      end

      def server_has_bulk_signing_endpoints
        url = HttpClient::URL.new('https', @ca_server, @ca_port, 'status', 'v1', 'services')
        result = @client.with_connection(url) do |connection|
          connection.get(url)
        end
        version = process_results(:server_version, nil, result)
        return version >= Gem::Version.new('8.4.0')
      end

      def worst_result(previous_result, current_result)
        %i{success invalid not_found error}.each do |state|
          if previous_result == state
            return current_result
          elsif current_result == state
            return previous_result
          else
            next
          end
        end
      end

      # Returns a URI-like wrapper around CA specific urls
      def make_ca_url(resource_type = nil, certname = nil, query = {})
        HttpClient::URL.new('https', @ca_server, @ca_port, 'puppet-ca', 'v1', resource_type, certname, query)
      end

      def process_ttl_input(ttl)
        match = /^(\d+)(s|m|h|d|y)?$/.match(ttl)
        if match
          if match[2]
            match[1].to_i * UNITMAP[match[2]].to_i
          else
            ttl
          end
        else
          @logger.err "Error:"
          @logger.err " '#{ttl}' is an invalid ttl value"
          @logger.err "Value should match regex \"^(\d+)(s|m|h|d|y)?$\""
          nil
        end
      end

      def sign_all
        return post(resource_type: 'sign',
          resource_name: 'all',
          body: '{}',
          type: :sign_all)
      end

      def sign_bulk(certnames)
        return post(resource_type: 'sign',
          body: "{\"certnames\":#{certnames}}",
          type: :sign_bulk
        )
      end

      def sign_certs(certnames, ttl=nil)
        results = []
        if ttl
          lifetime = process_ttl_input(ttl)
          return false if lifetime.nil?
          body = JSON.dump({ desired_state: 'signed', cert_ttl: lifetime})
          results = put(certnames,
            resource_type: 'certificate_status',
            body: body,
            type: :sign)
        else
          results = put(certnames,
                        resource_type: 'certificate_status',
                        body: JSON.dump({ desired_state: 'signed' }),
                        type: :sign)
        end


        results.all? { |result| result == :success }
      end

      def revoke_certs(certnames)
        results = put(certnames,
                    resource_type: 'certificate_status',
                    body: REVOKE_BODY,
                    type: :revoke)

        results.reduce { |prev, curr| worst_result(prev, curr) }
      end

      def submit_certificate_request(certname, csr)
        results = put([certname],
                    resource_type: 'certificate_request',
                    body: csr.to_pem,
                    headers: {'Content-Type' => 'text/plain'},
                    type: :submit)

        results.all? { |result| result == :success }
      end

      # Make an HTTP PUT request to CA
      # @param resource_type [String] the resource type of url
      # @param certnames [Array] array of certnames
      # @param body [JSON/String] body of the put request
      # @param type [Symbol] type of error processing to perform on result
      # @return [Boolean] whether all requests were successful
      def put(certnames, resource_type:, body:, type:, headers: {})
        url = make_ca_url(resource_type)
        results = @client.with_connection(url) do |connection|
          certnames.map do |certname|
            url.resource_name = certname
            result = connection.put(body, url, headers)
            process_results(type, certname, result)
          end
        end
      end

      # Make an HTTP POST request to CA
      # @param endpoint [String] the endpoint to post to for the url
      # @param body [JSON/String] body of the post request
      # @param type [Symbol] type of error processing to perform on result
      # @return [Boolean] whether all requests were successful
      def post(resource_type:, resource_name: nil, body:, type:, headers: {})
        url = make_ca_url(resource_type, resource_name)
        results = @client.with_connection(url) do |connection|
          result = connection.post(body, url, headers)
          process_results(type, nil, result)
        end
      end

      # Handle the result data from the /sign and /sign/all endpoints
      def process_bulk_sign_result_data(result)
        data = JSON.parse(result.body)
        signed = data.dig('signed') || []
        no_csr = data.dig('no-csr') || []
        signing_errors = data.dig('signing-errors') || []

        if !signed.empty?
          @logger.inform "Successfully signed the following certificate requests:"
          signed.each { |s| @logger.inform "  #{s}" }
        end

        @logger.err 'Error:' if !no_csr.empty? || !signing_errors.empty?
        if !no_csr.empty?
          @logger.err '    No certificate request found for the following nodes when attempting to sign:'
          no_csr.each { |s| @logger.err "      #{s}" }
        end
        if !signing_errors.empty?
          @logger.err '    Error encountered when attempting to sign the certificate request for the following nodes:'
          signing_errors.each { |s| @logger.err "      #{s}" }
        end
        if no_csr.empty? && signing_errors.empty?
          @logger.err 'No waiting certificate requests to sign.' if signed.empty?
          return signed.empty? ? :no_requests : :success
        else
          return :error
        end
      end

      # logs the action and returns true/false for success
      def process_results(type, certname, result)
        case type
        when :sign
          case result.code
          when '204'
            @logger.inform "Successfully signed certificate request for #{certname}"
            return :success
          when '404'
            @logger.err 'Error:'
            @logger.err "    Could not find certificate request for #{certname}"
            return :not_found
          else
            @logger.err 'Error:'
            @logger.err "    When attempting to sign certificate request '#{certname}', received"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return :error
          end
        when :sign_all
          if result.code == '200'
            if !result.body
              @logger.err 'Error:'
              @logger.err '    Response from /sign/all endpoint did not include a body. Unable to verify certificate requests were signed.'
              return :error
            end
            begin
              return process_bulk_sign_result_data(result)
            rescue JSON::ParserError
              @logger.err 'Error:'
              @logger.err '    Unable to parse the response from the /sign/all endpoint.'
              @logger.err "      body #{result.body.to_s}"
              return :error
            end
          else
            @logger.err 'Error:'
            @logger.err '    When attempting to sign all certificate requests, received:'
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return :error
          end
        when :sign_bulk
          if result.code == '200'
            if !result.body
              @logger.err 'Error:'
              @logger.err '    Response from /sign endpoint did not include a body. Unable to verify certificate requests were signed.'
              return :error
            end
            begin
              return process_bulk_sign_result_data(result)
            rescue JSON::ParserError
              @logger.err 'Error:'
              @logger.err '    Unable to parse the response from the /sign endpoint.'
              @logger.err "      body #{result.body.to_s}"
              return :error
            end
          else
            @logger.err 'Error:'
            @logger.err '    When attempting to sign certificate requests, received:'
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return :error
          end
        when :revoke
          case result.code
          when '200', '204'
            @logger.inform "Certificate for #{certname} has been revoked"
            return :success
          when '404'
            @logger.err 'Error:'
            @logger.err "    Could not find certificate for #{certname}"
            return :not_found
          when '409'
            @logger.err 'Error:'
            @logger.err "    Could not revoke unsigned csr for #{certname}"
            return :invalid
          else
            @logger.err 'Error:'
            @logger.err "    When attempting to revoke certificate '#{certname}', received:"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return :error
          end
        when :submit
          case result.code
          when '200', '204'
            @logger.inform "Successfully submitted certificate request for #{certname}"
            return :success
          else
            @logger.err 'Error:'
            @logger.err "    When attempting to submit certificate request for '#{certname}', received:"
            @logger.err "      code: #{result.code}"
            @logger.err "      body: #{result.body.to_s}" if result.body
            return :error
          end
        when :server_version
          if result.code == '200' && result.body
            begin
              data = JSON.parse(result.body)
              version_str = data.dig('ca','service_version')
              return Gem::Version.new(version_str.match('^\d+\.\d+\.\d+')[0])
            rescue JSON::ParserError, NoMethodError
              # If we get bad JSON, version_str is nil, or the matcher doesn't match,
              # fall through to returning a version of 0.
            end
          end
          @logger.debug 'Could not detect server version. Defaulting to legacy signing endpoints.'
          return Gem::Version.new(0)
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

            if revoked == :error || cleaned != :success
              :error

            # If we get passed the first conditional we know that
            # cleaned must == :success and revoked must be one of
            # :invalid, :not_found, or :success. We'll treat both
            # :not_found and :success of revocation here as successes.
            # However we'll treat invalid's specially.
            elsif revoked == :invalid
              :invalid

            else
              :success
            end
          end
        end

        return results.reduce {|prev, curr| worst_result(prev, curr) }
      end

      # possibly logs the action, always returns a status symbol 👑
      def check_revocation(certname, result)
        case result.code
        when '200', '204'
          @logger.inform "Certificate for #{certname} has been revoked"
          return :success
        when '409'
          return :invalid
        when '404'
          return :not_found
        else
          @logger.err 'Error:'
          @logger.err "    When attempting to revoke certificate '#{certname}', received:"
          @logger.err "      code: #{result.code}"
          @logger.err "      body: #{result.body.to_s}" if result.body
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
          @logger.err "    Could not find files to clean for #{certname}"
          return :not_found
        else
          @logger.err 'Error:'
          @logger.err "    When attempting to clean certificate '#{certname}', received:"
          @logger.err "      code: #{result.code}"
          @logger.err "      body: #{result.body.to_s}" if result.body
          return :error
        end
      end

      # Returns nil for errors, else the result of the GET request
      def get_certificate_statuses(query = {})
        result = get('certificate_statuses', 'any_key', query)

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
          @logger.err "    When attempting to download certificate '#{certname}', received:"
          @logger.err "      code: #{result.code}"
          @logger.err "      body: #{result.body.to_s}" if result.body
          return nil
        end
      end

      # Make an HTTP GET request to CA
      # @param resource_type [String] the resource type of url
      # @param resource_name [String] the resource name of url
      # @return [Struct] an instance of the Result struct with :code, :body
      def get(resource_type, resource_name, query = {})
        url = make_ca_url(resource_type, resource_name, query)
        @client.with_connection(url) do |connection|
          connection.get(url)
        end
      end
    end
  end
end
