require 'fileutils'
require 'openssl'
require 'yaml'

module Puppetserver
  module Ca
    class Host
      # Exclude OIDs that may conflict with how Puppet creates CSRs.
      #
      # We only have nominal support for Microsoft extension requests, but since we
      # ultimately respect that field when looking for extension requests in a CSR
      # we need to prevent that field from being written to directly.
      PRIVATE_CSR_ATTRIBUTES = [
        'extReq',   '1.2.840.113549.1.9.14',
        'msExtReq', '1.3.6.1.4.1.311.2.1.14',
      ]

      PRIVATE_EXTENSIONS = [
        'subjectAltName', '2.5.29.17',
      ]

      # A mapping of Puppet extension short names to their OIDs. These appear in
      # csr_attributes.yaml.
      PUPPET_SHORT_NAMES =
      {'pp_uuid' =>             "1.3.6.1.4.1.34380.1.1.1",
       'pp_instance_id' =>      "1.3.6.1.4.1.34380.1.1.2",
       'pp_image_name' =>       "1.3.6.1.4.1.34380.1.1.3",
       'pp_preshared_key'=>    "1.3.6.1.4.1.34380.1.1.4",
       'pp_cost_center' =>      "1.3.6.1.4.1.34380.1.1.5",
       'pp_product' =>          "1.3.6.1.4.1.34380.1.1.6",
       'pp_project' =>          "1.3.6.1.4.1.34380.1.1.7",
       'pp_application' =>      "1.3.6.1.4.1.34380.1.1.8",
       'pp_service'=>          "1.3.6.1.4.1.34380.1.1.9",
       'pp_employee' =>         "1.3.6.1.4.1.34380.1.1.10",
       'pp_created_by' =>       "1.3.6.1.4.1.34380.1.1.11",
       'pp_environment' =>      "1.3.6.1.4.1.34380.1.1.12",
       'pp_role' =>             "1.3.6.1.4.1.34380.1.1.13",
       'pp_software_version' => "1.3.6.1.4.1.34380.1.1.14",
       'pp_department' =>       "1.3.6.1.4.1.34380.1.1.15",
       'pp_cluster' =>          "1.3.6.1.4.1.34380.1.1.16",
       'pp_provisioner' =>      "1.3.6.1.4.1.34380.1.1.17",
       'pp_region' =>           "1.3.6.1.4.1.34380.1.1.18",
       'pp_datacenter' =>       "1.3.6.1.4.1.34380.1.1.19",
       'pp_zone' =>             "1.3.6.1.4.1.34380.1.1.20",
       'pp_network' =>          "1.3.6.1.4.1.34380.1.1.21",
       'pp_securitypolicy' =>   "1.3.6.1.4.1.34380.1.1.22",
       'pp_cloudplatform' =>    "1.3.6.1.4.1.34380.1.1.23",
       'pp_apptier' =>          "1.3.6.1.4.1.34380.1.1.24",
       'pp_hostname' =>         "1.3.6.1.4.1.34380.1.1.25",
       'pp_owner' =>            "1.3.6.1.4.1.34380.1.1.26",
       'pp_authorization' =>    "1.3.6.1.4.1.34380.1.3.1",
       'pp_auth_role' =>        "1.3.6.1.4.1.34380.1.3.13"}

      attr_reader :errors

      def initialize(digest)
        @digest = digest
        @errors = []
      end

      # If both the private and public keys exist for a server then we want
      # to honor them here, if only one key exists we want to surface an error,
      # and if neither exist we generate a new key. This logic is necessary for
      # proper bootstrapping for certain server workflows.
      def create_private_key(keylength, private_path = '', public_path = '')
        if File.exist?(private_path) && File.exist?(public_path)
          return OpenSSL::PKey.read(File.read(private_path))
        elsif !File.exist?(private_path) && !File.exist?(public_path)
          return OpenSSL::PKey::RSA.new(keylength)
        elsif !File.exist?(private_path) && File.exist?(public_path)
          @errors << "Missing private key to match public key at #{public_path}"
          return nil
        elsif File.exist?(private_path) && !File.exist?(public_path)
          @errors << "Missing public key to match private key at #{private_path}"
          return nil
        end
      end

      def create_csr(name:, key:, cli_extensions: [], csr_attributes_path: '')
        csr = OpenSSL::X509::Request.new
        csr.public_key = key.public_key
        csr.subject = OpenSSL::X509::Name.new([["CN", name]])

        custom_attributes = get_custom_attributes(csr_attributes_path)
        extension_requests = get_extension_requests(csr_attributes_path)

        add_csr_attributes(csr, custom_attributes)
        add_csr_extensions(csr, extension_requests, cli_extensions)

        csr.sign(key, @digest) if @errors.empty?

        csr
      end

      def extension_attribute(extensions)
        seq = OpenSSL::ASN1::Sequence(extensions)
        ext_req = OpenSSL::ASN1::Set([seq])
        OpenSSL::X509::Attribute.new("extReq", ext_req)
      end

      def get_custom_attributes(attributes_path)
        if csr_attributes = load_csr_attributes(attributes_path)
          csr_attributes['custom_attributes']
        end
      end

      def get_extension_requests(attributes_path)
        if csr_attributes = load_csr_attributes(attributes_path)
          csr_attributes['extension_requests']
        end
      end

      # This loads all the custom_attributes and extension requests
      # from the csr_attributes.yaml
      def load_csr_attributes(attributes_path)
        @custom_csr_attributes ||=
        if File.exist?(attributes_path)
          yaml = YAML.load_file(attributes_path)
          if !yaml.is_a?(Hash)
            @errors << "Invalid CSR attributes, expected instance of Hash, received instance of #{yaml.class}"
            return
          end
          yaml
        end
      end

      def add_csr_attributes(csr, csr_attributes)
        if csr_attributes
          csr_attributes.each do |oid, value|
            begin
              if PRIVATE_CSR_ATTRIBUTES.include? oid
                @errors << "Cannot specify CSR attribute #{oid}: conflicts with internally used CSR attribute"
              end
              oid = PUPPET_SHORT_NAMES[oid] || oid
              encoded = OpenSSL::ASN1::PrintableString.new(value.to_s)
              attr_set = OpenSSL::ASN1::Set.new([encoded])

              csr.add_attribute(OpenSSL::X509::Attribute.new(oid, attr_set))
            rescue OpenSSL::X509::AttributeError => e
              @errors << "Cannot create CSR with attribute #{oid}: #{e.message}"
            end
          end
        end
      end

      def add_csr_extensions(csr, extension_requests, cli_extensions)
        if extension_requests || cli_extensions.any?
          extensions =
            if extension_requests
              validated_extensions(extension_requests) + cli_extensions
            else
              cli_extensions
            end
          csr.add_attribute(extension_attribute(extensions))
        end
      end

      def validated_extensions(extension_requests)
        extensions = []
        extension_requests.each do |oid, value|
          begin
            if PRIVATE_EXTENSIONS.include? oid
              @errors << "Cannot specify CSR extension request #{oid}: conflicts with internally used extension request"
            end
            oid = PUPPET_SHORT_NAMES[oid] || oid
            ext = OpenSSL::X509::Extension.new(oid, OpenSSL::ASN1::UTF8String.new(value.to_s).to_der, false)
            extensions << ext
          rescue OpenSSL::X509::ExtensionError => e
            @errors << "Cannot create CSR with extension request #{oid}: #{e.message}"
          end
        end
        extensions
      end
    end
  end
end
