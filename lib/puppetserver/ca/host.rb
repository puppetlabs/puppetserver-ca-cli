require 'openssl'
require 'fileutils'
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
      {:pp_uuid =>             "1.3.6.1.4.1.34380.1.1.1",
       :pp_instance_id =>      "1.3.6.1.4.1.34380.1.1.2",
       :pp_image_name =>       "1.3.6.1.4.1.34380.1.1.3",
       :pp_preshared_key =>    "1.3.6.1.4.1.34380.1.1.4",
       :pp_cost_center =>      "1.3.6.1.4.1.34380.1.1.5",
       :pp_product =>          "1.3.6.1.4.1.34380.1.1.6",
       :pp_project =>          "1.3.6.1.4.1.34380.1.1.7",
       :pp_application =>      "1.3.6.1.4.1.34380.1.1.8",
       :pp_service =>          "1.3.6.1.4.1.34380.1.1.9",
       :pp_employee =>         "1.3.6.1.4.1.34380.1.1.10",
       :pp_created_by =>       "1.3.6.1.4.1.34380.1.1.11",
       :pp_environment =>      "1.3.6.1.4.1.34380.1.1.12",
       :pp_role =>             "1.3.6.1.4.1.34380.1.1.13",
       :pp_software_version => "1.3.6.1.4.1.34380.1.1.14",
       :pp_department =>       "1.3.6.1.4.1.34380.1.1.15",
       :pp_cluster =>          "1.3.6.1.4.1.34380.1.1.16",
       :pp_provisioner =>      "1.3.6.1.4.1.34380.1.1.17",
       :pp_region =>           "1.3.6.1.4.1.34380.1.1.18",
       :pp_datacenter =>       "1.3.6.1.4.1.34380.1.1.19",
       :pp_zone =>             "1.3.6.1.4.1.34380.1.1.20",
       :pp_network =>          "1.3.6.1.4.1.34380.1.1.21",
       :pp_securitypolicy =>   "1.3.6.1.4.1.34380.1.1.22",
       :pp_cloudplatform =>    "1.3.6.1.4.1.34380.1.1.23",
       :pp_apptier =>          "1.3.6.1.4.1.34380.1.1.24",
       :pp_hostname =>         "1.3.6.1.4.1.34380.1.1.25",
       :pp_authorization =>    "1.3.6.1.4.1.34380.1.3.1",
       :pp_auth_role =>        "1.3.6.1.4.1.34380.1.3.13"}

      attr_reader :errors

      def initialize(digest)
        @digest = digest
        @errors = []
      end

      def create_private_key(keylength)
        OpenSSL::PKey::RSA.new(keylength)
      end

      def create_extension(extension_name, extension_value, critical = false)
        value = OpenSSL::ASN1::UTF8String.new(extension_value.to_s)
        # OpenSSL::X509::ExtensionFactory.new.create_extension(extension_name, value.to_der, critical)
        ext = OpenSSL::X509::Extension.new(extension_name, value.to_der, critical)
      end

      def create_csr(name:, key:, extensions: [], csr_attribute_path: '')
        csr = OpenSSL::X509::Request.new
        csr.public_key = key.public_key
        csr.subject = OpenSSL::X509::Name.new([["CN", name]])
        csr.version = 2
        csr.add_attribute(extension_attribute(extensions)) unless extensions.empty?
        add_custom_attributes_and_extensions(csr, csr_attribute_path) unless csr_attribute_path.empty?
        csr.sign(key, @digest) if @errors.empty?

        csr
      end

      def extension_attribute(extensions)
        seq = OpenSSL::ASN1::Sequence(extensions)
        ext_req = OpenSSL::ASN1::Set([seq])
        OpenSSL::X509::Attribute.new("extReq", ext_req)
      end

      # This takes all the custom_attributes and extension requests
      # from the csr_attributes.yaml and adds those to the csr
      def add_custom_attributes_and_extensions(csr, attributes_path)
        if File.exist?(attributes_path)
          custom_attributes = custom_csr_attributes(attributes_path)
          return unless custom_attributes
          add_csr_attributes(csr, custom_attributes.fetch('custom_attributes', {}))
          add_csr_extensions(csr, custom_attributes.fetch('extension_requests', {}))
        end
      end

      def custom_csr_attributes(csr_attributes_path)
        yaml = YAML.load_file(csr_attributes_path)
        if !yaml.is_a?(Hash)
          @errors << "invalid CSR attributes, expected instance of Hash, received instance of #{yaml.class}"
          return
        end
        yaml
      end

      def add_csr_attributes(csr, csr_attributes)
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

      def add_csr_extensions(csr, extension_requests)
        extensions = validated_extensions(extension_requests)
        unless extensions.empty?
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
            ext = create_extension(oid, value)
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
