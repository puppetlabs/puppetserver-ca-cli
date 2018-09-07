
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "puppetserver/ca/version"

Gem::Specification.new do |spec|
  spec.name          = "puppetserver-ca"
  spec.version       = Puppetserver::Ca::VERSION
  spec.authors       = ["Puppet, Inc."]
  spec.email         = ["release@puppet.com"]
  spec.license       = "Apache-2.0"

  spec.summary       = %q{A simple CLI tool for interacting with Puppet Server's Certificate Authority}
  spec.homepage      = "https://github.com/puppetlabs/puppetserver-ca-cli/"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "facter", [">= 2.0.1", "< 4"]

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
