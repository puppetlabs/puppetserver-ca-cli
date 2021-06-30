# Puppet Server's CA CLI Library

This gem provides the functionality behind the Puppet Server CA interactions.
The actual CLI executable lives within the Puppet Server project.


## Installation

You may install it yourself with:

    $ gem install puppetserver-ca


## Usage

For initial CA setup, we provide two options. These need to be run before starting
Puppet Server for the first time.

To set up a default CA, with a self-signed root cert and an intermediate signing cert:
```
puppetserver ca setup
```

To import a custom CA:
```
puppetserver ca import --cert-bundle certs.pem --crl-chain crls.pem --private-key ca_key.pem
```

The remaining actions provided by this gem require a running Puppet Server, since
it primarily uses the CA's API endpoints to do its work. The following examples
assume that you are using the gem packaged within Puppet Server.

To sign a pending certificate request:
```
puppetserver ca sign --certname foo.example.com
```

To list certificates and CSRs:
```
puppetserver ca list --all
```

To revoke a signed certificate:
```
puppetserver ca revoke --certname foo.example.com
```

To revoke the cert and clean up all SSL files for a given certname:
```
puppetserver ca clean --certname foo.example.com
```

To create a new keypair and certificate for a certname:
```
puppetserver ca generate --certname foo.example.com
```

To enable verbose mode:
```
puppetserver ca --verbose <action>
```

For more details, see the help output:
```
puppetserver ca --help
```

This code in this project is licensed under the Apache Software License v2,
please see the included [License](https://github.com/puppetlabs/puppetserver-ca-cli/blob/main/LICENSE.md)
for more details.


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `bundle exec rake spec` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.

### Testing
To test your changes on a VM:
1. Build the gem with your changes: `gem build puppetserver-ca.gemspec`
1. Copy the gem to your VM: `scp puppetserver-ca-<version>.gem <your-vm>:.`
1. Install puppetserver (FOSS) by installing the relevant release package and then installing the puppetserver package. For example:
    ```
    $ wget http://nightlies.puppet.com/yum/puppet6-nightly-release-el-7.noarch.rpm
    $ rpm -i puppet6-nightly-release-el-7.noarch.rpm
    $ yum update
    $ yum install -y puppetserver
    ```
1. Restart your shell so that puppet's bin dir is on your $PATH: `exec bash`
1. Install the gem into puppet's gem directory using puppet's gem command:
    ```
    $ /opt/puppetlabs/puppet/bin/gem install --install-dir "/opt/puppetlabs/puppet/lib/ruby/vendor_gems" puppetserver-ca-<version>.gem
    ```
1. To confirm that installation was successful, run `puppetserver ca --help`

### Releasing
To release a new version, run the [release pipeline](https://jenkins-platform.delivery.puppetlabs.net/job/platform_puppetserver-ca_init-multijob_1.x/), which will bump the version, tag, build, and release the gem.


## Contributing & Support

Bug reports and feature requests are welcome in JIRA at
https://tickets.puppetlabs.com/projects/SERVER/issues.

For interactive questions feel free to post to #puppet or #puppet-dev on
Freenode, or the Puppet Community Slack channel.

Contributions are welcome at https://github.com/puppetlabs/puppetserver-ca-cli/pulls.
Contributors should both be sure to read the
[contributing document](https://github.com/puppetlabs/puppetserver-ca-cli/blob/main/CONTRIBUTING.md)
and sign the [contributor license agreement](https://cla.puppet.com/).

Everyone interacting with the project’s codebase, issue tracker, etc is expected
to follow the
[code of conduct](https://github.com/puppetlabs/puppetserver-ca-cli/blob/main/CODE_OF_CONDUCT.md).
