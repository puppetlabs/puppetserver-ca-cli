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

For more details, see the help output:
```
puppetserver ca --help
```

This code in this project is licensed under the Apache Software License v2,
please see the included [License](https://github.com/puppetlabs/puppetserver-ca-cli/blob/master/LICENSE.md)
for more details.


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `rake spec` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.

To release a new version, update the version number in `version.rb`, and then
speak with Release Engineering.


## Contributing & Support

Bug reports and feature requests are welcome in JIRA at
https://tickets.puppetlabs.com/projects/SERVER/issues.

For interactive questions feel free to post to #puppet or #puppet-dev on
Freenode, or the Puppet Community Slack channel.

Contributions are welcome at https://github.com/puppetlabs/puppetserver-ca-cli/pulls.
Contributors should both be sure to read the
[contributing document](https://github.com/puppetlabs/puppetserver-ca-cli/blob/master/CONTRIBUTING.md)
and sign the [contributor license agreement](https://cla.puppet.com/).

Everyone interacting with the project’s codebase, issue tracker, etc is expected
to follow the
[code of conduct](https://github.com/puppetlabs/puppetserver-ca-cli/blob/master/CODE_OF_CONDUCT.md).
