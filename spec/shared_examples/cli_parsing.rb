RSpec.shared_examples 'basic cli args' do |action, usage|
  it 'responds to a --help flag' do
    args = [action, '--help'].compact
    exit_code = Puppetserver::Ca::Cli.run(args, stdout, stderr)
    expect(stdout.string).to match(usage)
    expect(exit_code).to be 0
  end

  it 'prints the help output & returns 1 if no input is given' do
    args = [action].compact
    exit_code = Puppetserver::Ca::Cli.run(args, stdout, stderr)
    expect(stderr.string).to match(usage)
    expect(exit_code).to be 1
  end

  it 'prints the version' do
    semverish = /\d+\.\d+\.\d+(-[a-z0-9._-]+)?/
    args = [action, '--version'].compact
    first_code = Puppetserver::Ca::Cli.run(args, stdout, stderr)
    expect(stdout.string).to match(semverish)
    expect(stderr.string).to be_empty
    expect(first_code).to be 0
  end
end
