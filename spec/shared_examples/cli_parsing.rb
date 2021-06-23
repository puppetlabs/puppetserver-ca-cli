RSpec.shared_examples 'basic cli args' do |action, usage|
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }

  it 'responds to a --help flag' do
    args = [action, '--help'].compact
    exit_code = Puppetserver::Ca::Cli.run(args, stdout, stderr)
    expect(stdout.string).to match(usage)
    expect(exit_code).to be 0
  end

  it 'prints the version' do
    semverish = /\d+\.\d+\.\d+(-[a-z0-9._-]+)?/
    args = [action, '--version'].compact
    first_code = Puppetserver::Ca::Cli.run(args, stdout, stderr)
    expect(stdout.string).to match(semverish)
    expect(stderr.string).to be_empty
    expect(first_code).to be 0
  end

  it 'raise the verbose flag' do
    args = ['--verbose', action].compact
    _,parsed,_ = Puppetserver::Ca::Cli.parse_general_inputs(args)
    expect(parsed['verbose']).to be true
    logger = Puppetserver::Ca::Logger.new(:debug, stdout, stderr)
    expect(logger.level).to be Puppetserver::Ca::Logger::LEVELS[:debug]
  end
end
