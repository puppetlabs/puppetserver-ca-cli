source "https://rubygems.org"

git_source(:github) {|repo_name| "https://github.com/#{repo_name}" }

# Specify your gem's dependencies in puppetserver-ca.gemspec
gemspec

gem 'hocon', '~> 1.2', require: false
gem 'rake', '~> 13.0', require: false
gem 'rspec', '~> 3.4', require: false

group(:development, optional: true) do
  gem 'pry'
  gem 'pry-byebug'
end
