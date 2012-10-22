require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new('spec')
task :build do
  load 'ext/extconf.rb'
  output = `make`
  raise output unless $? == 0
  File.rename('keychain.bundle', 'lib/keychain/keychain.bundle')
end

task :spec => :build

task :default => :spec