require 'rake/testtask'

task :default => [:codeclimate]

task :test do
  #set this, so that we can modify behavior based on where's it's ran from
  ENV['FROM_RAKE'] = 'true'

  require File.join(File.dirname(__FILE__), 'test/test_helper')
  Dir.glob('./test/test_*.rb').each { |file| require file}

  require 'minitest'
  Minitest.run
end

task :codeclimate do
  Rake::Task['test'].execute

  require 'simplecov'
  require 'codeclimate-test-reporter'
end

task :submitcodeclimate do
  ENV['CODECLIMATE_REPO_TOKEN'] ='6fd9c710b9a6e0da2011c62b81075b9bd620200a2a400f4dbeab9c88829f4cb6'

  system 'codeclimate-test-reporter'
end
