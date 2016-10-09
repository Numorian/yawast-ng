require 'rake/testtask'

task :default => [:codeclimate]

task :test do
  require File.join(File.dirname(__FILE__), 'test/test_helper')
  Dir.glob('./test/test_*.rb').each { |file| require file}

  require 'minitest'
  Minitest.run
end

task :codeclimate do
  Rake::Task['test'].execute

  require 'simplecov'
  require 'codeclimate-test-reporter'

  ENV['CODECLIMATE_REPO_TOKEN'] ='6fd9c710b9a6e0da2011c62b81075b9bd620200a2a400f4dbeab9c88829f4cb6'

  SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter.new([
    SimpleCov::Formatter::HTMLFormatter,
    CodeClimate::TestReporter::Formatter
  ])

  CodeClimate::TestReporter::Formatter.new.format(SimpleCov.result)
end
