require 'simplecov'

dir = File.join(File.dirname(__FILE__), '../coverage')
SimpleCov.coverage_dir(dir)
SimpleCov.start

require 'minitest/reporters'
MiniTest::Reporters.use!
