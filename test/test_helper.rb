require 'simplecov'
require 'codeclimate-test-reporter'
require 'minitest/reporters'

SimpleCov.start
CodeClimate::TestReporter.start
MiniTest::Reporters.use!
