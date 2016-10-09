require 'minitest/reporters'
require 'coveralls'
require "codeclimate-test-reporter"

CodeClimate::TestReporter.start
MiniTest::Reporters.use!
Coveralls.wear!
