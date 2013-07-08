require 'minitest/autorun'
require './lib/yawast'
require './test/base'

class TestScannerCms < MiniTest::Unit::TestCase
  include TestBase

  def test_generator_tag_valid
    body = Yawast::Shared::Http.get URI::Parser.new.parse 'http://wordpress.org/news/'
    override_stdout
    Yawast::Scanner::Cms.get_generator body

    assert stdout_value.include?('WordPress'), "Unexpected generator tag: #{stdout_value}"

    restore_stdout
  end

  def test_generator_tag_invalid
    body = Yawast::Shared::Http.get URI::Parser.new.parse 'http://wordpress.org/'
    override_stdout
    Yawast::Scanner::Cms.get_generator body

    assert stdout_value == '', "Unexpected generator tag: #{stdout_value}"

    restore_stdout
  end
end
