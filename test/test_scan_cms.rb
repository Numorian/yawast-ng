require 'minitest/autorun'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestScannerCms < Minitest::Test
  include TestBase

  def test_generator_tag_valid
    body = File.read(File.dirname(__FILE__) + '/data/cms_wordpress_body.txt')
    override_stdout
    Yawast::Scanner::Cms.get_generator body

    assert stdout_value.include?('WordPress'), "Unexpected generator tag: #{stdout_value}"

    restore_stdout
  end

  def test_generator_tag_invalid
    body = File.read(File.dirname(__FILE__) + '/data/cms_none_body.txt')
    override_stdout
    Yawast::Scanner::Cms.get_generator body

    assert stdout_value == '', "Unexpected generator tag: #{stdout_value}"

    restore_stdout
  end
end
