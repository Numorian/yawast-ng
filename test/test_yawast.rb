require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestYawast < Minitest::Test
  include TestBase

  def test_header
    override_stdout

    Yawast.header
    header = stdout_value
    assert header.include?('Copyright'), "Header not found in #{header}"
    assert header.include?(Yawast::VERSION), "Version not found in #{header}"

    restore_stdout
  end
end
