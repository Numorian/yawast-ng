require 'minitest/autorun'
require './lib/yawast'
require './test/base'

class TestYawast < Minitest::Test
  include TestBase

  def test_header
    override_stdout

    Yawast.header
    header = stdout_value
    assert header.include?('Copyright'), 'Header not found'

    restore_stdout
  end
end
