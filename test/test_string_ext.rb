require 'minitest/autorun'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestStringExtensions < Minitest::Test
  include TestBase

  def test_valid_number
    assert_equal '42'.is_number?, true
  end

  def test_invalid_number
    assert_equal '4two'.is_number?, false
  end
end
