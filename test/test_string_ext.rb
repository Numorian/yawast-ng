require 'minitest/autorun'
require './lib/yawast'
require './test/base'

class TestStringExtensions < MiniTest::Unit::TestCase
  include TestBase

  def test_can_colorize_number
    assert_equal "\e[1mtest\e[0m", 'test'.colorize(1)
  end

  def test_cant_colorize_string
    assert_raises ArgumentError, 'color_code must be numeric' do
      'test'.colorize('test')
    end
  end

  def test_can_colorize_red
    assert_equal "\e[31mtest\e[0m", 'test'.red
  end

  def test_can_colorize_green
    assert_equal "\e[32mtest\e[0m", 'test'.green
  end

  def test_can_colorize_yellow
    assert_equal "\e[33mtest\e[0m", 'test'.yellow
  end

  def test_can_colorize_pink
    assert_equal "\e[35mtest\e[0m", 'test'.pink
  end

  def test_valid_number
    assert_equal '42'.is_number?, true
  end

  def test_invalid_number
    assert_equal '4two'.is_number?, false
  end
end
