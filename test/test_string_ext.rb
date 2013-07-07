require 'minitest/autorun'
require './lib/string_ext'

class TestStringExtensions < Minitest::Test
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
end
