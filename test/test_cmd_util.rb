require 'minitest/autorun'
require './lib/yawast'
require './test/base'

class TestCommandUtils < MiniTest::Unit::TestCase
  include TestBase

  def test_valid_url
    args = ['http://www.apple.com']
    uri = Yawast::Commands::Utils.extract_uri args
    assert_equal uri.to_s, 'http://www.apple.com/'
  end

  def test_invalid_url
    args = ['xxx:\invalid']

    assert_raises URI::InvalidURIError do
      Yawast::Commands::Utils.extract_uri args
    end
  end

  def test_unresolvable_url
    args = ['http://www.gjhgjhbmnbmnvgccf.com']

    assert_raises ArgumentError do
      Yawast::Commands::Utils.extract_uri args
    end
  end
end
