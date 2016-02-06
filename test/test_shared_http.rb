require 'minitest/autorun'
require './lib/yawast'
require './test/base'

class TestSharedHttp < Minitest::Test
  include TestBase

  def setup
    @uri = URI::Parser.new.parse 'http://www.apple.com/library/test/success.html'
  end

  def test_get_apple_success
    body = Yawast::Shared::Http.get @uri

    assert body.include?('Success'), 'Failed to receive "Success" message from Apple.com'
  end

  def test_status_apple_success
    status = Yawast::Shared::Http.get_status_code @uri

    assert_equal status, '200'
  end

  def test_status_apple_failure
    uri = @uri
    uri.path += '.404'
    status = Yawast::Shared::Http.get_status_code uri

    assert_equal status, '404'
  end

  def test_head_apple_success
    head = Yawast::Shared::Http.head @uri
    head.each do |k, v|
      if k.downcase == 'server'
        assert_equal v, 'Apache'
      end
    end
  end
end
