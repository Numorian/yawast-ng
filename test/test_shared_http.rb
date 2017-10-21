require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestSharedHttp < Minitest::Test
  include TestBase

  def setup
    @uri = URI::Parser.new.parse 'https://www.apple.com/library/test/success.html'
  end

  def test_get_apple_success
    Yawast::Shared::Http.setup nil, nil
    body = Yawast::Shared::Http.get @uri

    assert body.include?('Success'), 'Failed to receive "Success" message from Apple.com'
  end

  def test_status_apple_success
    Yawast::Shared::Http.setup nil, nil
    status = Yawast::Shared::Http.get_status_code @uri

    assert_equal status, '200'
  end

  def test_status_apple_failure
    uri = @uri
    uri.path += '.404'

    Yawast::Shared::Http.setup nil, nil
    status = Yawast::Shared::Http.get_status_code uri

    assert_equal status, '404'
  end

  def test_head_apple_success
    Yawast::Shared::Http.setup nil, nil
    head = Yawast::Shared::Http.head @uri

    head.each do |k, v|
      if k.downcase == 'server'
        assert_equal v, 'Apache'
      end
    end
  end
end
