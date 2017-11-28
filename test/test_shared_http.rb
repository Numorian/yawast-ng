require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestSharedHttp < Minitest::Test
  include TestBase

  def setup
    @uri = URI::Parser.new.parse 'https://www.apple.com/library/test/success.html'
  end

  def test_setup
    override_stdout

    Yawast::Shared::Http.setup '127.0.0.1:8080', '1=2'

    assert stdout_value.include?('Using Proxy: 127.0.0.1:8080'), "Proxy notice not found: #{stdout_value}"
    assert stdout_value.include?('Using Cookie: 1=2'), "Cookie notice not found: #{stdout_value}"

    # run setup again to make sure things are reset
    Yawast::Shared::Http.setup nil, nil

    restore_stdout
  end

  def test_get_headers
    Yawast::Shared::Http.setup nil, '1=2'
    header = { 'Test' => 1 }

    ret = Yawast::Shared::Http.get_headers header

    assert ret != nil, 'Headers are nil'
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
