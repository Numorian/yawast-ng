require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestInternalSSL < Minitest::Test
  include TestBase

  def test_internalssl_ss_cert
    override_stdout

    uri = URI.parse 'https://self-signed.badssl.com/'
    Yawast::Scanner::Ssl.info uri, false, false

    assert stdout_value.include?('Certificate Is Self-Singed'), 'self-signed certificate warning not found'
    restore_stdout
  end
end
