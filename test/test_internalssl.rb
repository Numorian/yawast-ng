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

  def test_internalssl_known_suite
    override_stdout

    uri = URI.parse 'https://self-signed.badssl.com/'
    Yawast::Scanner::Ssl.info uri, true, false

    #HACK: This is an awful test, as it depends on the configuration of the server above, so could
    # easily break if they make any changes, and only tests for a single value, but it's better than nothing.
    # The other awful thing is that this is slow, and may take 60 seconds or more to complete.
    assert stdout_value.include?('Cipher: AES256-SHA'), 'known cipher suite not found in output'

    restore_stdout
  end
end
