require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestSharedHttp < Minitest::Test
  include TestBase

  def test_check_tdes
    override_stdout

    res = Yawast::Scanner::Plugins::SSL::Sweet32.check_tdes

    assert stdout_value.include?('OpenSSL supports 3DES'), "Header line not found in #{stdout_value}"
    assert res, '3DES support check failed'

    restore_stdout
  end

  def test_session_count
    override_stdout

    uri = URI::Parser.new.parse 'https://3des.badssl.com/'
    Yawast::Scanner::Plugins::SSL::Sweet32.get_tdes_session_msg_count uri, 1

    assert stdout_value.include?('Connection not terminated after'), "SWEET32 warning not found in #{stdout_value}"

    restore_stdout
  end

end
