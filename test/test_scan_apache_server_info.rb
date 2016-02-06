require 'minitest/autorun'
require 'webrick'
require './lib/yawast'
require './test/base'

class TestScannerApacheServerInfo < Minitest::Test
  include TestBase

  def test_server_info_present
    server = start_web_server 'test/data/apache_server_info.txt', 'server-info'

    override_stdout
    uri = Yawast::Commands::Utils.extract_uri(['http://localhost:1234'])
    Yawast::Scanner::Apache.check_server_info uri

    assert stdout_value.include?('Apache Server Info page found'), 'Apache Server Info page warning not found'

    server.exit
    restore_stdout
  end
end
