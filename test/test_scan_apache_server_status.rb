require 'webrick'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestScannerApacheServerStatus < Minitest::Test
  include TestBase

  def test_server_status_present
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/apache_server_status.txt', 'server-status', port

    override_stdout
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    Yawast::Shared::Http.setup nil, nil
    Yawast::Scanner::Plugins::Servers::Apache.check_server_status uri

    assert stdout_value.include?('Apache Server Status page found'), 'Apache Server Status page warning not found'

    server.exit
    restore_stdout
  end
end
