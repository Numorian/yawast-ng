require 'webrick'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestSSLLabsInfo < Minitest::Test
  include TestBase
  def test_info_msg_present
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/ssl_labs_info.json', 'api/v3/info', port

    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    body = Yawast::Scanner::Plugins::SSL::SSLLabs::Info.call_info uri
    msg = Yawast::Scanner::Plugins::SSL::SSLLabs::Info.extract_msg body

    assert msg != nil, 'SSL Labs: Info Msg Not Found'

    server.exit
  end
end