require 'webrick'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestSSLLabsAnalyze < Minitest::Test
  include TestBase
  def test_analyze_start
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/ssl_labs_analyze_start.json', 'api/v3/analyze', port

    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    body = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.start_scan uri, 'adamcaudill.com'

    assert body.include?('Resolving domain names'), 'SSL Labs: Start Status Not Found'

    server.exit
  end

  def test_analyze_data
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/ssl_labs_analyze_data.json', 'api/v3/analyze', port

    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    body = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.start_scan uri, 'adamcaudill.com'
    status = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.extract_status body

    assert status == 'READY', 'SSL Labs: Start Status Not Found'

    server.exit
  end
end