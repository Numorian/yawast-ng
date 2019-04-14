require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestScannerNginx < Minitest::Test
  include TestBase

  def test_nginx_basic_banner
    server = 'nginx/1.8.1'

    override_stdout
    Yawast::Scanner::Plugins::Servers::Nginx.check_banner server

    assert stdout_value.include?("nginx Version: #{server}"), "Unexpected banner: #{stdout_value}"

    restore_stdout
  end

  def test_nginx_status_present
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/nginx_status_page.txt', 'status', port

    override_stdout
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    Yawast::Shared::Http.setup nil, nil
    Yawast::Scanner::Plugins::Servers::Nginx.check_status_page uri

    assert stdout_value.include?('Nginx status page found'), 'Nginx Status page warning not found'

    server.exit
    restore_stdout
  end
end
