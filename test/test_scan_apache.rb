require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestScannerApacheBanner < Minitest::Test
  include TestBase

  def test_check_tomcat_put_rce
    override_stdout

    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/apache_server_info.txt', '', port
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    error = nil
    begin
      Yawast::Scanner::Plugins::Servers::Apache.check_tomcat_put_rce uri
    rescue => e
      error = e.message
    end

    assert !stdout_value.include?('[V]'), "Unexpected finding: #{stdout_value}"
    assert error == nil, "Unexpected error: #{error}"

    restore_stdout

    server.exit
  end
end