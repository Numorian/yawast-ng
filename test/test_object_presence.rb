require 'minitest/autorun'
require 'webrick'
require './lib/yawast'
require './test/base'

class TestScannerApacheServerStatus < Minitest::Test
  include TestBase

  def test_readme_html_present
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server 'test/data/wordpress_readme_html.txt', 'readme.html', port

    override_stdout
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])
    Yawast::Scanner::ObjectPresence.check_readme_html uri

    assert stdout_value.include?('\'/readme.html\' found:'), 'readme.html page warning not found'

    server.exit
    restore_stdout
  end
end
