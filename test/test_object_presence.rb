require 'minitest/autorun'
require 'webrick'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestScannerApacheServerStatus < Minitest::Test
  include TestBase

  def test_readme_html_present
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/wordpress_readme_html.txt', 'readme.html', port

    override_stdout
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])
    Yawast::Scanner::Plugins::Http::FilePresence.check_readme_html uri

    assert stdout_value.include?('\'/readme.html\' found:'), 'readme.html page warning not found'

    server.exit
    restore_stdout
  end

  def test_release_notes_txt_present
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/tomcat_release_notes.txt', 'RELEASE-NOTES.txt', port

    override_stdout
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])
    Yawast::Scanner::Plugins::Http::FilePresence.check_release_notes_txt uri

    assert stdout_value.include?('\'/RELEASE-NOTES.txt\' found:'), 'RELEASE-NOTES.txt page warning not found'

    server.exit
    restore_stdout
  end
end
