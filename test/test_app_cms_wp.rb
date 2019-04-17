require 'webrick'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestAppCMSWordPress < Minitest::Test
  include TestBase

  def test_identify_wp_551
    override_stdout

    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/wp-login-5.1.1.txt', '', port
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    error = nil
    begin
      Yawast::Shared::Http.setup nil, nil
      Yawast::Scanner::Plugins::Applications::CMS::WordPress.identify uri
    rescue => e
      error = e.message
    end

    assert stdout_value.include?('Found WordPress v5.1.1'), "WordPress version not found: #{stdout_value}"
    assert error == nil, "Unexpected error: #{error}"

    restore_stdout

    server.exit
  end

  def test_identify_wp_498
    override_stdout

    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/wp-login-4.9.8.txt', '', port
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    error = nil
    begin
      Yawast::Shared::Http.setup nil, nil
      Yawast::Scanner::Plugins::Applications::CMS::WordPress.identify uri
    rescue => e
      error = e.message
    end

    assert stdout_value.include?('Found WordPress v4.9.8'), "WordPress version not found: #{stdout_value}"
    assert error == nil, "Unexpected error: #{error}"

    restore_stdout

    server.exit
  end

  def test_wp_json_enum
    override_stdout

    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/wp-json-users.txt', '', port
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    error = nil
    begin
      Yawast::Shared::Http.setup nil, nil
      Yawast::Scanner::Plugins::Applications::CMS::WordPress.check_json_user_enum uri
    rescue => e
      error = e.message
    end

    assert stdout_value.include?('WordPress WP-JSON User Enumeration at'), "WordPress WP-JSON User Enum not found: #{stdout_value}"
    assert error == nil, "Unexpected error: #{error}"

    restore_stdout

    server.exit
  end
end
