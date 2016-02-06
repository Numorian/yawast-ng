require 'minitest/autorun'
require './lib/yawast'
require './test/base'

class TestScannerNginxHeaders < Minitest::Test
  include TestBase

  def test_nginx_basic_banner
    server = 'nginx/1.8.1'

    override_stdout
    Yawast::Scanner::Nginx.check_banner server

    assert stdout_value.include?("nginx Version: #{server}"), "Unexpected banner: #{stdout_value}"

    restore_stdout
  end
end
