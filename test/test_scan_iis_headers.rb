require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestScannerIisHeaders < Minitest::Test
  include TestBase

  def test_iis_basic_banner
    server = 'Microsoft-IIS/8.5'

    override_stdout
    Yawast::Scanner::Plugins::Servers::Iis.check_banner server

    assert stdout_value.include?("IIS Version: #{server}"), "Unexpected banner: #{stdout_value}"

    restore_stdout
  end

  def test_asp_version
    headers = parse_headers_from_file File.dirname(__FILE__) + '/data/iis_server_header.txt'

    override_stdout
    Yawast::Scanner::Plugins::Servers::Iis.check_asp_banner headers

    assert stdout_value.include?('ASP.NET Version'), 'ASP.NET Version warning not found.'

    restore_stdout
  end

  def test_mvc_version
    headers = parse_headers_from_file File.dirname(__FILE__) + '/data/iis_server_header.txt'

    override_stdout
    Yawast::Scanner::Plugins::Servers::Iis.check_mvc_version headers

    assert stdout_value.include?('ASP.NET MVC Version'), 'ASP.NET MVC Version warning not found.'

    restore_stdout
  end
end
