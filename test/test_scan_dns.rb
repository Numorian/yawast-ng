require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestScannerDns < Minitest::Test
  include TestBase

  def test_dns_caa
    override_stdout

    uri = URI::Parser.new.parse 'https://www.adamcaudill.com/'
    Yawast::Scanner::Plugins::DNS::CAA.caa_info uri

    assert stdout_value.include?('mailto:adam@adamcaudill.com'), "DNS CAA Record not found: #{stdout_value}"

    restore_stdout
  end

  def test_get_network_info
    ret = Yawast::Scanner::Plugins::DNS::Generic.get_network_info '127.0.0.1'

    assert !ret.include?('Error'), "Unexpected error: #{ret}"
  end
end
