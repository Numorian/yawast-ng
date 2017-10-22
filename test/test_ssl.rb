require 'webrick'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestSSLLabsAnalyze < Minitest::Test
  include TestBase

  def test_hsts_header
    head = parse_headers_from_file File.dirname(__FILE__) + '/data/hsts_server_header.txt'

    override_stdout

    Yawast::Scanner::Plugins::SSL::SSL.check_hsts head

    assert stdout_value.include?('HSTS: Enabled'), "HSTS enabled not found in #{stdout_value}"

    restore_stdout
  end

  def test_no_hsts_header
    head = parse_headers_from_file File.dirname(__FILE__) + '/data/hsts_disabled_server_header.txt'

    override_stdout

    Yawast::Scanner::Plugins::SSL::SSL.check_hsts head

    assert stdout_value.include?('HSTS: Not Enabled'), "HSTS disabled not found in #{stdout_value}"

    restore_stdout
  end

  def test_hsts_preload
    uri = URI::Parser.new.parse 'https://adamcaudill.com/'

    override_stdout

    Yawast::Scanner::Plugins::SSL::SSL.check_hsts_preload uri

    assert stdout_value.include?('HSTS Preload'), "HSTS Preload not found in #{stdout_value}"

    restore_stdout
  end
end
