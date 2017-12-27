require 'webrick'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestSSLLabsAnalyze < Minitest::Test
  include TestBase

  def test_analyze_start
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/ssl_labs_analyze_start.json', 'api/v3/analyze', port

    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    body = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.scan uri, 'adamcaudill.com', true

    assert body.include?('Resolving domain names'), 'SSL Labs: Start Status Not Found'

    server.exit
  end

  def test_analyze_data
    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/ssl_labs_analyze_data.json', 'api/v3/analyze', port

    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    body = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.scan uri, 'adamcaudill.com', false
    status = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.extract_status body

    assert status == 'READY', 'SSL Labs: Start Status Not Found'

    server.exit
  end

  def test_process_data
    override_stdout

    uri = URI.parse 'https://adamcaudill.com/'
    body = JSON.parse(File.read(File.dirname(__FILE__) + '/data/ssl_labs_analyze_data.json'))

    Yawast::Scanner::SslLabs.process_results uri, body, false

    assert stdout_value.include?('*.adamcaudill.com'), "wildcard domain name not found in #{stdout_value}"
    assert !stdout_value.include?('[E]'), "Error message found in #{stdout_value}"

    restore_stdout
  end

  def test_process_data_parivahan
    override_stdout

    uri = URI.parse 'https://parivahan.gov.in/'
    body = JSON.parse(File.read(File.dirname(__FILE__) + '/data/ssl_labs_analyze_data_parivahan_gov_in.json'))

    Yawast::Scanner::SslLabs.process_results uri, body, false

    assert stdout_value.include?('parivahan.gov.in'), "domain name not found in #{stdout_value}"
    assert !stdout_value.include?('[E]'), "Error message found in #{stdout_value}"

    restore_stdout
  end

  def test_process_data_file_zetlab
    override_stdout

    uri = URI.parse 'https://file.zetlab.com/'
    body = JSON.parse(File.read(File.dirname(__FILE__) + '/data/ssl_labs_analyze_data_file_zetlab_com.json'))

    Yawast::Scanner::SslLabs.process_results uri, body, false

    assert stdout_value.include?('file.zetlab.com'), "domain name not found in #{stdout_value}"
    assert stdout_value.include?('Certificate Issue: hostname mismatch'), "hostname mismatch not found in #{stdout_value}"
    assert !stdout_value.include?('[E]'), "Error message found in #{stdout_value}"

    restore_stdout
  end

  def test_process_data_act_is
    override_stdout

    uri = URI.parse 'https://activationservice1.installshield.com/'
    body = JSON.parse(File.read(File.dirname(__FILE__) + '/data/ssl_labs_analyze_data_activationservice1_installshield_com.json'))

    Yawast::Scanner::SslLabs.process_results uri, body, false

    assert stdout_value.include?('installshield.com'), "domain name not found in #{stdout_value}"
    assert stdout_value.include?('Root Stores: Mozilla (trusted)'), "root store name not found in #{stdout_value}"
    assert !stdout_value.include?('[E]'), "Error message found in #{stdout_value}"

    restore_stdout
  end

  def test_process_data_forest_gov
    override_stdout

    uri = URI.parse 'https://www.forest.gov.tw/'
    body = JSON.parse(File.read(File.dirname(__FILE__) + '/data/ssl_labs_analyze_data_forest_gov_tw.json'))

    Yawast::Scanner::SslLabs.process_results uri, body, false

    assert stdout_value.include?('www.forest.gov.tw'), "domain name not found in #{stdout_value}"
    assert stdout_value.include?('Root Stores: Apple (trusted) Windows (trusted)'), "root store name not found in #{stdout_value}"
    assert !stdout_value.include?('[E]'), "Error message found in #{stdout_value}"

    restore_stdout
  end
end
