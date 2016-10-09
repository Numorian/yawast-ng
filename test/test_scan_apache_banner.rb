require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestScannerApacheBanner < Minitest::Test
  include TestBase

  def test_apache_basic_banner_no_version
    server = 'Apache'
    override_stdout
    Yawast::Scanner::Apache.check_banner server

    assert stdout_value.include?("Apache Server: #{server}"), "Unexpected banner: #{stdout_value}"

    restore_stdout
  end

  def test_apache_basic_banner
    server = 'Apache/2.4.7'
    override_stdout
    Yawast::Scanner::Apache.check_banner server

    assert stdout_value.include?("Apache Server: #{server}"), "Unexpected banner: #{stdout_value}"

    restore_stdout
  end

  def test_apache_basic_banner_distro
    server = 'Apache/2.4.7 (Ubuntu)'
    override_stdout
    Yawast::Scanner::Apache.check_banner server

    assert stdout_value.include?("Apache Server: #{server}"), "Unexpected banner: #{stdout_value}"

    restore_stdout
  end

  def test_apache_one_module
    server = 'Apache/2.4.6 (FreeBSD) PHP/5.4.23'
    override_stdout
    Yawast::Scanner::Apache.check_banner server

    assert stdout_value.include?('Apache Server: Module listing enabled'), 'Module listing missing'

    restore_stdout
  end

  def test_apache_openssl_module
    server = 'Apache/2.4.6 (FreeBSD) PHP/5.4.23 OpenSSL/0.9.8n'
    override_stdout
    Yawast::Scanner::Apache.check_banner server

    assert stdout_value.include?('Apache Server: Module listing enabled'), 'Module listing missing'
    assert stdout_value.include?('OpenSSL Version Disclosure'), 'OpenSSL version warning missing'

    restore_stdout
  end
end
