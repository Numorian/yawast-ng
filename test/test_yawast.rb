require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestYawast < Minitest::Test
  include TestBase

  def test_header
    override_stdout

    Yawast.header
    header = stdout_value
    assert header.include?('Copyright'), "Header not found in #{header}"
    assert header.include?(Yawast::VERSION), "Version not found in #{header}"

    restore_stdout
  end

  def test_non_www_redirect
    override_stdout

    original = Yawast::Shared::Uri.extract_uri'https://www.adamcaudill.com'
    new = Yawast::Scanner::Core.check_www_redirect original.copy

    assert original.host != new.host, "Host not changed: '#{new}'"
    assert stdout_value.include?('Non-WWW Redirect'), "Non-WWW Redirect not found in: #{stdout_value}"

    restore_stdout
  end

  def test_www_redirect
    override_stdout

    original = Yawast::Shared::Uri.extract_uri'https://apple.com'
    new = Yawast::Scanner::Core.check_www_redirect original.copy

    assert original.host != new.host, "Host not changed: '#{new}'"
    assert stdout_value.include?('WWW Redirect'), "WWW Redirect not found in: #{stdout_value}"

    restore_stdout
  end

  def test_no_redirect
    override_stdout

    original = Yawast::Shared::Uri.extract_uri'https://adamcaudill.com'
    new = Yawast::Scanner::Core.check_www_redirect original.copy

    assert original.host == new.host, "Host changed: '#{new}'"
    assert !stdout_value.include?('Non-WWW Redirect'), "Non-WWW Redirect found in: #{stdout_value}"
    assert !stdout_value.include?('WWW Redirect'), "WWW Redirect found in: #{stdout_value}"

    restore_stdout
  end

  def test_non_www_redirect_scheme
    override_stdout

    original = Yawast::Shared::Uri.extract_uri'http://apple.com'
    new = Yawast::Scanner::Core.check_www_redirect original.copy

    assert original.host != new.host, "Host not changed: '#{new}'"
    assert stdout_value.include?('WWW Redirect'), "WWW Redirect not found in: #{stdout_value}"
    assert original.scheme != new.scheme, "Scheme not changed: Original: '#{original}' - New: '#{new}'"

    restore_stdout
  end
end
