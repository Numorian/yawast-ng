require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestAppFWPHP < Minitest::Test
  include TestBase

  def test_php_powered_by
    override_stdout

    error = nil
    begin
      Yawast::Scanner::Plugins::Applications::Framework::PHP.check_powered_by('PHP/5.4.22')
    rescue => e
      error = e.message
    end

    assert stdout_value.include?('PHP Version: PHP/5.4.22'), "PHP version not found: #{stdout_value}"
    assert error == nil, "Unexpected error: #{error}"

    restore_stdout
  end
end
