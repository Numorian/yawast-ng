module TestBase
  def override_stdout
    @orig_stdout = $stdout
    reset_stdout
  end

  def stdout_value
    $stdout.string
  end

  def reset_stdout
    $stdout = StringIO.new
  end

  def restore_stdout
    $stdout = @orig_stdout
  end
end
