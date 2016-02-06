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

  def start_web_server(file, url)
    thr = Thread.new {
      server = WEBrick::HTTPServer.new :Port => 1234,
                                       :BindAddress => 'localhost',
                                       :AccessLog => [],
                                       :Logger => WEBrick::Log.new('/dev/null')
      server.mount "/#{url}", WEBrick::HTTPServlet::FileHandler, file
      server.start
    }

    thr
  end
end
