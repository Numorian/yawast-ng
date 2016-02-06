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

  def start_web_server(file, url, port = 1234)
    thr = Thread.new {
      server = WEBrick::HTTPServer.new :Port => port,
                                       :BindAddress => 'localhost',
                                       :AccessLog => []#,
                                       #:Logger => WEBrick::Log.new('/dev/null')
      server.mount "/#{url}", WEBrick::HTTPServlet::FileHandler, file
      server.start
    }

    thr
  end

  def parse_headers_from_file(file)
    headers = {}
    File.foreach(file) do |line|
      key = line.partition(':').first.trim
      value = line.partition(':').last.trim

      headers[key] = value
    end

    headers
  end
end
