require 'minitest/autorun'
require 'webrick'
require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestDirectorySearch < Minitest::Test
  include TestBase

  def test_directory_search_recurs
    port = rand(60000) + 1024 # pick a random port number
    server = run_server port

    override_stdout
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    Yawast::Scanner::Plugins::Http::DirectorySearch.search uri, true, true, ['test', 'data']

    assert stdout_value.include?('Recursively searching for common directories'), 'Output not found'

    server.exit
    restore_stdout
  end

  def test_directory_search
    port = rand(60000) + 1024 # pick a random port number
    server = run_server port

    override_stdout
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    Yawast::Scanner::Plugins::Http::DirectorySearch.search uri, false, true, ['test', 'data']

    assert stdout_value.include?('Searching for common directories'), 'Output not found'

    server.exit
    restore_stdout
  end

  def run_server(port)
    thr = Thread.new {
      sockets = WEBrick::Utils.create_listeners nil, port

      server = WEBrick::HTTPServer.new :Port => port,
                                       :BindAddress => 'localhost',
                                       :AccessLog => [],
                                       :Logger => WEBrick::Log.new('/dev/null'),
                                       :DocumentRoot => File.dirname(__FILE__),
                                       :DoNotListen => true
      server.listeners.replace sockets
      server.start
    }

    thr
  end
end
