module Yawast
  module Scanner
    module Plugins
      module Http
        class DirectorySearch
          def self.search(uri, recursive, list_redirects, search_list = nil)
            @recursive = recursive
            @list_redirects = list_redirects

            if recursive
              puts 'Recursively searching for common directories (this will take a while)...'
            else
              puts 'Searching for common directories...'
            end

            if search_list == nil
              @search_list = []

              File.open(File.dirname(__FILE__) + '/../../../resources/common.txt', 'r') do |f|
                f.each_line do |line|
                  @search_list.push line.strip
                end
              end
            else
              @search_list = search_list
            end

            begin
              pool_size = 16
              @jobs = Queue.new
              @results = Queue.new

              #load the queue, starting at /
              base = uri.copy
              base.path = '/'
              load_queue base

              workers = (pool_size).times.map do
                Thread.new do
                  begin
                    while (check = @jobs.pop(true))
                      process check
                    end
                  rescue ThreadError
                    #do nothing
                  end
                end
              end

              results = Thread.new do
                begin
                  while true
                    if @results.length > 0
                      out = @results.pop(true)
                      Yawast::Utilities.puts_info out
                    end
                  end
                rescue ThreadError
                  #do nothing
                end
              end

              workers.map(&:join)
              results.terminate
            rescue => e
              Yawast::Utilities.puts_error "Error searching for directories (#{e.message})"
            end

            puts
          end

          def self.load_queue(uri)
            @search_list.each do |line|
              check = uri.copy
              check.path = check.path + "#{line}/"

              #add the job to the queue
              @jobs.push check
            end
          end

          def self.process(uri)
            begin
              res = Yawast::Shared::Http.head uri

              if res.code == '200'
                @results.push "\tFound: '#{uri}'"

                load_queue uri if @recursive
              elsif res.code == '301' && @list_redirects
                @results.push "\tFound Redirect: '#{uri} -> '#{res['Location']}'"
              end
            rescue => e
              Yawast::Utilities.puts_error "Error searching for directories (#{e.message})"
            end
          end
        end
      end
    end
  end
end
