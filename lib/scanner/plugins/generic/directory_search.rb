module Yawast
  module Scanner
    module Plugins
      module Generic
        class DirectorySearch
          def self.search(uri, recursive)
            @recursive = recursive

            if recursive
              puts 'Recursively searching for common directories (this will take a while)...'
            else
              puts 'Searching for common directories...'
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
            File.open(File.dirname(__FILE__) + '/../../../resources/common.txt', "r") do |f|
              f.each_line do |line|
                check = uri.copy
                check.path = check.path + "#{line.strip}/"

                #add the job to the queue
                @jobs.push check
              end
            end
          end

          def self.process(uri)
            begin
              res = Yawast::Shared::Http.head uri

              if res.code == '200'
                @results.push "\tFound: '#{uri.to_s}'"

                load_queue uri if @recursive
              elsif res.code == '301'
                @results.push "\tFound Redirect: '#{uri.to_s} -> '#{res['Location']}'"
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
