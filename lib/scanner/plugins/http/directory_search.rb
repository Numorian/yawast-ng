require 'securerandom'

module Yawast
  module Scanner
    module Plugins
      module Http
        class DirectorySearch
          def self.search(uri, recursive, list_redirects, search_list = nil)
            #first, we need to see if the site responds to 404 in a reasonable way
            unless Yawast::Shared::Http.check_not_found(uri, false)
              puts 'Site does not respond properly to non-existent directory requests; skipping some checks.'

              return
            end

            @recursive = recursive
            @list_redirects = list_redirects

            if recursive
              puts 'Recursively searching for common directories (this will take a while)...'
            else
              puts 'Searching for common directories...'
            end

            if search_list == nil
              @search_list = []

              File.open(File.dirname(__FILE__) + '/../../../resources/common_dir.txt', 'r') do |f|
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

              begin
                check.path = check.path + "#{line}/"

                #add the job to the queue
                @jobs.push check
              rescue
                #who cares
              end
            end
          end

          def self.process(uri)
            begin
              res = Yawast::Shared::Http.head uri

              if res.code == '200'
                @results.push "\tFound: '#{uri}'"
                Yawast::Shared::Output.log_append_value 'http', 'http_dir', uri

                load_queue uri if @recursive
              elsif res.code == '301' && @list_redirects
                @results.push "\tFound Redirect: '#{uri} -> '#{res['Location']}'"
                Yawast::Shared::Output.log_value 'http', 'http_dir_redirect', uri, res['Location']
              end
            rescue => e
              unless e.message.include?('end of file') || e.message.include?('getaddrinfo')
                Yawast::Utilities.puts_error "Error searching for directory '#{uri.path}' (#{e.message})"
              end
            end
          end
        end
      end
    end
  end
end
