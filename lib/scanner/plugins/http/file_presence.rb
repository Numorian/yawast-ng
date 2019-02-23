require 'securerandom'

module Yawast
  module Scanner
    module Plugins
      module Http
        class FilePresence
          def self.check_path(uri, path, vuln)
            #note: this only checks directly at the root, I'm not sure if this is what we want
            # should probably be relative to what's passed in, instead of overriding the path.
            check = uri.copy
            check.path = "#{path}"
            code = Yawast::Shared::Http.get_status_code(check)

            if code == '200'
              msg = "'#{path}' found: #{check}"

              if vuln
                Yawast::Utilities.puts_vuln msg
              else
                Yawast::Utilities.puts_warn msg
              end

              puts ''
            end
          end

          def self.check_all(uri, common_files)
            #first, we need to see if the site responds to 404 in a reasonable way
            unless Yawast::Shared::Http.check_not_found(uri, true)
              puts 'Site does not respond properly to non-existent file requests; skipping some checks.'

              return
            end

            check_source_control uri
            check_cross_domain uri
            check_sitemap uri
            check_wsftp_log uri
            check_trace_axd uri
            check_elmah_axd uri
            check_readme_html uri
            check_release_notes_txt uri
            check_change_log_txt uri

            if common_files
              puts ''
              puts 'Checking for common files (this will take a few minutes)...'
              check_common uri
            end

            puts ''
          end

          def self.check_source_control(uri)
            check_path(uri, '/.git/', true)
            check_path(uri, '/.hg/', true)
            check_path(uri, '/.svn/', true)
            check_path(uri, '/.bzr/', true)
            check_path(uri, '/.csv/', true)
          end

          def self.check_cross_domain(uri)
            check_path(uri, '/crossdomain.xml', false)
            check_path(uri, '/clientaccesspolicy.xml', false)
          end

          def self.check_sitemap(uri)
            check_path(uri, '/sitemap.xml', false)
          end

          def self.check_wsftp_log(uri)
            #check both upper and lower, as they are both seen in the wild
            check_path(uri, '/WS_FTP.LOG', false)
            check_path(uri, '/ws_ftp.log', false)
          end

          def self.check_trace_axd(uri)
            check_path(uri, '/Trace.axd', false)
          end

          def self.check_elmah_axd(uri)
            check_path(uri, '/elmah.axd', false)
          end

          def self.check_readme_html(uri)
            check_path(uri, '/readme.html', false)
          end

          def self.check_release_notes_txt(uri)
            check_path(uri, '/RELEASE-NOTES.txt', false)
            check_path(uri, '/docs/RELEASE-NOTES.txt', false)
          end

          def self.check_change_log_txt(uri)
            check_path(uri, '/CHANGELOG.txt', false)
            check_path(uri, '/core/CHANGELOG.txt', false)
          end

          def self.check_common(uri)
            begin
              @search_list = []

              File.open(File.dirname(__FILE__) + '/../../../resources/common_file.txt', 'r') do |f|
                f.each_line do |line|
                  @search_list.push line.strip
                end
              end

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
              Yawast::Utilities.puts_error "Error searching for files (#{e.message})"
            end
          end

          def self.load_queue(uri)
            @search_list.each do |line|
              check = uri.copy

              begin
                check.path = "/#{line}"

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
                @results.push "'#{uri.path}' found: #{uri}"
                Yawast::Shared::Output.log_append_value 'http', 'http_file', uri
              end
            rescue => e
              unless e.message.include?('end of file') || e.message.include?('getaddrinfo')
                Yawast::Utilities.puts_error "Error searching for file '#{uri.path}' (#{e.message})"
              end
            end
          end
        end
      end
    end
  end
end
