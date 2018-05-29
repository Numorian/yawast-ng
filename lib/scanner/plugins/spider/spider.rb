require 'nokogiri'

module Yawast
  module Scanner
    module Plugins
      module Spider
        class Spider
          def self.spider(uri)
            @uri = uri.copy

            @workers = []
            @results = Queue.new

            @links = []
            @links.push @uri.to_s
            puts 'Spidering site...'
            get_links @uri

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

            @workers.map(&:join)
            results.terminate

            puts
          end

          def self.get_links(uri)
            # get the page, and work out from there
            res = Yawast::Shared::Http.get_with_code uri
            doc = Nokogiri::HTML res[:body]

            results = doc.css('a').map { |link| link['href'] }

            results.each do |link|
              # check to see if this link is in scope
              if link.to_s.include?(@uri.to_s) && res[:code] == '200'
                # check to see if we've already seen this one
                unless @links.include? link.to_s
                  @links.push link.to_s
                  @results.push "#{link.to_s}"

                  @workers.push Thread.new {
                    get_links URI.parse(link)
                  }
                end
              end
            end
          end
        end
      end
    end
  end
end
