module Yawast
  module Scanner
    module Plugins
      module Servers
        class Iis
          def self.check_banner(banner)
            #don't bother if this doesn't include IIS
            return unless banner.include? 'Microsoft-IIS/'
            @iis = true

            Yawast::Utilities.puts_warn "IIS Version: #{banner}"
            puts ''
          end

          def self.check_all(uri, head)
            #run all the defined checks
            check_asp_banner(head)
            check_mvc_version(head)
            check_asp_net_debug(uri)
          end

          def self.check_asp_banner(head)
            check_header_value head, 'x-aspnet-version', 'ASP.NET'
          end

          def self.check_mvc_version(head)
            check_header_value head, 'x-aspnetmvc-version', 'ASP.NET MVC'
          end

          def self.check_header_value(head, search, message)
            head.each do |k, v|
              if k.downcase == search
                Yawast::Utilities.puts_warn "#{message} Version: #{v}"
                puts ''
              end
            end
          end

          def self.check_asp_net_debug(uri)
            begin
              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              headers = Yawast::Shared::Http.get_headers
              headers['Command'] = 'stop-debug'
              headers['Accept'] = '*/*'
              res = req.request(Debug.new('/', headers))

              if res.code == 200
                Yawast::Utilities.puts_vuln 'ASP.NET Debugging Enabled'
              end

              Yawast::Shared::Output.log_value 'http', 'asp_net_debug', 'raw', res.body
              Yawast::Shared::Output.log_value 'http', 'asp_net_debug', 'code', res.code
            end
          end
        end

        #Custom class to allow using the DEBUG verb
        class Debug < Net::HTTPRequest
          METHOD = 'DEBUG'
          REQUEST_HAS_BODY = false
          RESPONSE_HAS_BODY = true
        end
      end
    end
  end
end
