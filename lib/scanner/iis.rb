module Yawast
  module Scanner
    class Iis
      def self.check_banner(banner)
        #don't bother if this doesn't include IIS
        return if !banner.include? 'Microsoft-IIS/'
        @iis = true

        Yawast::Utilities.puts_warn "IIS Version: #{banner}"
        puts ''
      end

      def self.check_all(uri, head)
        return if !@iis

        #run all the defined checks
        check_asp_banner(head)
        check_mvc_version(head)
        check_asp_net_debug(uri)
      end

      def self.check_asp_banner(head)
        head.each do |k, v|
          if k.downcase == 'x-aspnet-version'
            Yawast::Utilities.puts_warn "ASP.NET Version: #{v}"
            puts ''
          end
        end
      end

      def self.check_mvc_version(head)
        head.each do |k, v|
          if k.downcase == 'x-aspnetmvc-version'
            Yawast::Utilities.puts_warn "ASP.NET MVC Version: #{v}"
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
          res = req.request(Debug.new('/'))

          if res.code == 200
            Yawast::Utilities.puts_vuln 'ASP.NET Debugging Enabled'
          end
        end
      end
    end

    #Custom class to allow using the DEBUG verb
    class Debug < Net::HTTPRequest
      METHOD = "DEBUG"
      REQUEST_HAS_BODY = false
      RESPONSE_HAS_BODY = true
    end
  end
end
