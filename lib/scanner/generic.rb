require 'ipaddr_extensions'

module Yawast
  module Scanner
    class Generic
      def self.server_info(uri, options)
        begin
          puts 'DNS Information:'

          dns = Resolv::DNS.new
          Resolv::DNS.open do |resv|
            a = resv.getresources(uri.host, Resolv::DNS::Resource::IN::A)
            unless a.empty?
              a.each do |ip|
                begin
                  host_name = dns.getname(ip.address)
                rescue
                  host_name = 'N/A'
                end

                Yawast::Utilities.puts_info "\t\t#{ip.address} (#{host_name})"

                # if address is private, force internal SSL mode, don't show links
                if IPAddr.new(ip.address.to_s, Socket::AF_INET).private?
                  options.internalssl = true
                else
                  puts "\t\t\t\thttps://www.shodan.io/host/#{ip.address}"
                  puts "\t\t\t\thttps://censys.io/ipv4/#{ip.address}"
                end
              end
            end

            aaaa = resv.getresources(uri.host, Resolv::DNS::Resource::IN::AAAA)
            unless aaaa.empty?
              aaaa.each do |ip|
                begin
                  host_name = dns.getname(ip.address)
                rescue
                  host_name = 'N/A'
                end

                Yawast::Utilities.puts_info "\t\t#{ip.address} (#{host_name})"

                # if address is private, force internal SSL mode, don't show links
                if IPAddr.new(ip.address.to_s, Socket::AF_INET6).private?
                  options.internalssl = true
                else
                  puts "\t\t\t\thttps://www.shodan.io/host/#{ip.address.to_s.downcase}"
                end
              end
            end

            txt = resv.getresources(uri.host, Resolv::DNS::Resource::IN::TXT)
            unless txt.empty?
              txt.each do |rec|
                Yawast::Utilities.puts_info "\t\tTXT: #{rec.data}"
              end
            end

            mx = resv.getresources(uri.host, Resolv::DNS::Resource::IN::MX)
            unless mx.empty?
              mx.each do |rec|
                Yawast::Utilities.puts_info "\t\tMX: #{rec.exchange} (#{rec.preference})"
              end
            end

            ns = resv.getresources(uri.host, Resolv::DNS::Resource::IN::NS)
            unless ns.empty?
              ns.each do |rec|
                Yawast::Utilities.puts_info "\t\tNS: #{rec.name}"
              end
            end
          end

          puts
        rescue => e
          Yawast::Utilities.puts_error "Error getting basic information: #{e.message}"
          raise
        end
      end

      def self.head_info(head, uri)
        begin
          server = ''
          powered_by = ''
          cookies = Array.new
          pingback = ''
          frame_options = ''
          content_options = ''
          csp = ''
          backend_server = ''
          runtime = ''
          xss_protection = ''
          via = ''
          hpkp = ''
          acao = ''

          Yawast::Utilities.puts_info 'HEAD:'
          head.each do |k, v|
            Yawast::Utilities.puts_info "\t\t#{k}: #{v}"

            server = v if k.downcase == 'server'
            powered_by = v if k.downcase == 'x-powered-by'
            pingback = v if k.downcase == 'x-pingback'
            frame_options = v if k.downcase == 'x-frame-options'
            content_options = v if k.downcase == 'x-content-type-options'
            csp = v if k.downcase == 'content-security-policy'
            backend_server = v if k.downcase == 'x-backend-server'
            runtime = v if k.downcase == 'x-runtime'
            xss_protection = v if k.downcase == 'x-xss-protection'
            via = v if k.downcase == 'via'
            hpkp = v if k.downcase == 'public-key-pins'
            acao = v if k.downcase == 'access-control-allow-origin'

            if k.downcase == 'set-cookie'
              #this chunk of magic manages to properly split cookies, when multiple are sent together
              v.gsub(/(,([^;,]*=)|,$)/) { "\r\n#{$2}" }.split(/\r\n/).each { |c| cookies.push(c) }
            end
          end
          puts ''

          if server != ''
            Yawast::Scanner::Apache.check_banner(server)
            Yawast::Scanner::Php.check_banner(server)
            Yawast::Scanner::Iis.check_banner(server)
            Yawast::Scanner::Nginx.check_banner(server)

            if server == 'cloudflare-nginx'
              Yawast::Utilities.puts_info 'NOTE: Server appears to be Cloudflare; WAF may be in place.'
              puts
            end
          end

          if powered_by != ''
            Yawast::Utilities.puts_warn "X-Powered-By Header Present: #{powered_by}"
          end

          if xss_protection == '0'
            Yawast::Utilities.puts_warn 'X-XSS-Protection Disabled Header Present'
          end

          unless pingback == ''
            Yawast::Utilities.puts_info "X-Pingback Header Present: #{pingback}"
          end

          unless runtime == ''
            if runtime.is_number?
              Yawast::Utilities.puts_warn 'X-Runtime Header Present; likely indicates a RoR application'
            else
              Yawast::Utilities.puts_warn "X-Runtime Header Present: #{runtime}"
            end
          end

          unless backend_server == ''
            Yawast::Utilities.puts_warn "X-Backend-Server Header Present: #{backend_server}"
          end

          unless via == ''
            Yawast::Utilities.puts_warn "Via Header Present: #{via}"
          end

          if frame_options == ''
            Yawast::Utilities.puts_warn 'X-Frame-Options Header Not Present'
          else
            if frame_options.downcase == 'allow'
              Yawast::Utilities.puts_vuln "X-Frame-Options Header: #{frame_options}"
            else
              Yawast::Utilities.puts_info "X-Frame-Options Header: #{frame_options}"
            end
          end

          if content_options == ''
            Yawast::Utilities.puts_warn 'X-Content-Type-Options Header Not Present'
          else
            Yawast::Utilities.puts_info "X-Content-Type-Options Header: #{content_options}"
          end

          if csp == ''
            Yawast::Utilities.puts_warn 'Content-Security-Policy Header Not Present'
          end

          if hpkp == ''
            Yawast::Utilities.puts_warn 'Public-Key-Pins Header Not Present'
          end

          if acao == '*'
            Yawast::Utilities.puts_warn 'Access-Control-Allow-Origin: Unrestricted'
          end

          puts ''

          unless cookies.empty?
            Yawast::Utilities.puts_info 'Cookies:'

            cookies.each do |val|
              Yawast::Utilities.puts_info "\t\t#{val.strip}"

              elements = val.strip.split(';')

              #check for secure cookies
              if elements.include?(' Secure') || elements.include?(' secure')
                if uri.scheme != 'https'
                  Yawast::Utilities.puts_warn "\t\t\tCookie with Secure flag sent over non-HTTPS connection"
                end
              else
                Yawast::Utilities.puts_warn "\t\t\tCookie missing Secure flag"
              end

              #check for HttpOnly cookies
              unless elements.include? ' HttpOnly'
                Yawast::Utilities.puts_warn "\t\t\tCookie missing HttpOnly flag"
              end
            end

            puts ''
          end

          puts ''
        rescue => e
          Yawast::Utilities.puts_error "Error getting head information: #{e.message}"
          raise
        end
      end

      def self.check_options(uri)
        begin
          req = Yawast::Shared::Http.get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          headers = Yawast::Shared::Http.get_headers
          res = req.request(Options.new('/', headers))

          if res['Public'] != nil
            Yawast::Utilities.puts_info "Public HTTP Verbs (OPTIONS): #{res['Public']}"

            puts ''
          end
        end
      end

      def self.check_trace(uri)
        begin
          req = Yawast::Shared::Http.get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          headers = Yawast::Shared::Http.get_headers
          res = req.request(Trace.new('/', headers))

          if res.body.include?('TRACE / HTTP/1.1') && res.code == '200'
            Yawast::Utilities.puts_warn 'HTTP TRACE Enabled'
            puts "\t\t\"curl -X TRACE #{uri}\""

            puts ''
          end
        end
      end

      def self.check_propfind(uri)
        begin
          req = Yawast::Shared::Http.get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          headers = Yawast::Shared::Http.get_headers
          res = req.request(Propfind.new('/', headers))

          if res.code.to_i <= 400 && res.body.length > 0 && res['Content-Type'] == 'text/xml'
            Yawast::Utilities.puts_warn 'Possible Info Disclosure: PROPFIND Enabled'
            puts "\t\t\"curl -X PROPFIND #{uri}\""

            puts ''
          end
        end
      end
    end

    #Custom class to allow using the PROPFIND verb
    class Propfind < Net::HTTPRequest
      METHOD = 'PROPFIND'
      REQUEST_HAS_BODY = false
      RESPONSE_HAS_BODY = true
    end

    #Custom class to allow using the OPTIONS verb
    class Options < Net::HTTPRequest
      METHOD = 'OPTIONS'
      REQUEST_HAS_BODY = false
      RESPONSE_HAS_BODY = true
    end

    #Custom class to allow using the TRACE verb
    class Trace < Net::HTTPRequest
      METHOD = 'TRACE'
      REQUEST_HAS_BODY = false
      RESPONSE_HAS_BODY = true
    end
  end
end
