require 'ipaddr_extensions'
require 'json'
require 'public_suffix'

module Yawast
  module Scanner
    class Generic
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
            Yawast::Shared::Output.log_value 'http', 'head', k, v

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
              v.gsub(/(,([^;,]*=)|,$)/) { "\r\n#{$2}" }.split(/\r\n/).each do |c|
                cookies.push(c)

                Yawast::Shared::Output.log_append_value 'http', 'head', 'cookies', c
              end
            end
          end
          puts ''

          if server != ''
            Yawast::Scanner::Plugins::Servers::Apache.check_banner(server)
            Yawast::Scanner::Php.check_banner(server)
            Yawast::Scanner::Plugins::Servers::Iis.check_banner(server)
            Yawast::Scanner::Plugins::Servers::Nginx.check_banner(server)
            Yawast::Scanner::Plugins::Servers::Python.check_banner(server)

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
              unless elements.include?(' HttpOnly') || elements.include?(' httponly')
                Yawast::Utilities.puts_warn "\t\t\tCookie missing HttpOnly flag"
              end

              #check for SameSite cookies
              unless elements.include?(' SameSite') || elements.include?(' samesite')
                Yawast::Utilities.puts_warn "\t\t\tCookie missing SameSite flag"
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
    end
  end
end
