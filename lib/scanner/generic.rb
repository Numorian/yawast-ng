# frozen_string_literal: true

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
          cookies = []
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
          referrer_policy = ''
          feature_policy = ''

          Yawast::Utilities.puts_info 'HEAD:'
          head.each do |k, v|
            Yawast::Utilities.puts_info "\t\t#{k}: #{v}"
            Yawast::Shared::Output.log_value 'http', 'head', k, v

            server = v if k.casecmp('server').zero?
            powered_by = v if k.casecmp('x-powered-by').zero?
            pingback = v if k.casecmp('x-pingback').zero?
            frame_options = v if k.casecmp('x-frame-options').zero?
            content_options = v if k.casecmp('x-content-type-options').zero?
            csp = v if k.casecmp('content-security-policy').zero?
            backend_server = v if k.casecmp('x-backend-server').zero?
            runtime = v if k.casecmp('x-runtime').zero?
            xss_protection = v if k.casecmp('x-xss-protection').zero?
            via = v if k.casecmp('via').zero?
            hpkp = v if k.casecmp('public-key-pins').zero?
            acao = v if k.casecmp('access-control-allow-origin').zero?
            referrer_policy = v if k.casecmp('referrer-policy').zero?
            feature_policy = v if k.casecmp('feature-policy').zero?

            if k.casecmp('set-cookie').zero?
              # this chunk of magic manages to properly split cookies, when multiple are sent together
              v.gsub(/(,([^;,]*=)|,$)/) { "\r\n#{$2}" }.split(/\r\n/).each do |c|
                cookies.push(c)

                Yawast::Shared::Output.log_append_value 'http', 'head', 'cookies', c
              end
            end
          end
          puts ''

          if server != ''
            Yawast::Scanner::Plugins::Servers::Apache.check_banner(server)
            Yawast::Scanner::Plugins::Applications::Framework::PHP.check_banner(server)
            Yawast::Scanner::Plugins::Servers::Iis.check_banner(server)
            Yawast::Scanner::Plugins::Servers::Nginx.check_banner(server)
            Yawast::Scanner::Plugins::Servers::Python.check_banner(server)

            if server == 'cloudflare'
              Yawast::Utilities.puts_info 'NOTE: Server appears to be Cloudflare; WAF may be in place.'
              puts
            end

            Yawast::Shared::Output.log_value 'server', server
          end

          if powered_by != ''
            Yawast::Utilities.puts_warn "X-Powered-By Header Present: #{powered_by}"
            Yawast::Scanner::Plugins::Applications::Framework::PHP.check_powered_by(powered_by)
          end

          Yawast::Utilities.puts_warn 'X-XSS-Protection Disabled Header Present' if xss_protection == '0'

          Yawast::Utilities.puts_info "X-Pingback Header Present: #{pingback}" unless pingback == ''

          unless runtime == ''
            if runtime.is_number?
              Yawast::Utilities.puts_warn 'X-Runtime Header Present; likely indicates a RoR application'
            else
              Yawast::Utilities.puts_warn "X-Runtime Header Present: #{runtime}"
            end
          end

          Yawast::Utilities.puts_warn "X-Backend-Server Header Present: #{backend_server}" unless backend_server == ''

          Yawast::Utilities.puts_warn "Via Header Present: #{via}" unless via == ''

          if frame_options == ''
            Yawast::Utilities.puts_warn 'X-Frame-Options Header Not Present'
          else
            if frame_options.casecmp('allow').zero?
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

          Yawast::Utilities.puts_warn 'Content-Security-Policy Header Not Present' if csp == ''

          Yawast::Utilities.puts_warn 'Public-Key-Pins Header Not Present' if hpkp == ''

          Yawast::Utilities.puts_warn 'Access-Control-Allow-Origin: Unrestricted' if acao == '*'

          Yawast::Utilities.puts_warn 'Referrer-Policy Header Not Present' if referrer_policy == ''

          Yawast::Utilities.puts_warn 'Feature-Policy Header Not Present' if feature_policy == ''

          puts ''

          unless cookies.empty?
            Yawast::Utilities.puts_info 'Cookies:'

            cookies.each do |val|
              Yawast::Utilities.puts_info "\t\t#{val.strip}"

              elements = val.strip.split(';')

              # check for secure cookies
              if elements.include?(' Secure') || elements.include?(' secure')
                if uri.scheme != 'https'
                  Yawast::Utilities.puts_warn "\t\t\tCookie with Secure flag sent over non-HTTPS connection"
                end
              else
                Yawast::Utilities.puts_warn "\t\t\tCookie missing Secure flag"
              end

              # check for HttpOnly cookies
              unless elements.include?(' HttpOnly') || elements.include?(' httponly')
                Yawast::Utilities.puts_warn "\t\t\tCookie missing HttpOnly flag"
              end

              # check for SameSite cookies
              unless elements.include?(' SameSite') || elements.include?(' samesite')
                Yawast::Utilities.puts_warn "\t\t\tCookie missing SameSite flag"
              end
            end

            puts ''
          end

          puts ''
        rescue => e # rubocop:disable Style/RescueStandardError
          Yawast::Utilities.puts_error "Error getting head information: #{e.message}"
          raise
        end
      end
    end
  end
end
