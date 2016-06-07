module Yawast
  module Scanner
    class Generic
      def self.server_info(uri)
        begin
          Yawast::Utilities.puts_info "Full URI: #{uri}"

          Yawast::Utilities.puts_info 'IP(s):'
          dns = Resolv::DNS.new()
          addr = dns.getaddresses(uri.host)
          addr.each do |ip|
            begin
              host_name = dns.getname(ip.to_s)
            rescue
              host_name = 'N/A'
            end

            Yawast::Utilities.puts_info "\t\t#{ip} (#{host_name})"
          end
          puts ''
        rescue => e
          Yawast::Utilities.puts_error "Error getting basic information: #{e.message}"
          raise
        end
      end

      def self.head_info(head)
        begin
          server = ''
          powered_by = ''
          cookies = Array.new
          pingback = ''
          frame_options = ''
          content_options = ''
          backend_server = ''
          runtime = ''
          xss_protection = ''
          via = ''

          Yawast::Utilities.puts_info 'HEAD:'
          head.each do |k, v|
            Yawast::Utilities.puts_info "\t\t#{k}: #{v}"

            server = v if k.downcase == 'server'
            powered_by = v if k.downcase == 'x-powered-by'
            pingback = v if k.downcase == 'x-pingback'
            frame_options = v if k.downcase == 'x-frame-options'
            content_options = v if k.downcase == 'x-content-type-options'
            backend_server = v if k.downcase == 'x-backend-server'
            runtime = v if k.downcase == 'x-runtime'
            xss_protection = v if k.downcase == 'x-xss-protection'
            via = v if k.downcase == 'via'

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
            Yawast::Utilities.puts_info "X-Frame-Options Header: #{frame_options}"
          end

          if content_options == ''
            Yawast::Utilities.puts_warn 'X-Content-Type-Options Header Not Present'
          else
            Yawast::Utilities.puts_info "X-Content-Type-Options Header: #{content_options}"
          end

          unless cookies.empty?
            Yawast::Utilities.puts_info 'Cookies:'

            cookies.each do |val|
              Yawast::Utilities.puts_info "\t\t#{val.strip}"
            end

            puts ''
          end

          puts ''
        rescue => e
          Yawast::Utilities.puts_error "Error getting head information: #{e.message}"
          raise
        end
      end

      def self.directory_search(uri)
        puts 'Searching for common directories...'

        File.open("lib/resources/common.txt", "r") do |f|
          f.each_line do |line|
            check = uri.copy
            check.path = check.path + "#{line.strip}/"

            code = Yawast::Shared::Http.get_status_code(check)

            if code == "200"
              Yawast::Utilities.puts_info "\tFound: '#{check.to_s}'"
            end
          end
        end

        puts ''
      end
    end
  end
end
