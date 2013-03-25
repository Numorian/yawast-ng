module Yawast
  module Scanner
    class Core
      def self.process(uri, ssl_test)
        Yawast.header
        puts "Scanning: #{uri.to_s}"
        puts ''

        begin
          Yawast::Scanner::Generic.server_info(uri)
          Yawast::Scanner::Generic.head_info(uri)

          #perfom SSL checks
          if (uri.scheme == 'https') && ssl_test
            Yawast::Scanner::Ssl.info(uri)
            Yawast::Scanner::Ssl.check_hsts(uri)
          end

          #apache specific checks
          Yawast::Scanner::Apache.check_server_status(uri)
          Yawast::Scanner::Apache.check_server_info(uri)

          #iis specific checks
          Yawast::Scanner::Iis.check_asp_banner(uri)
        rescue => e
          Yawast::Utilities.puts_error "Fatal Error: Can not continue. (#{e.message})"
        end
      end
    end
  end
end
