module Yawast
  module Scanner
    class Core
      def self.process(uri, options)
        Yawast.header
        puts "Scanning: #{uri.to_s}"
        puts ''

        begin
          Yawast::Scanner::Generic.server_info(uri)
          Yawast::Scanner::Generic.head_info(uri)

          #perfom SSL checks
          if uri.scheme == 'https' && !options.nossl
              Yawast::Scanner::Ssl.info(uri)
              Yawast::Scanner::Ssl.check_hsts(uri)
          end

          unless options.head
            #apache specific checks
            Yawast::Scanner::Apache.check_server_status(uri)
            Yawast::Scanner::Apache.check_server_info(uri)

            #iis specific checks
            Yawast::Scanner::Iis.check_asp_banner(uri)
          end
        rescue => e
          Yawast::Utilities.puts_error "Fatal Error: Can not continue. (#{e.message})"
        end
      end
    end
  end
end
