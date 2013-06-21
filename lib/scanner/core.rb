module Yawast
  module Scanner
    class Core
      def self.process(uri, options)
        Yawast.header
        puts "Scanning: #{uri.to_s}"
        puts ''

        begin
          #cache the HEAD result, so that we can minimize hits
          head = Yawast::Shared::Http.head(uri)

          Yawast::Scanner::Generic.server_info(uri)
          Yawast::Scanner::Generic.head_info(head)

          #perfom SSL checks
          if uri.scheme == 'https' && !options.nossl
              Yawast::Scanner::Ssl.info(uri)
              Yawast::Scanner::Ssl.check_hsts(head)
          end

          #process the 'scan' stuff that goes beyond 'head'
          unless options.head
            #server specific checks
            Yawast::Scanner::Apache.check_all(uri, head)
            Yawast::Scanner::Iis.check_all(uri, head)

            Yawast::Scanner::ObjectPresence.check_source_control(uri)
            Yawast::Scanner::ObjectPresence.check_cross_domain(uri)
            Yawast::Scanner::ObjectPresence.check_wsftp_log(uri)
          end
        rescue => e
          Yawast::Utilities.puts_error "Fatal Error: Can not continue. (#{e.message})"
        end
      end
    end
  end
end
