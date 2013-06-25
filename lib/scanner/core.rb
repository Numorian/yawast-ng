module Yawast
  module Scanner
    class Core
      def self.print_header(uri)
        if @header != true
          Yawast.header
          puts "Scanning: #{uri.to_s}"
          puts ''
        end

        @header = true
      end

      def self.process(uri, options)
        print_header(uri)

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
            Yawast::Scanner::ObjectPresence.check_trace_axd(uri)
            Yawast::Scanner::ObjectPresence.check_elmah_axd(uri)

            get_cms(uri, options)
          end
        rescue => e
          Yawast::Utilities.puts_error "Fatal Error: Can not continue. (#{e.message})"
        end
      end

      def self.get_cms(uri, options)
        print_header(uri)

        body = Yawast::Shared::Http.get(uri)
        Yawast::Scanner::Cms.get_generator(body)
      end
    end
  end
end
