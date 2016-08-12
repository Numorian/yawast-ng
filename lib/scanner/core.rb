module Yawast
  module Scanner
    class Core
      def self.print_header(uri)
        Yawast.header

        puts "Scanning: #{uri.to_s}"

        begin
          dns = Resolv::DNS.new()
          addrs = dns.getaddresses(uri.host)

          addrs.each do |ip|
            begin
              puts "\t#{ip} - #{dns.getname(ip.to_s)}"
            rescue
              puts "\t#{ip}"
            end
          end
        rescue
          # meh.
        end

        puts ''
      end

      def self.setup(uri)
        unless @setup
          print_header(uri)
          Yawast.set_openssl_options
        end

        @setup = true
      end

      def self.process(uri, options)
        setup(uri)

        begin
          #setup the proxy
          Yawast::Shared::Http.setup(options.proxy, options.cookie)

          #cache the HEAD result, so that we can minimize hits
          head = Yawast::Shared::Http.head(uri)

          Yawast::Scanner::Generic.server_info(uri)
          Yawast::Scanner::Generic.head_info(head)

          #perfom SSL checks
          check_ssl(uri, options, head)

          #process the 'scan' stuff that goes beyond 'head'
          unless options.head
            #server specific checks
            Yawast::Scanner::Apache.check_all(uri, head)
            Yawast::Scanner::Iis.check_all(uri, head)

            Yawast::Scanner::ObjectPresence.check_source_control(uri)
            Yawast::Scanner::ObjectPresence.check_sitemap(uri)
            Yawast::Scanner::ObjectPresence.check_cross_domain(uri)
            Yawast::Scanner::ObjectPresence.check_wsftp_log(uri)
            Yawast::Scanner::ObjectPresence.check_trace_axd(uri)
            Yawast::Scanner::ObjectPresence.check_elmah_axd(uri)
            Yawast::Scanner::ObjectPresence.check_readme_html(uri)
            Yawast::Scanner::ObjectPresence.check_release_notes_txt(uri)

            Yawast::Scanner::Generic.check_propfind(uri)
            Yawast::Scanner::Generic.check_options(uri)
            Yawast::Scanner::Generic.check_trace(uri)

            #check for common directories
            if options.dir
              Yawast::Scanner::Generic.directory_search(uri)
            end

            get_cms(uri, options)

            puts 'Scan complete.'
          end
        rescue => e
          Yawast::Utilities.puts_error "Fatal Error: Can not continue. (#{e.message})"
        end
      end

      def self.get_cms(uri, options)
        setup(uri)

        body = Yawast::Shared::Http.get(uri)
        Yawast::Scanner::Cms.get_generator(body)
      end

      def self.check_ssl(uri, options, head)
        setup(uri)

        if uri.scheme == 'https' && !options.nossl
          head = Yawast::Shared::Http.head(uri) if head == nil

          Yawast::Scanner::Ssl.info(uri, !options.nociphers)
          Yawast::Scanner::Ssl.check_hsts(head)
        end
      end
    end
  end
end
