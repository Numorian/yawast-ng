module Yawast
  module Scanner
    class Core
      def self.print_header
        Yawast.header

        puts "Scanning: #{@uri}"
        puts
      end

      def self.setup(uri, options)
        unless @setup
          @uri = uri

          print_header

          ssl_redirect = check_for_ssl_redirect
          if ssl_redirect
            @uri = ssl_redirect
            puts "Server redirects to TLS: Scanning: #{@uri}"
          end

          Yawast.set_openssl_options

          unless options.nodns
            Yawast::Scanner::Plugins::DNS::Generic.dns_info @uri, options
          end
        end

        @setup = true
      end

      def self.process(uri, options)
        setup(uri, options)

        begin
          #setup the proxy
          Yawast::Shared::Http.setup(options.proxy, options.cookie)

          #cache the HEAD result, so that we can minimize hits
          head = get_head
          Yawast::Scanner::Generic.head_info(head, @uri)

          #perfom SSL checks
          check_ssl(@uri, options, head)

          #process the 'scan' stuff that goes beyond 'head'
          unless options.head
            # connection details for SSL
            Yawast::Scanner::Generic.ssl_connection_info @uri

            # server specific checks
            Yawast::Scanner::Apache.check_all(@uri)
            Yawast::Scanner::Iis.check_all(@uri, head)

            Yawast::Scanner::Plugins::Http::FilePresence.check_all @uri, options.files

            # generic header checks
            Yawast::Scanner::Generic.check_propfind(@uri)
            Yawast::Scanner::Generic.check_options(@uri)
            Yawast::Scanner::Generic.check_trace(@uri)

            #check for common directories
            if options.dir
              Yawast::Scanner::Plugins::Http::DirectorySearch.search @uri, options.dirrecursive, options.dirlistredir
            end

            get_cms(@uri, options)
          end

          puts 'Scan complete.'
        rescue => e
          Yawast::Utilities.puts_error "Fatal Error: Can not continue. (#{e.class}: #{e.message})"
        end
      end

      def self.get_cms(uri, options)
        setup(uri, options)

        body = Yawast::Shared::Http.get(uri)
        Yawast::Scanner::Cms.get_generator(body)
      end

      def self.check_for_ssl_redirect
        #check to see if the site redirects to SSL by default
        if @uri.scheme != 'https'
          head = Yawast::Shared::Http.head(@uri)

          if head['Location'] != nil
            begin
              location = URI.parse(head['Location'])

              if location.scheme == 'https'
                #we run this through extract_uri as it performs a few checks we need
                return Yawast::Shared::Uri.extract_uri location.to_s
              end
            rescue
              #we don't care if this fails
            end
          end
        end

        return nil
      end

      def self.check_ssl(uri, options, head)
        setup(uri, options)

        if @uri.scheme == 'https' && !options.nossl
          head = get_head if head == nil

          if options.internalssl || IPAddress.valid?(@uri.host) || @uri.port != 443
            Yawast::Scanner::Ssl.info(@uri, !options.nociphers, options.tdessessioncount)
          else
            Yawast::Scanner::SslLabs.info(@uri, options.tdessessioncount)
          end

          Yawast::Scanner::Ssl.check_hsts(head)
          Yawast::Scanner::Ssl.check_hsts_preload @uri
        elsif @uri.scheme == 'http'
          puts 'Skipping TLS checks; URL is not HTTPS'
        end
      end

      def self.get_head()
        begin
          Yawast::Shared::Http.head(@uri)
        rescue => e
          Yawast::Utilities.puts_error "Fatal Connection Error: Unable to complete HEAD request from '#{@uri}' (#{e.class}: #{e.message})"
          exit 1
        end
      end
    end
  end
end
