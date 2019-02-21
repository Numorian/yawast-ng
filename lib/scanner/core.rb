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

          if options.output != nil
            Yawast::Shared::Output.setup @uri, options
          end

          ssl_redirect = Yawast::Scanner::Plugins::SSL::SSL.check_for_ssl_redirect @uri
          if ssl_redirect
            @uri = ssl_redirect
            puts "Server redirects to TLS: Scanning: #{@uri}"
            Yawast::Shared::Output.log_value 'server_tls_redirect', @uri
          end

          Yawast::Scanner::Plugins::SSL::SSL.set_openssl_options

          unless options.nodns
            Yawast::Scanner::Plugins::DNS::Generic.dns_info @uri, options
          end
        end

        @setup = true
      end

      def self.process(uri, options)
        # get the start time, so we can display elapsed time
        start_time = Time.now

        setup(uri, options)

        begin
          #setup the proxy
          Yawast::Shared::Http.setup(options.proxy, options.cookie)

          #cache the HEAD result, so that we can minimize hits
          head = get_head
          Yawast::Shared::Output.log_hash 'http', 'head', 'raw', head.to_hash
          Yawast::Scanner::Generic.head_info(head, @uri)

          #perfom SSL checks
          check_ssl(@uri, options, head)

          #process the 'scan' stuff that goes beyond 'head'
          unless options.head
            # connection details for SSL
            Yawast::Scanner::Plugins::SSL::SSL.ssl_connection_info @uri

            # server specific checks
            Yawast::Scanner::Plugins::Servers::Apache.check_all(@uri)
            Yawast::Scanner::Plugins::Servers::Iis.check_all(@uri, head)

            Yawast::Scanner::Plugins::Http::FilePresence.check_all @uri, options.files

            # generic header checks
            Yawast::Scanner::Plugins::Http::Generic.check_propfind(@uri)
            Yawast::Scanner::Plugins::Http::Generic.check_options(@uri)
            Yawast::Scanner::Plugins::Http::Generic.check_trace(@uri)

            #TODO: Add check for option
            Yawast::Scanner::VulnScan.scan(@uri, options)

            if options.spider
              Yawast::Scanner::Plugins::Spider::Spider.spider(@uri)
            end

            #check for common directories
            if options.dir
              Yawast::Scanner::Plugins::Http::DirectorySearch.search @uri, options.dirrecursive, options.dirlistredir
            end

            get_cms(@uri, options)
          end

          # get the total time to complete the scan. this works as long as the scan take
          # less than 24 hours. if a scan is that long, we have bigger problems
          elapsed_time = Time.at(Time.now - start_time).utc.strftime('%H:%M:%S')

          Yawast::Shared::Output.write_file
          puts "Scan complete (#{elapsed_time})."
        rescue => e
          Yawast::Utilities.puts_error "Fatal Error: Can not continue. (#{e.class}: #{e.message})"
        end
      end

      def self.get_cms(uri, options)
        setup(uri, options)

        body = Yawast::Shared::Http.get(uri)
        Yawast::Scanner::Plugins::Applications::CMS::Generic.get_generator(body)
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

          Yawast::Scanner::Plugins::SSL::SSL.check_hsts(head)
          Yawast::Scanner::Plugins::SSL::SSL.check_hsts_preload @uri
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
