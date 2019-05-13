# frozen_string_literal: true

module Yawast
  module Scanner
    class Core < Yawast::Scanner::Base
      def self.print_header
        Yawast.header

        puts "Scanning: #{@uri}"
        puts
      end

      def self.setup(uri, options)
        unless @setup
          @uri = uri

          print_header

          Yawast::Shared::Output.setup @uri, options if options.output != nil
          Yawast::Shared::Output.set_current_uri @uri

          ssl_redirect = Yawast::Scanner::Plugins::SSL::SSL.check_for_ssl_redirect @uri
          if ssl_redirect
            @uri = ssl_redirect
            puts "Server redirects to TLS: Scanning: #{@uri}"
            Yawast::Shared::Output.log_value 'server_tls_redirect', @uri
          end
          @uri = check_www_redirect @uri.copy

          Yawast::Scanner::Plugins::SSL::SSL.set_openssl_options

          Yawast::Scanner::Plugins::DNS::Generic.dns_info @uri, options unless options.nodns
        end

        @setup = true
      end

      def self.process(uri, options)
        # get the start time, so we can display elapsed time
        start_time = Time.now

        setup(uri, options)

        begin
          # setup the proxy
          Yawast::Shared::Http.setup(options.proxy, options.cookie)

          # cache the HEAD result, so that we can minimize hits
          head = get_head
          Yawast::Scanner::Generic.head_info(head, @uri)

          # perform SSL checks
          check_ssl(@uri, options, head)

          # process the 'scan' stuff that goes beyond 'head'
          unless options.head
            # connection details for SSL
            Yawast::Scanner::Plugins::SSL::SSL.ssl_connection_info @uri

            if Yawast.options.vuln_scan
              # new scanner-----------------------------------------------------
              # this is the new model, that will eventually become the default--
              # ----------------------------------------------------------------

              Yawast::Scanner::VulnScan.scan(@uri, options, head)
            else
              # legacy checks --------------------------------------------------
              # try not to break these, until the old scanner model is removed--
              # ----------------------------------------------------------------

              # server specific checks
              Yawast::Scanner::Plugins::Servers::Apache.check_all(@uri)
              Yawast::Scanner::Plugins::Servers::Nginx.check_all(@uri)
              Yawast::Scanner::Plugins::Servers::Iis.check_all(@uri, head)

              Yawast::Scanner::Plugins::Http::FilePresence.check_all @uri, options.files

              # generic header checks
              Yawast::Scanner::Plugins::Http::Generic.check_propfind(@uri)
              Yawast::Scanner::Plugins::Http::Generic.check_options(@uri)
              Yawast::Scanner::Plugins::Http::Generic.check_trace(@uri)

              Yawast::Scanner::Plugins::Spider::Spider.spider(@uri) if options.spider
            end

            # check for common directories
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
        rescue => e # rubocop:disable Style/RescueStandardError
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
          head = get_head if head.nil?

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

      def self.check_www_redirect(uri)
        # check to see if the server redirects us to the WWW or non-WWW version of the domain
        head = Yawast::Shared::Http.head(uri)

        unless head['location'].nil?
          begin
            location = URI.parse(head['location'])

            if location.host.start_with?('www') && !uri.host.start_with?('www') && location.host == "www.#{uri.host}"
              uri.host = location.host
              uri.scheme = location.scheme
              Yawast::Utilities.puts_raw "WWW Redirect: Scanning #{uri}"

              return uri
            elsif !location.host.start_with?('www') && uri.host.start_with?('www') && uri.host == "www.#{location.host}"
              uri.host = location.host
              uri.scheme = location.scheme
              Yawast::Utilities.puts_raw "Non-WWW Redirect: Scanning: #{uri}"

              return uri
            end
          rescue # rubocop:disable Style/RescueStandardError, Lint/HandleExceptions
            # we don't care if this fails
          end
        end

        uri
      end

      def self.get_head
        begin
          head = Yawast::Shared::Http.head(@uri)
          Yawast::Shared::Output.log_hash 'http', 'head', @uri, head.to_hash

          unless head['location'].nil?
            Yawast::Utilities.puts_info "HEAD received redirect to '#{head['location']}'; following."
            head = Yawast::Shared::Http.head(URI.parse(head['location']))
            Yawast::Shared::Output.log_hash 'http', 'head', head['location'], head.to_hash
          end

          head
        rescue => e # rubocop:disable Style/RescueStandardError
          Yawast::Utilities.puts_error "Fatal Connection Error: Unable to complete HEAD request from '#{@uri}' (#{e.class}: #{e.message})"
          exit 1
        end
      end
    end
  end
end
