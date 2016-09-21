require 'openssl'
require 'openssl-extensions/all'

module Yawast
  module Scanner
    class Cert
      def setup
        unless @setup

          Yawast.header
          puts

          Yawast.set_openssl_options
        end

        @setup = true
      end

      def get_certs(options)
        setup

        content = File.readlines options.input

        pool_size = 16
        jobs = Queue.new
        @results = Queue.new

        content.map do |domain|
          jobs.push domain.trim
        end

        workers = (pool_size).times.map do
          Thread.new do
            begin
              while (domain = jobs.pop(true))
                process domain
              end
            rescue ThreadError
              #do nothing
            end
          end
        end

        results = Thread.new do
          begin
            while true
              if @results.length > 0
                out = @results.pop(true)
                Yawast::Utilities.puts_info out
              end
            end
          rescue ThreadError
            #do nothing
          end
        end

        workers.map(&:join)
        results.terminate

        puts
        puts
        puts 'Done.'
      end

      def process(domain)
        return if domain == ''

        begin
          socket = Socket.tcp(domain, 443, opts={connect_timeout: 3})

          ctx = OpenSSL::SSL::SSLContext.new
          ctx.ciphers = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]

          ssl = OpenSSL::SSL::SSLSocket.new(socket, ctx)
          ssl.hostname = domain

          Timeout::timeout(5) {
            ssl.connect
          }

          cert = ssl.peer_cert

          if cert.nil?
            raise 'No certificate received.'
          else
            @results.push "#{domain}: Issuer: '#{cert.issuer.common_name}' / '#{cert.issuer.organization}' Serial: #{cert.serial}"
          end
        rescue
          unless domain.start_with? 'www.'
            process 'www.' + domain
          end
        ensure
          ssl.sysclose if ssl
          socket.close if socket
        end
      end
    end
  end
end
