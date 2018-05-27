module Yawast
  module Scanner
    module Plugins
      module SSL
        class SSL
          def self.print_precert(cert)
            scts = cert.extensions.find {|e| e.oid == 'ct_precert_scts'}

            unless scts.nil?
              Yawast::Utilities.puts_info "\t\tSCTs:"
              scts.value.split("\n").each { |line| puts "\t\t\t#{line}" }
            end
          end

          def self.print_cert_hash(cert)
            hash = Digest::SHA1.hexdigest(cert.to_der)
            Yawast::Utilities.puts_info "\t\tHash: #{hash}"
            puts "\t\t\thttps://censys.io/certificates?q=#{hash}"
            puts "\t\t\thttps://crt.sh/?q=#{hash}"
          end

          def self.check_hsts(head)
            found = ''

            head.each do |k, v|
              if k.downcase.include? 'strict-transport-security'
                found = "#{k}: #{v}"
              end
            end

            if found == ''
              Yawast::Utilities.puts_warn 'HSTS: Not Enabled'
            else
              Yawast::Utilities.puts_info "HSTS: Enabled (#{found})"
            end
          end

          def self.check_hsts_preload(uri)
            begin
              info = Yawast::Shared::Http.get_json URI("https://hstspreload.com/api/v1/status/#{uri.host}")

              chrome = info['chrome'] != nil
              firefox = info['firefox'] != nil
              tor = info['tor'] != nil

              Yawast::Utilities.puts_info "HSTS Preload: Chrome - #{chrome}; Firefox - #{firefox}; Tor - #{tor}"
            rescue => e
              Yawast::Utilities.puts_error "Error getting HSTS preload information: #{e.message}"
            end
          end

          def self.set_openssl_options
            # change certain defaults, to make things work better
            # we prefer RSA, to avoid issues with small DH keys
            OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers] = 'RSA:ALL:COMPLEMENTOFALL'
            OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:verify_mode] = OpenSSL::SSL::VERIFY_NONE
            OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options] = OpenSSL::SSL::OP_ALL
          end

          def self.check_for_ssl_redirect(uri)
            # check to see if the site redirects to SSL by default
            if uri.scheme != 'https'
              head = Yawast::Shared::Http.head(uri)

              if head['Location'] != nil
                begin
                  location = URI.parse(head['Location'])

                  if location.scheme == 'https'
                    # we run this through extract_uri as it performs a few checks we need
                    return Yawast::Shared::Uri.extract_uri location.to_s
                  end
                rescue
                  # we don't care if this fails
                end
              end
            end

            return nil
          end

          def self.ssl_connection_info(uri)
            begin
              # we only care if this is https
              if uri.scheme == 'https'
                # setup the connection
                socket = TCPSocket.new(uri.host, uri.port)

                ctx = OpenSSL::SSL::SSLContext.new
                ctx.ciphers = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]

                ssl = OpenSSL::SSL::SSLSocket.new(socket, ctx)
                ssl.hostname = uri.host
                ssl.connect

                # this provides a bunch of useful info, that's already formatted
                #  instead of building this manually, we'll let OpenSSL do the
                session_info = ssl.session.to_text
                puts session_info

                Yawast::Shared::Output.log_value 'ssl', 'session', 'info', session_info

                puts
              end
            rescue => e
              Yawast::Utilities.puts_error "SSL Information: Error Getting Details: #{e.message}"
            end
          end
        end
      end
    end
  end
end
