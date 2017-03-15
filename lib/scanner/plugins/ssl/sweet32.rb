module Yawast
  module Scanner
    module Plugins
      module SSL
        class Sweet32
          def self.get_tdes_session_msg_count(uri)
            # this method will send a number of HEAD requests to see
            #  if the connection is eventually killed.
            puts 'TLS Session Request Limit: Checking number of requests accepted using 3DES suites...'

            count = 0
            begin
              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              req.keep_alive_timeout = 600
              headers = Yawast::Shared::Http.get_headers

              #force 3DES - this is to ensure that 3DES specific limits are caught
              req.ciphers = ['3DES']

              #attempt to find a version that supports 3DES
              versions = OpenSSL::SSL::SSLContext::METHODS.find_all { |v| !v.to_s.include?('_client') && !v.to_s.include?('_server')}
              versions.each do |version|
                if version.to_s != 'SSLv23'
                  req.ssl_version = version

                  begin
                    req.start do |http|
                      head = http.head(uri.path, headers)

                      #check to see if this is on Cloudflare - they break Keep-Alive limits, creating a false positive
                      head.each do |k, v|
                        if k.downcase == 'server'
                          if v == 'cloudflare-nginx'
                            puts 'Cloudflare server found: SWEET32 mitigated: https://support.cloudflare.com/hc/en-us/articles/231510928'
                            return
                          end
                        end
                      end
                    end

                    print "Using #{version}"
                    break
                  rescue
                    #we don't care
                  end
                end
              end

              req.start do |http|
                #cache the number of hits
                hits = http.instance_variable_get(:@ssl_context).session_cache_stats[:cache_hits]
                10000.times do |i|
                  http.head(uri.path, headers)

                  # hack to detect transparent disconnects
                  if http.instance_variable_get(:@ssl_context).session_cache_stats[:cache_hits] != hits
                    raise 'TLS Reconnected'
                  end

                  count += 1

                  if i % 20 == 0
                    print '.'
                  end
                end
              end
            rescue => e
              puts

              if e.message.include? 'alert handshake failure'
                Yawast::Utilities.puts_info 'TLS Session Request Limit: Server does not support 3DES cipher suites'
              else
                Yawast::Utilities.puts_info "TLS Session Request Limit: Connection terminated after #{count} requests (#{e.message})"
              end

              return
            end

            puts
            Yawast::Utilities.puts_vuln 'TLS Session Request Limit: Connection not terminated after 10,000 requests; possibly vulnerable to SWEET32'
          end
        end
      end
    end
  end
end
