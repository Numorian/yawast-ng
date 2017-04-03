module Yawast
  module Scanner
    module Plugins
      module SSL
        class Sweet32
          def self.get_tdes_session_msg_count(uri)
            # this method will send a number of HEAD requests to see
            #  if the connection is eventually killed.
            unless check_tdes(uri)
              #if the OpenSSL install doesn't support 3DES, bailout
              Yawast::Utilities.puts_error "Your copy of OpenSSL doesn't support 3DES cipher suites - SWEET32 test aborted."
              return
            end

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

          def self.check_tdes(uri)
            puts 'Confirming your OpenSSL supports 3DES cipher suites...'

            dns = Resolv::DNS.new

            if IPAddress.valid? uri.host
              ip = IPAddress.parse uri.host
            else
              ip = dns.getaddresses(uri.host)[0]
            end

            #find all versions that don't include '_server' or '_client'
            versions = OpenSSL::SSL::SSLContext::METHODS.find_all { |v| !v.to_s.include?('_client') && !v.to_s.include?('_server')}

            versions.each do |version|
              #ignore SSLv23, as it's an auto-negotiate, which just adds noise
              if version.to_s != 'SSLv23' && version.to_s != 'SSLv2'
                #try to get the list of ciphers supported for each version
                ciphers = nil

                get_ciphers_failed = false
                begin
                  ciphers = OpenSSL::SSL::SSLContext.new(version).ciphers
                rescue => e
                  Yawast::Utilities.puts_error "\tError getting cipher suites for #{version}, skipping. (#{e.message})"
                  get_ciphers_failed = true
                end

                if ciphers != nil
                  ciphers.each do |cipher|
                    if cipher[0].include?('3DES') || cipher[0].include?('CBC3')
                      return true
                    end
                  end
                elsif !get_ciphers_failed
                  Yawast::Utilities.puts_info "\t#{version}: No cipher suites available."
                end
              end
            end

            puts ''
            return false
          end
        end
      end
    end
  end
end
