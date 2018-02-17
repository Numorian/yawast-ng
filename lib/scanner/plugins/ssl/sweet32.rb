module Yawast
  module Scanner
    module Plugins
      module SSL
        class Sweet32
          def self.get_tdes_session_msg_count(uri, limit = 10000)
            Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'limit', limit

            # this method will send a number of HEAD requests to see
            #  if the connection is eventually killed.
            unless check_tdes
              # if the OpenSSL install doesn't support 3DES, bailout
              Yawast::Utilities.puts_error "Your copy of OpenSSL doesn't support 3DES cipher suites - SWEET32 test aborted."
              puts '  See here for more information: https://github.com/adamcaudill/yawast/wiki/OpenSSL-&-3DES-Compatibility'

              Yawast::Shared::Output.log_value 'ssl', 'sweet32', '3des_supported', false
              return
            end

            Yawast::Shared::Output.log_value 'ssl', 'sweet32', '3des_supported', true

            puts 'TLS Session Request Limit: Checking number of requests accepted using 3DES suites...'

            count = 0
            begin
              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              req.keep_alive_timeout = 600
              headers = Yawast::Shared::Http.get_headers

              # we will use HEAD by default, but allow GET if we have issues with HEAD
              use_head = true

              # force 3DES - this is to ensure that 3DES specific limits are caught
              req.ciphers = ['3DES']
              cipher = nil

              # attempt to find a version that supports 3DES
              versions = OpenSSL::SSL::SSLContext::METHODS.find_all { |v| !v.to_s.include?('_client') && !v.to_s.include?('_server')}
              versions.each do |version|
                if version.to_s != 'SSLv23'
                  req.ssl_version = version

                  begin
                    req.start do |http|

                      head = nil
                      begin
                        if use_head
                          head = http.head(uri.path, headers)
                        else
                          head = http.request_get(uri.path, headers)
                        end

                        cipher = http.instance_variable_get(:@socket).io.cipher[0]
                      rescue
                        # check if we are using HEAD or GET. If we've already switched to GET, no need to do this again.
                        if use_head
                          head = http.request_get(uri.path, headers)

                          #if we are here, that means that HEAD failed, but GET didn't, so we'll use GET from now on.
                          use_head = false
                          Yawast::Utilities.puts_error 'Error: HEAD request failed; using GET requests for SWEET32 check...'
                        end
                      end

                      # check to see if this is on Cloudflare - they break Keep-Alive limits, creating a false positive
                      head.each do |k, v|
                        if k.downcase == 'server'
                          if v == 'cloudflare'
                            puts 'Cloudflare server found: SWEET32 mitigated: https://support.cloudflare.com/hc/en-us/articles/231510928'
                          end
                        end
                      end
                    end

                    print "Using #{version} (#{cipher})"

                    Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'tls_version', version
                    Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'tls_cipher', cipher
                    Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'use_head_req', use_head

                    break
                  rescue
                    # we don't care
                  end
                end
              end

              # reset the req object
              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              req.keep_alive_timeout = 600

              req.ciphers = [*cipher]

              req.start do |http|
                limit.times do |i|
                  if use_head
                    http.head(uri.path, headers)
                  else
                    http.request_get(uri.path, headers)
                  end

                  # HACK: to detect transparent disconnects
                  if http.instance_variable_get(:@ssl_context).session_cache_stats[:cache_hits] != 0
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

              if e.message.include?('alert handshake failure') || e.message.include?('no cipher match')
                Yawast::Utilities.puts_info 'TLS Session Request Limit: Server does not support 3DES cipher suites'
              else
                Yawast::Utilities.puts_info "TLS Session Request Limit: Connection terminated after #{count} requests (#{e.message})"
              end

              Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'vulnerable', false
              Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'requests', count
              Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'exception', e.message

              return
            end

            puts
            limit_formatted = limit.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
            Yawast::Utilities.puts_vuln "TLS Session Request Limit: Connection not terminated after #{limit_formatted} requests; possibly vulnerable to SWEET32"

            Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'vulnerable', true
            Yawast::Shared::Output.log_value 'ssl', 'sweet32', 'requests', count
          end

          def self.check_tdes
            ret = false
            puts 'Confirming your OpenSSL supports 3DES cipher suites...'

            # find all versions that don't include '_server' or '_client'
            versions = OpenSSL::SSL::SSLContext::METHODS.find_all { |v| !v.to_s.include?('_client') && !v.to_s.include?('_server')}

            versions.each do |version|
              # ignore SSLv23, as it's an auto-negotiate, which just adds noise
              if version.to_s != 'SSLv23' && version.to_s != 'SSLv2'
                # try to get the list of ciphers supported for each version
                Yawast::Shared::Output.log_append_value 'ssl', 'tls_versions', version.to_s

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
                      ret = true
                    end

                    Yawast::Shared::Output.log_append_value 'ssl', 'tls_ciphers', version.to_s, cipher[0]
                  end
                elsif !get_ciphers_failed
                  Yawast::Utilities.puts_info "\t#{version}: No cipher suites available."
                end
              end
            end

            puts ''
            ret
          end
        end
      end
    end
  end
end
