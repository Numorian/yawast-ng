module Yawast
  module Scanner
    module Plugins
      module DNS
        class Generic
          def self.dns_info(uri, options)
            begin
              puts 'DNS Information:'
              root_domain = PublicSuffix.parse(uri.host).domain

              dns = Resolv::DNS.new
              Resolv::DNS.open do |resv|
                a = resv.getresources(uri.host, Resolv::DNS::Resource::IN::A)
                unless a.empty?
                  a.each do |ip|
                    begin
                      host_name = dns.getname(ip.address)
                    rescue
                      host_name = 'N/A'
                    end

                    Yawast::Utilities.puts_info "\t\t#{ip.address} (#{host_name})"

                    # if address is private, force internal SSL mode, don't show links
                    if IPAddr.new(ip.address.to_s, Socket::AF_INET).private?
                      options.internalssl = true
                    else
                      #show network info
                      Yawast::Utilities.puts_info "\t\t\t#{get_network_info(ip.address)}"

                      puts "\t\t\thttps://www.shodan.io/host/#{ip.address}"
                      puts "\t\t\thttps://censys.io/ipv4/#{ip.address}"
                    end
                  end
                end

                aaaa = resv.getresources(uri.host, Resolv::DNS::Resource::IN::AAAA)
                unless aaaa.empty?
                  aaaa.each do |ip|
                    begin
                      host_name = dns.getname(ip.address)
                    rescue
                      host_name = 'N/A'
                    end

                    Yawast::Utilities.puts_info "\t\t#{ip.address} (#{host_name})"

                    # if address is private, force internal SSL mode, don't show links
                    if IPAddr.new(ip.address.to_s, Socket::AF_INET6).private?
                      options.internalssl = true
                    else
                      #show network info
                      Yawast::Utilities.puts_info "\t\t\t#{get_network_info(ip.address)}"

                      puts "\t\t\thttps://www.shodan.io/host/#{ip.address.to_s.downcase}"
                    end
                  end
                end

                txt = resv.getresources(uri.host, Resolv::DNS::Resource::IN::TXT)
                unless txt.empty?
                  txt.each do |rec|
                    Yawast::Utilities.puts_info "\t\tTXT: #{rec.data}"
                  end
                end

                #check for higher-level TXT records, if we aren't already at the top
                if root_domain != uri.host
                  txt = resv.getresources(root_domain, Resolv::DNS::Resource::IN::TXT)
                  unless txt.empty?
                    txt.each do |rec|
                      Yawast::Utilities.puts_info "\t\tTXT (#{root_domain}): #{rec.data}"
                    end
                  end
                end

                mx = resv.getresources(uri.host, Resolv::DNS::Resource::IN::MX)
                unless mx.empty?
                  mx.each do |rec|
                    begin
                      ip = resv.getaddress rec.exchange

                      Yawast::Utilities.puts_info "\t\tMX: #{rec.exchange} (#{rec.preference}) - #{ip} (#{get_network_info(ip.to_s)})"
                    rescue => e
                      Yawast::Utilities.puts_error "\t\tMX: #{rec.exchange} (#{rec.preference}) - Error: #{e.message})"
                    end
                  end
                end

                #check for higher-level MX records, if we aren't already at the top
                if root_domain != uri.host
                  mx = resv.getresources(root_domain, Resolv::DNS::Resource::IN::MX)
                  unless mx.empty?
                    mx.each do |rec|
                      begin
                        ip = resv.getaddress rec.exchange

                        Yawast::Utilities.puts_info "\t\tMX (#{root_domain}): #{rec.exchange} (#{rec.preference}) - #{ip} (#{get_network_info(ip.to_s)})"
                      rescue => e
                        Yawast::Utilities.puts_info "\t\tMX (#{root_domain}): #{rec.exchange} (#{rec.preference}) - Error: #{e.message})"
                      end
                    end
                  end
                end

                ns = resv.getresources(root_domain, Resolv::DNS::Resource::IN::NS)
                unless ns.empty?
                  ns.each do |rec|
                    ip = resv.getaddress rec.name

                    Yawast::Utilities.puts_info "\t\tNS: #{rec.name} - #{ip} (#{get_network_info(ip.to_s)})"
                  end
                end

                if options.srv
                  find_srv root_domain, resv
                end

                if options.subdomains
                  find_subdomains root_domain, resv
                end
              end

              #get the CAA info
              Yawast::Scanner::Plugins::DNS::CAA.caa_info uri

              puts
            rescue => e
              Yawast::Utilities.puts_error "Error getting basic information: #{e.message}"
              raise
            end
          end

          def self.find_srv(root_domain, resv)
            File.open(File.dirname(__FILE__) + '/../../../resources/srv_list.txt', 'r') do |f|
              f.each_line do |line|
                host = line.strip + '.' + root_domain
                begin
                  srv = resv.getresources(host, Resolv::DNS::Resource::IN::SRV)

                  unless srv.empty?
                    srv.each do |rec|
                      ip = resv.getaddress rec.target

                      Yawast::Utilities.puts_info "\t\tSRV: #{host}: #{rec.target}:#{rec.port} - #{ip} (#{get_network_info(ip.to_s)})"
                    end
                  end
                rescue
                  #if this fails, don't really care
                end
              end
            end
          end

          def self.find_subdomains(root_domain, resv)
            File.open(File.dirname(__FILE__) + '/../../../resources/subdomain_list.txt', 'r') do |f|
              f.each_line do |line|
                host = line.strip + '.' + root_domain

                begin
                  a = resv.getresources(host, Resolv::DNS::Resource::IN::A)

                  unless a.empty?
                    a.each do |ip|
                      if IPAddr.new(ip.address.to_s, Socket::AF_INET).private?
                        Yawast::Utilities.puts_info "\t\tA: #{host}: #{ip.address}"
                      else
                        Yawast::Utilities.puts_info "\t\tA: #{host}: #{ip.address} (#{get_network_info(ip.address)})"
                      end
                    end
                  end
                rescue
                  #if this fails, don't really care
                end
              end
            end
          end

          def self.get_network_info(ip)
            #check to see if we have this one cached
            @netinfo = Hash.new if @netinfo == nil
            return @netinfo[ip] if @netinfo[ip] != nil

            #check to see if this has failed, if so, skip it. We do this to avoid repeated timeouts if outbound
            #connections are blocked.
            @netinfo_failed = false if @netinfo_failed == nil
            return 'Network Information disabled due to prior failure' if @netinfo_failed

            begin
              network_info = Yawast::Shared::Http.get_json URI("https://api.iptoasn.com/v1/as/ip/#{ip}")

              ret = "#{network_info['as_country_code']} - #{network_info['as_description']}"
              @netinfo[ip] = ret

              return ret
            rescue => e
              @netinfo_failed = true
              return "Error: getting network information failed (#{e.message})"
            end
          end
        end
      end
    end
  end
end
