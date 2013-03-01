require 'socket'
require './scanner/http'
require './scanner/apache'
require './scanner/php'
require './scanner/iis'

def scan(uri)
  begin
    server_info(uri)

    #apache specific checks
    apache_check_server_status(uri)
    apache_check_server_info(uri)
  rescue
    puts_error 'Fatal Error: Can not continue.'
  end
end

def server_info(uri)
  begin
    puts_info "Full URI: #{uri}"

    puts_info 'IP(s):'
    dns = Resolv::DNS.new()
    addr = dns.getaddresses(uri.host)
    addr.each do |ip|
      begin
        host_name = dns.getname(ip.to_s)
      rescue
        host_name = 'N/A'
      end

      puts_info "\t\t#{ip} (#{host_name})"
    end
    puts ''

    server = ''
    powered_by = ''
    head = http_head(uri)
    puts_info 'HEAD:'
    head.each do |k, v|
      puts_info "\t\t#{k}: #{v}"

      server = v if k.downcase == 'server'
      powered_by = v if k.downcase == 'x-powered-by'
    end
    puts ''

    if server != ''
      puts_info "Server Banner: #{server}"
      puts ''

      apache_check_banner(server)
      php_check_banner(server)
      iis_check_banner(server)
    end

    if powered_by != ''
      puts_warn "X-Powered-By Header Present: #{powered_by}"
    end
  rescue => e
    puts_error "Error getting basic information: #{e.message}"
    raise
  end
end
