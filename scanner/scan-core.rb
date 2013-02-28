require 'socket'
require './scanner/http'
require './scanner/apache'

def scan(uri)
  begin
    server_info(uri)

      #apache specific checks
      apache_check_server_status(uri)
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
      host_name = dns.getname(ip.to_s)
      puts_info "\t\t#{ip} (#{host_name})"
    end
    puts ''

    server = ''
    head = http_head(uri)
    puts_info 'HEAD:'
    head.each do |k, v|
      puts_info "\t\t#{k}: #{v}"

      server = v if k.downcase == 'server'
    end
    puts ''

    if server != ''
      puts_warn "Possible information disclosure (server banner): #{server}"
    end
  rescue => e
    puts_error "Error getting basic information: #{e.message}"
    raise
  end
end
