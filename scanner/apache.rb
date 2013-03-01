def apache_check_banner(banner)
  #don't bother if this doesn't look like Apache
  return if !banner.include? 'Apache'

  modules = banner.split(' ')

  if modules.count == 1
    #if there's only one item, it's just the server, no modules
    puts_info "Apache Server: #{banner}"
  else
    puts_warn 'Apache Server: Module listing enabled'
    modules.each { |mod| puts_warn "\t\t#{mod}" }
  end

  puts ''
end

def apache_check_server_status(uri)
  uri.path = '/server-status'
  uri.query = '' if uri.query != nil

  ret = http_get(uri)

  if ret.include? 'Apache Server Status'
    puts_vuln "Apache Server Status page found: #{uri}"
  end

  puts ''
end

def apache_check_server_info(uri)
  uri.path = '/server-info'
  uri.query = '' if uri.query != nil

  ret = http_get(uri)

  if ret.include? 'Apache Server Information'
    puts_vuln "Apache Server Info page found: #{uri}"
  end

  puts ''
end
