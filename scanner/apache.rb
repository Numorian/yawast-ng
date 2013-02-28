def apache_check_server_status(uri)
  uri.path = '/server-status'
  uri.query = '' if uri.query != nil

  ret = http_get(uri)

  if ret.include? 'Apache Server Status'
    puts_vuln "Apache Server Status page found: #{uri}"
  end
end
