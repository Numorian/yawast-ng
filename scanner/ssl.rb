def ssl_info(uri)
  begin
    #get the x509 cert so we can examine it
    cert = http_peer_cert(uri)

    unless cert.nil?
      puts_info 'Found X509 Certificate:'
      puts_info "\t\tIssuer: #{cert.issuer}"
      puts_info "\t\tVersion: #{cert.version}"
      puts_info "\t\tSerial: #{cert.serial}"
      puts_info "\t\tSubject: #{cert.subject}"
      puts_info "\t\tExpires: #{cert.not_after}"
      puts_info "\t\tExtensions:"
      cert.extensions.each { |ext| puts_info "\t\t\t#{ext}" }
      puts ''
    end
  rescue => e
    puts_error "SSL: Error Reading X509 Details: #{e.message}"
  end
end

def ssl_check_hsts(uri)
  headers = http_head(uri)
  found = ''

  headers.each do |k, v|
    if k.downcase.include? 'strict-transport-security'
      found = k
    end
  end

  if found == ''
    puts_warn 'HSTS: Not Enabled'
  else
    puts_info "HSTS: Enabled (#{found})"
  end
  puts ''
end
