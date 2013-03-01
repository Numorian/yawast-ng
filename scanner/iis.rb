def iis_check_banner(banner)
  #don't bother if this doesn't include IIS
  return if !banner.include? 'Microsoft-IIS/'

  puts_warn "IIS Version: #{banner}"
  puts ''
end

def iis_check_asp_banner(uri)
  headers = http_head(uri)

  headers.each do |k, v|
    if k.downcase == 'x-aspnet-version'
      puts_warn "ASP.NET Version: #{v}"
      puts ''
    end
  end
end
