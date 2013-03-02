def nginx_check_banner(banner)
  #don't bother if this doesn't include nginx
  return if !banner.include? 'nginx/'

  puts_warn "nginx Version: #{banner}"
  puts ''
end