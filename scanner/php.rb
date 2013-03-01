def php_check_banner(banner)
  #don't bother if this doesn't include PHP
  return if !banner.include? 'PHP/'

  modules = banner.split(' ')

  modules.each do |mod|
    if mod.include? 'PHP/'
      puts_warn "PHP Version: #{mod}"
      puts ''
    end
  end
end
