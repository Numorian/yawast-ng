# Require all of the Ruby files in the given directory.
#
# path - The String relative path from here to the directory.
def require_all(path)
  glob = File.join(File.dirname(__FILE__), path, '*.rb')
  Dir[glob].each do |f|
    require f
  end
end

require 'uri'
require 'resolv'
require 'net/http'
require 'socket'

require './lib/string_ext'
require './lib/util'

require_all '/commands'
require_all '/scanner'

module Yawast
  VERSION = '0.0.1'
  DESCRIPTION = 'Yawast: Yet Another Web Application Security Tool'
  HTTP_UA = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; Yawast/#{VERSION})"

  def self.header
    puts "Yawast v#{VERSION} - #{DESCRIPTION}"
    puts 'Copyright (c) 2013 Adam Caudill <adam@adamcaudill.com>'
    puts ''
  end
end
