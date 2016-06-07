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
require_all '/shared'

module Yawast
  VERSION = '0.1.0'
  DESCRIPTION = 'YAWAST: Antecedent Web Application Security Toolkit'
  HTTP_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Yawast/#{VERSION} Chrome/52.0.2743.24 Safari/537.36"
  def self.header
    puts "YAWAST v#{VERSION} - #{DESCRIPTION}"
    puts ' Copyright (c) 2013-2016 Adam Caudill <adam@adamcaudill.com>'
    puts ' Support & Documentation: https://github.com/adamcaudill/yawast'
    puts " Ruby #{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}; #{OpenSSL::OPENSSL_VERSION} (#{RUBY_PLATFORM})"
    puts ''
  end

  def self.set_openssl_options
    #change certain defaults, to make things work better
    #we prefer RSA, to avoid issues with small DH keys
    OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers] = "RSA:ALL:COMPLEMENTOFALL"
    OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:verify_mode] = OpenSSL::SSL::VERIFY_NONE
    OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options] = OpenSSL::SSL::OP_ALL
  end
end
