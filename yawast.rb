#!/usr/bin/env ruby

require 'uri'
require 'resolv'
require './scanner/scan-core'

VERSION = '0.0.1'

def header
  puts "YAWAST v #{VERSION}"
  puts 'Copyright (c) 2013 Adam Caudill <adam@adamcaudill.com>'
  puts ''
end

def usage
  puts './yawast.rb <url>'
  exit(-1)
end

def puts_error(msg)
  puts "[E] #{msg}"
end

def puts_info(msg)
  puts "[I] #{msg}"
end

#start the execution flow
header
usage if ARGV.count != 1

#make sure ARGV[0] is a URL
begin
  uri = URI.parse(ARGV[0])
  
  #see if we can resolve the host
  dns = Resolv::DNS.new()
  addr = dns.getaddress(uri.host)

  uri.path = '/' if uri.path == ''

  puts "Scanning: #{uri.to_s} (#{addr})..."
  puts ''

  #we made it this far, so we should be good to go
  scan(uri)
rescue => e
  puts_error "Invalid URL (#{e.message})"
  usage
end
