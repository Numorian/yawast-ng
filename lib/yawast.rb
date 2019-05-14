# frozen_string_literal: true

# Require all of the Ruby files in the given directory.
#
# path - The String relative path from here to the directory.
def require_all(path)
  glob = File.join(File.dirname(__FILE__), path + '/**/', '*.rb')
  Dir[glob].each do |f|
    require f
  end
end

require 'uri'
require 'resolv'
require 'net/http'
require 'socket'
require 'colorize'

require File.dirname(__FILE__) + '/string_ext'
require File.dirname(__FILE__) + '/uri_ext'
require File.dirname(__FILE__) + '/util'
require File.dirname(__FILE__) + '/version'

require_all '/commands'
require_all '/scanner'
require_all '/shared'

module Yawast
  DESCRIPTION = 'The YAWAST Antecedent Web Application Security Toolkit'
  HTTP_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) YAWAST/#{VERSION} Chrome/61.0.3163.100 Safari/537.36"

  def self.header
    # prevent multiple runs
    return if @header

    encoding = "#{Encoding.default_external}/#{Encoding.default_internal}/#{Encoding.find('locale')}"

    puts '__   _____  _    _  ___   _____ _____ '
    puts '\ \ / / _ \| |  | |/ _ \ /  ___|_   _|'
    puts ' \ V / /_\ \ |  | / /_\ \\\ `--.  | |  '
    puts '  \ /|  _  | |/\| |  _  | `--. \ | |  '
    puts '  | || | | \  /\  / | | |/\__/ / | |  '
    puts '  \_/\_| |_/\/  \/\_| |_/\____/  \_/  '
    puts ''
    puts "YAWAST v#{VERSION} - #{DESCRIPTION}"
    puts ' Copyright (c) 2013-2019 Adam Caudill <adam@adamcaudill.com>'
    puts ' Support & Documentation: https://github.com/adamcaudill/yawast'
    puts " Ruby #{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}; #{OpenSSL::OPENSSL_VERSION} (#{RUBY_PLATFORM}); #{encoding}"
    puts " Started at #{Time.now.strftime('%Y-%m-%d %H:%M:%S %Z')}"

    begin
      version = Yawast::Shared::Http.get_json(URI('https://rubygems.org/api/v1/versions/yawast/latest.json'))['version']

      if version != VERSION
        puts " Latest Version: YAWAST v#{version} is the officially supported version, please update.".blue
      end
    rescue
      # we don't care, this is a best effort check
    end

    puts ''
    @header = true
  end

  def self.options
    @options
  end

  def self.options=(opts)
    @options = opts
  end

  STDOUT.sync = true

  trap 'SIGINT' do
    puts
    puts 'Scan cancelled by user.'

    # attempt to save the output
    Yawast::Shared::Output.write_file

    exit 0
  end
end
