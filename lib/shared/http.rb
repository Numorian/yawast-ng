# frozen_string_literal: true

require 'securerandom'
require 'json'

module Yawast
  module Shared
    class Http
      def self.setup(proxy, cookie)
        if !proxy.nil? && proxy.include?(':')
          @proxy_host, @proxy_port = proxy.split(':')
          @proxy = true

          puts "Using Proxy: #{proxy}"
        else
          @proxy = false
        end

        @cookie = cookie
        puts "Using Cookie: #{@cookie}" unless @cookie.nil?
      end

      def self.head(uri)
        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          req.head(uri, get_headers)
        rescue # rubocop:disable Style/RescueStandardError
          # if we get here, the HEAD failed - but GET may work
          # so we silently fail back to using GET instead
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_get(uri, get_headers)
          res
        end
      end

      def self.get_raw(uri, headers = nil)
        res = nil

        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_get(uri, get_headers(headers))
        rescue => e # rubocop:disable Style/RescueStandardError
          Yawast::Utilities.puts_error "Error sending request to #{uri} - '#{e.message}'"
        end

        res
      end

      def self.get_with_code(uri, headers = nil)
        res = get_raw(uri, headers)

        {body: res.body, code: res.code}
      end

      def self.get(uri, headers = nil)
        get_with_code(uri, headers)[:body]
      end

      def self.get_json(uri)
        body = ''

        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_get(uri, {'User-Agent' => "YAWAST/#{Yawast::VERSION}"})
          body = res.read_body
        rescue # rubocop:disable Style/RescueStandardError, Lint/HandleExceptions
          # do nothing for now
        end

        JSON.parse body
      end

      def self.put(uri, body, headers = nil)
        ret = nil

        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_put(uri, body, get_headers(headers))
          ret = res.read_body
        rescue # rubocop:disable Style/RescueStandardError, Lint/HandleExceptions
          # do nothing for now
        end

        ret
      end

      def self.get_status_code(uri)
        req = get_http(uri)
        req.use_ssl = uri.scheme == 'https'
        res = req.head(uri, get_headers)

        res.code
      end

      def self.get_http(uri)
        req = if @proxy
                Net::HTTP.new(uri.host, uri.port, @proxy_host, @proxy_port)
              else
                Net::HTTP.new(uri.host, uri.port)
              end

        req
      end

      def self.check_not_found(uri, file)
        fake_uri = uri.copy

        fake_uri.path = if file
                          "/#{SecureRandom.hex}.html"
                        else
                          "/#{SecureRandom.hex}/"
                        end

        if Yawast::Shared::Http.get_status_code(fake_uri) != '404'
          # crazy 404 handling
          return false
        end

        true
      end

      # noinspection RubyStringKeysInHashInspection
      def self.get_headers(extra_headers = nil)
        headers = if @cookie.nil?
                    {'User-Agent' => HTTP_UA}
                  else
                    {'User-Agent' => HTTP_UA, 'Cookie' => @cookie}
                  end

        headers.merge! extra_headers unless extra_headers.nil?

        headers
      end
    end
  end
end
