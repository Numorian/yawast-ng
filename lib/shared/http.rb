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
        rescue
          # if we get here, the HEAD failed - but GET may work
          # so we silently fail back to using GET instead
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_get(uri, get_headers)
          res
        end
      end

      def self.get(uri, headers = nil)
        body = ''

        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_get(uri, get_headers(headers))
          body = res.read_body
        rescue
          # do nothing for now
        end

        body
      end

      def self.get_json(uri)
        body = ''

        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_get(uri, 'User-Agent' => "YAWAST/#{Yawast::VERSION}")
          body = res.read_body
        rescue
          # do nothing for now
        end

        JSON.parse body
      end

      def self.put(uri, body, headers = nil)
        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_put(uri, body, get_headers(headers))
        rescue
          # do nothing for now
        end

        res.read_body
      end

      def self.get_status_code(uri)
        req = get_http(uri)
        req.use_ssl = uri.scheme == 'https'
        res = req.head(uri, get_headers)
        res.code
      end

      def self.get_http(uri)
        if @proxy
          req = Net::HTTP.new(uri.host, uri.port, @proxy_host, @proxy_port)
        else
          req = Net::HTTP.new(uri.host, uri.port)
        end

        req
      end

      def self.check_not_found(uri, file)
        fake_uri = uri.copy

        if file
          fake_uri.path = "/#{SecureRandom.hex}.html"
        else
          fake_uri.path = "/#{SecureRandom.hex}/"
        end

        if Yawast::Shared::Http.get_status_code(fake_uri) != '404'
          # crazy 404 handling
          return false
        end

        return true
      end

      # noinspection RubyStringKeysInHashInspection
      def self.get_headers(extra_headers = nil)
        if @cookie == nil
          headers = { 'User-Agent' => HTTP_UA }
        else
          headers = { 'User-Agent' => HTTP_UA, 'Cookie' => @cookie }
        end

        headers.merge! extra_headers unless extra_headers.nil?

        headers
      end
    end
  end
end
