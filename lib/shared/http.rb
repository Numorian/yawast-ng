module Yawast
  module Shared
    class Http
      def self.setup(proxy, cookie)
        if proxy != nil && proxy.include?(':')
          @proxy_host, @proxy_port = proxy.split(':')
          @proxy = true

          puts "Using Proxy: #{proxy}"
        else
          @proxy = false
        end

        @cookie = cookie
        puts "Using Cookie: #{@cookie}" if @cookie != nil
      end

      def self.head(uri)
        req = get_http(uri)
        req.use_ssl = uri.scheme == 'https'
        req.head(uri.path, get_headers)
      end

      def self.get(uri)
        body = ''

        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          res = req.request_get(uri.path, get_headers)
          body = res.read_body
        rescue
          #do nothing for now
        end

        body
      end

      def self.get_status_code(uri)
        req = get_http(uri)
        req.use_ssl = uri.scheme == 'https'
        res = req.head(uri.path, get_headers)
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

      def self.get_headers
        if @cookie == nil
          headers = { 'User-Agent' => HTTP_UA }
        else
          headers = { 'User-Agent' => HTTP_UA, 'Cookie' => @cookie }
        end

        headers
      end
    end
  end
end
