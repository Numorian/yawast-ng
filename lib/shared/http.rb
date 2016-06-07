module Yawast
  module Shared
    class Http
      def self.setup(proxy)
        if proxy != nil && proxy.include?(':')
          @proxy_host, @proxy_port = proxy.split(':')
          @proxy = true

          puts "Using Proxy: #{proxy}"
        else
          @proxy = false
        end
      end

      def self.head(uri)
        req = get_http(uri)
        req.use_ssl = uri.scheme == 'https'
        headers = { 'User-Agent' => HTTP_UA }
        req.head(uri.path, headers)
      end

      def self.get(uri)
        body = ''

        begin
          req = get_http(uri)
          req.use_ssl = uri.scheme == 'https'
          headers = { 'User-Agent' => HTTP_UA }
          res = req.request_get(uri.path, headers)
          body = res.read_body
        rescue
          #do nothing for now
        end

        body
      end

      def self.get_status_code(uri)
        req = get_http(uri)
        req.use_ssl = uri.scheme == 'https'
        headers = { 'User-Agent' => HTTP_UA }
        res = req.head(uri.path, headers)
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
    end
  end
end
