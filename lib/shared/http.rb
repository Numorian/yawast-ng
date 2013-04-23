module Yawast
  module Shared
    class Http
      def self.head(uri)
        req = Net::HTTP.new(uri.host, uri.port)
        req.use_ssl = uri.scheme == 'https'
        headers = { 'User-Agent' => HTTP_UA }
        req.head(uri.path, headers)
      end

      def self.get(uri)
        body = ''

        begin
          req = Net::HTTP.new(uri.host, uri.port)
          req.use_ssl = uri.scheme == 'https'
          headers = { 'User-Agent' => HTTP_UA }
          res = req.request_get(uri.path, headers)
          body = res.read_body
        rescue
          #do nothing for now
        end

        body
      end

      def self.peer_cert(uri)
        req = Net::HTTP.new(uri.host, uri.port)
        req.use_ssl = uri.scheme == 'https'
        req.start { |http| return http.peer_cert }
      end
    end
  end
end
