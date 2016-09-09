module Yawast
  module Shared
    class Uri
      def self.extract_uri(url)
        #this might be buggy - actually, I know it is...
        url = 'http://' + url unless url.include?('http://') || url.include?('https://')

        #make sure the path is at least a slash
        uri = URI.parse(url)
        uri.path = '/' if uri.path == ''

        #this is buggy, but we don't handle files anyhow...
        #if the path doesn't end in a slash, add one.
        if uri.path[-1, 1] != '/'
          uri.path.concat '/'
        end

        #see if we can resolve the host
        # we don't really need it, it just serves as validation
        begin
          dns = Resolv::DNS.new
          dns.getaddress(uri.host)
        rescue => e
          raise ArgumentError.new("Invalid URL (#{e.message})") unless uri.host == 'localhost'
        end

        return uri
      end
    end
  end
end
