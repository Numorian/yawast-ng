module Yawast
  module Commands
    class Utils
      def self.extract_uri(args)
        raise ArgumentError.new('You must specify a URL.') if args.empty?

        #this might be a bad assumption
        url = args[0]

        #this might be buggy - actually, I know it is...
        url = 'http://' + url unless url.include?('http://') || url.include?('https://')

        uri = URI.parse(url)
        uri.path = '/' if uri.path == ''

        #see if we can resolve the host
        # we don't really need it, it just serves as validation
        begin
          dns = Resolv::DNS.new()
          dns.getaddress(uri.host)
        rescue => e
          raise ArgumentError.new("Invalid URL (#{e.message})") unless uri.host == 'localhost'
        end

        return uri
      end
    end
  end
end
