module Yawast
  module Commands
    class Utils
      def self.ExtractUri(args)
        raise ArgumentError.new('You must specify a URL.') if args.empty?

        #this might be a bad assumption
        url = args[0]

        uri = URI.parse(url)
        uri.path = '/' if uri.path == ''

        #see if we can resolve the host
        # we don't really need it, it just serves as validation
        begin
          dns = Resolv::DNS.new()
          dns.getaddress(uri.host)
        rescue => e
          raise ArgumentError.new("Invalid URL (#{e.message})")
        end

        return uri
      end
    end
  end
end
