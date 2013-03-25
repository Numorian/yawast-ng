module Yawast
  module Commands
    class Scan
      def self.process(args, options)
        raise ArgumentError.new('You must specify a URL.') if args.empty?

        url = args[0]
        ssl_test = options.ssl

        uri = URI.parse(url)
        uri.path = '/' if uri.path == ''

        #see if we can resolve the host
        begin
          dns = Resolv::DNS.new()
          dns.getaddress(uri.host)
        rescue => e
          raise ArgumentError.new("Invalid URL (#{e.message})")
        end

        Yawast::Scanner::Core.process(uri, ssl_test)
      end
    end
  end
end
