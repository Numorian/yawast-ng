require 'ipaddress'

module Yawast
  module Shared
    class Uri
      def self.extract_uri(url)
        # this might be buggy - actually, I know it is...
        url = 'http://' + url unless url.include?('http://') || url.include?('https://')

        uri = URI.parse(url)

        # this is buggy, but we don't handle files anyhow...
        # if the path doesn't end in a slash, add one.
        uri.path.concat '/' if uri.path == '' || uri.path[-1, 1] != '/'

        # see if we can resolve the host
        # we don't really need it, it just serves as validation
        begin
          if uri.host != 'localhost' && !IPAddress.valid?(uri.host)
            dns = Resolv::DNS.new
            dns.getaddress(uri.host)
          end
        rescue => e
          # we've passed all the exceptions, if we are here, it's a problem
          raise ArgumentError, "Invalid URL (#{e.message})"
        end

        uri
      end
    end
  end
end
