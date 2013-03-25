module Yawast
  module Scanner
    class Iis
      def self.check_banner(banner)
        #don't bother if this doesn't include IIS
        return if !banner.include? 'Microsoft-IIS/'

        Yawast::Utilities.puts_warn "IIS Version: #{banner}"
        puts ''
      end

      def self.check_asp_banner(uri)
        headers = Yawast::Scanner::Http.head(uri)

        headers.each do |k, v|
          if k.downcase == 'x-aspnet-version'
            Yawast::Utilities.puts_warn "ASP.NET Version: #{v}"
            puts ''
          end
        end
      end
    end
  end
end
