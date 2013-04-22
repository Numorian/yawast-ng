module Yawast
  module Scanner
    class Iis
      def self.check_banner(banner)
        #don't bother if this doesn't include IIS
        return if !banner.include? 'Microsoft-IIS/'
        @iis = true

        Yawast::Utilities.puts_warn "IIS Version: #{banner}"
        puts ''
      end

      def self.check_all(uri, head)
        #run all the defined checks
        check_asp_banner(head)
        check_mvc_version(head)
      end

      def self.check_asp_banner(head)
        return if !@iis

        head.each do |k, v|
          if k.downcase == 'x-aspnet-version'
            Yawast::Utilities.puts_warn "ASP.NET Version: #{v}"
            puts ''
          end
        end
      end

      def self.check_mvc_version(head)
        return if !@iis

        head.each do |k, v|
          if k.downcase == 'x-aspnetmvc-version'
            Yawast::Utilities.puts_warn "ASP.NET MVC Version: #{v}"
            puts ''
          end
        end
      end
    end
  end
end
