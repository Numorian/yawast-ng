module Yawast
  module Scanner
    class Nginx
      def self.check_banner(banner)
        #don't bother if this doesn't include nginx
        return if !banner.include? 'nginx/'

        Yawast::Utilities.puts_warn "nginx Version: #{banner}"
        puts ''
      end
    end
  end
end