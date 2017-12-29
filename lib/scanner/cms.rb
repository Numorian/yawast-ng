module Yawast
  module Scanner
    class Cms
      def self.get_generator(body)
        regex = /<meta name="generator[^>]+content\s*=\s*['"]([^'"]+)['"][^>]*>/
        match = body.match regex

        Yawast::Utilities.puts_info "Meta Generator: #{match[1]}" if match
      end
    end
  end
end
