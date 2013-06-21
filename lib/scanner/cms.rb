module Yawast
  module Scanner
    class Cms
      def self.get_generator(body)
        regex = /<meta name="generator[^>]+content\s*=\s*['"]([^'"]+)['"][^>]*>/
        match = body.match regex

        if match
          Yawast::Utilities.puts_info "Meta Generator: #{match[1]}"
        end
      end
    end
  end
end
