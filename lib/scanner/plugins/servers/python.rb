# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Servers
        class Python
          def self.check_banner(banner)
            # don't bother if this doesn't include Python
            return unless banner.include? 'Python/'

            Yawast::Utilities.puts_warn "Python Version: #{banner}"
            puts ''
          end
        end
      end
    end
  end
end
