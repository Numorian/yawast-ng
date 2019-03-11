# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Servers
        class Generic
          def self.check_banner_php(banner)
            # don't bother if this doesn't include PHP
            return unless banner.include? 'PHP/'

            modules = banner.split(' ')

            modules.each do |mod|
              if mod.include? 'PHP/'
                Yawast::Utilities.puts_warn "PHP Version: #{mod}"
                puts ''
              end
            end
          end
        end
      end
    end
  end
end
