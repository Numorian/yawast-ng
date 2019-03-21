# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Servers
        class Generic
          def self.check_banner_php(banner)
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'php_version_exposed',
                                            {vulnerable: false, version: nil}

            # don't bother if this doesn't include PHP
            return unless banner.include? 'PHP/'

            modules = banner.split(' ')

            modules.each do |mod|
              if mod.include? 'PHP/'
                Yawast::Utilities.puts_warn "PHP Version: #{mod}"
                puts ''

                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'php_version_exposed',
                                                {vulnerable: true, version: mod}
              end
            end
          end
        end
      end
    end
  end
end
