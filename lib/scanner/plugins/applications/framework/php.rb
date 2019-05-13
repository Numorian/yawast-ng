# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Applications
        module Framework
          class PHP < Yawast::Scanner::Base
            def self.check_banner(banner)
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'php_version_exposed_banner',
                                              {vulnerable: false, version: nil, banner: banner}

              # don't bother if this doesn't include PHP
              return unless banner.include? 'PHP/'

              modules = banner.split(' ')

              modules.each do |mod|
                if mod.include? 'PHP/'
                  Yawast::Utilities.puts_warn "PHP Version: #{mod}"
                  puts ''

                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'php_version_exposed_banner',
                                                  {vulnerable: true, version: mod, banner: banner}
                end
              end
            end

            def self.check_powered_by(banner)
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'php_version_exposed_powered_by',
                                              {vulnerable: false, version: nil}

              # don't bother if this doesn't include PHP
              return unless banner.include? 'PHP/'

              Yawast::Utilities.puts_warn "PHP Version: #{banner}"
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'php_version_exposed_powered_by',
                                              {vulnerable: true, version: banner}
            end
          end
        end
      end
    end
  end
end
