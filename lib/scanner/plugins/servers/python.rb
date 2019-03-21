# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Servers
        class Python
          def self.check_banner(banner)
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'python_version_exposed',
                                            {vulnerable: false, version: nil}

            # don't bother if this doesn't include Python
            return unless banner.include? 'Python/'

            Yawast::Utilities.puts_warn "Python Version: #{banner}"
            puts ''

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'python_version_exposed',
                                            {vulnerable: true, version: banner}
          end
        end
      end
    end
  end
end
