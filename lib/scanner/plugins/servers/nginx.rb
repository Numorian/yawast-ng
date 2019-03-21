# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Servers
        class Nginx
          def self.check_banner(banner)
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'nginx_version_exposed',
                                            {vulnerable: false, version: nil}

            # don't bother if this doesn't include nginx
            return unless banner.include? 'nginx/'

            Yawast::Utilities.puts_warn "nginx Version: #{banner}"
            puts ''

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'nginx_version_exposed',
                                            {vulnerable: true, version: banner}
          end
        end
      end
    end
  end
end
