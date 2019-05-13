# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Servers
        class Nginx < Yawast::Scanner::Base
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

          def self.check_all(uri)
            check_status_page uri.copy
          end

          def self.check_status_page(uri)
            uri.path = '/status'
            uri.query = '' unless uri.query.nil?

            body = Yawast::Shared::Http.get(uri)

            if body.include? 'Active connections:'
              Yawast::Utilities.puts_vuln "Nginx status page found: #{uri}"

              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'nginx_status_found',
                                              {vulnerable: true, uri: uri, body: body}

              puts ''
            else
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'nginx_status_found',
                                              {vulnerable: false, uri: uri, body: body}
            end
          end
        end
      end
    end
  end
end
