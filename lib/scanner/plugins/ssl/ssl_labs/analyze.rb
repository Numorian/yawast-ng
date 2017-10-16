require 'json'

module Yawast
  module Scanner
    module Plugins
      module SSL
        module SSLLabs
          class Analyze
            def self.start_scan(endpoint, target)
              uri = endpoint.copy
              uri.path = '/api/v3/analyze'
              uri.query = "host=#{target}&publish=off&startNew=on&all=done&ignoreMismatch=on"

              body = Yawast::Shared::Http.get uri

              return body
            end

            def self.get_results(endpoint, target)
              uri = endpoint.copy
              uri.path = '/api/v3/analyze'
              uri.query = "host=#{target}&publish=off&all=done&ignoreMismatch=on"

              body = Yawast::Shared::Http.get uri

              return body
            end

            def self.extract_status(body)
              json = JSON.parse body

              return json['status']
            end
          end
        end
      end
    end
  end
end
