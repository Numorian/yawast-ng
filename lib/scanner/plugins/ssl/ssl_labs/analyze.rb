require 'json'

module Yawast
  module Scanner
    module Plugins
      module SSL
        module SSLLabs
          class Analyze
            def self.scan(endpoint, target, startNew)
              uri = endpoint.copy
              uri.path = '/api/v3/analyze'

              if startNew
                uri.query = "host=#{target}&publish=off&startNew=on&all=done&ignoreMismatch=on"
              else
                uri.query = "host=#{target}&publish=off&all=done&ignoreMismatch=on"
              end

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
