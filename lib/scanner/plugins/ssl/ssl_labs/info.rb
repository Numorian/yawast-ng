require 'json'

module Yawast
  module Scanner
    module Plugins
      module SSL
        module SSLLabs
          class Info
            def self.call_info(endpoint)
              uri = endpoint.copy
              uri.path = '/api/v3/info'

              body = Yawast::Shared::Http.get uri

              return body
            end

            def self.extract_msg(body)
              json = JSON.parse body

              #BUG: Should return each item, in case some day there's more than one.
              return json['messages'][0]
            end
          end
        end
      end
    end
  end
end
