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

              body
            end

            def self.extract_msg(body)
              ret = []
              json = JSON.parse body

              json['messages'].each do |msg|
                ret.push msg
              end

              ret
            end
          end
        end
      end
    end
  end
end
