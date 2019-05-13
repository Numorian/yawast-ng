# frozen_string_literal: true

require 'json'

module Yawast
  module Scanner
    module Plugins
      module SSL
        module SSLLabs
          class Info < Yawast::Scanner::Base
            def self.call_info(endpoint)
              uri = endpoint.copy
              uri.path = '/api/v3/info'

              body = Yawast::Shared::Http.get uri

              body
            end

            def self.extract_msg(body)
              ret = []

              begin
                json = JSON.parse body
              rescue => e # rubocop:disable Style/RescueStandardError
                raise Exception, "Invalid response from SSL Labs: '#{e.message}'"
              end

              unless json['messages'].nil?
                json['messages'].each do |msg|
                  ret.push msg
                end
              end

              ret
            end
          end
        end
      end
    end
  end
end
