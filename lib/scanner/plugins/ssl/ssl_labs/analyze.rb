require 'json'

module Yawast
  module Scanner
    module Plugins
      module SSL
        module SSLLabs
          # setup exception classes
          class InvocationError < StandardError; end
          class RequestRateTooHigh < StandardError; end
          class InternalError < StandardError; end
          class ServiceNotAvailable < StandardError; end
          class ServiceOverloaded < StandardError; end

          class Analyze
            def self.scan(endpoint, target, start_new)
              uri = endpoint.copy
              uri.path = '/api/v3/analyze'

              if start_new
                uri.query = "host=#{target}&publish=off&startNew=on&all=done&ignoreMismatch=on"
              else
                uri.query = "host=#{target}&publish=off&all=done&ignoreMismatch=on"
              end

              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              res = req.request_get(uri, { 'User-Agent' => "YAWAST/#{Yawast::VERSION}" })
              body = res.read_body
              code = res.code.to_i

              # check for error in the response - if we don't, we'll wait forever for nothing
              json = JSON.parse body
              if json.key?('errors')
                raise InvocationError, "API returned: #{json['errors']}"
              end

              # check the response code, make sure it's 200 - otherwise, we should stop now
              if code != 200
                case code
                  when 400
                    raise InvocationError, 'invalid parameters'
                  when 429
                    raise RequestRateTooHigh, 'request rate is too high, please slow down'
                  when 500
                    raise InternalError, 'service encountered an error, sleep 5 minutes'
                  when 503
                    raise ServiceNotAvailable, 'service is not available, sleep 15 minutes'
                  when 529
                    raise ServiceOverloaded, 'service is overloaded, sleep 30 minutes'
                  else
                    raise StandardError, "http error code #{r.code}"
                end
              end

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
