# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Http
        class Generic < Yawast::Scanner::Base
          def self.check_propfind(uri)
            begin
              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              headers = Yawast::Shared::Http.get_headers
              res = req.request(Propfind.new('/', headers))

              if res.code.to_i <= 400 && res.body.length.positive? && res['Content-Type'] == 'text/xml'
                Yawast::Utilities.puts_warn 'Possible Info Disclosure: PROPFIND Enabled'
                puts "\t\t\"curl -X PROPFIND #{uri}\""

                puts ''

                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'http_propfind_enabled',
                                                {vulnerable: true, body: res.body, code: res.code,
                                                 content_type: res['Content-Type'], length: res.body.length}
              else
                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'http_propfind_enabled',
                                                {vulnerable: false, body: res.body, code: res.code,
                                                 content_type: res['Content-Type'], length: res.body.length}
              end
            end
          end

          def self.check_trace(uri)
            begin
              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              headers = Yawast::Shared::Http.get_headers
              res = req.request(Trace.new('/', headers))

              if res.body.include?('TRACE / HTTP/1.1') && res.code == '200'
                Yawast::Utilities.puts_warn 'HTTP TRACE Enabled'
                puts "\t\t\"curl -X TRACE #{uri}\""

                puts ''

                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'http_trace_enabled',
                                                {vulnerable: true, body: res.body, code: res.code}
              else
                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'http_trace_enabled',
                                                {vulnerable: false, body: res.body, code: res.code}
              end
            end
          end

          def self.check_options(uri)
            begin
              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              headers = Yawast::Shared::Http.get_headers
              res = req.request(Options.new('/', headers))

              unless res['Public'].nil?
                Yawast::Utilities.puts_info "Public HTTP Verbs (OPTIONS): #{res['Public']}"
                Yawast::Shared::Output.log_value 'http', 'options', 'public', res['Public']

                puts ''
              end

              unless res['Allow'].nil?
                Yawast::Utilities.puts_info "Allow HTTP Verbs (OPTIONS): #{res['Allow']}"
                Yawast::Shared::Output.log_value 'http', 'options', 'allow', res['Allow']

                puts ''
              end
            end
          end
        end

        # Custom class to allow using the PROPFIND verb
        class Propfind < Net::HTTPRequest
          METHOD = 'PROPFIND'
          REQUEST_HAS_BODY = false
          RESPONSE_HAS_BODY = true
        end

        # Custom class to allow using the TRACE verb
        class Trace < Net::HTTPRequest
          METHOD = 'TRACE'
          REQUEST_HAS_BODY = false
          RESPONSE_HAS_BODY = true
        end

        # Custom class to allow using the OPTIONS verb
        class Options < Net::HTTPRequest
          METHOD = 'OPTIONS'
          REQUEST_HAS_BODY = false
          RESPONSE_HAS_BODY = true
        end
      end
    end
  end
end
