# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Applications
        module CMS
          class Generic < Yawast::Scanner::Base
            def self.get_generator(body)
              regex = /<meta name="generator[^>]+content\s*=\s*['"]([^'"]+)['"][^>]*>/
              match = body.match regex

              if match
                Yawast::Utilities.puts_info "Meta Generator: #{match[1]}"

                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'cms_meta_generator_exposed',
                                                {vulnerable: true, generator: match[1]}
              else
                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'cms_meta_generator_exposed',
                                                {vulnerable: false, generator: nil}
              end
            end
          end
        end
      end
    end
  end
end
