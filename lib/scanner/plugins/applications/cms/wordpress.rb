# frozen_string_literal: true

module Yawast
  module Scanner
    module Plugins
      module Applications
        module CMS
          class WordPress
            # check to see if we can confirm the presence of WordPress
            def self.identify(uri)
              ret = nil

              # check for wp-login.php in the current directory
              resp = identify_by_path uri, uri.path

              if resp.nil?
                # if we don't get a hit at the current path, try under /blog/
                resp = identify_by_path uri, uri.path + 'blog/'
              end

              unless resp.nil?
                # confirmed hit
                res = resp[:result]
                ret = resp[:uri]

                # strip the file name from the path
                ret.path = ret.path.sub! 'wp-login.php', ''

                css = res[:body].scan /login.min.css\?ver=\d+\.\d+\.?\d*/

                ver = 'Unknown'
                if !css.count.zero?
                  ver = css[0].to_s.split('=')[1]
                else
                  # the current method doesn't work, fall back to an older method
                  css = res[:body].scan /load-styles.php\?[\w\,\;\=\&\%]+;ver=\d+\.\d+\.?\d*/
                  ver = css[0].to_s.split('=')[-1] unless css.count.zero?
                end

                Yawast::Utilities.puts_info "Found WordPress v#{ver} at #{ret}"
                Yawast::Shared::Output.log_value 'application', 'wordpress', 'uri', ret
                Yawast::Shared::Output.log_value 'application', 'wordpress', 'version', ver
                Yawast::Shared::Output.log_value 'application', 'wordpress', 'login_body', res[:body]
              end

              ret
            end

            def self.identify_by_path(uri, path)
              login_uri = uri.copy
              login_uri.path = path + 'wp-login.php'

              res = Yawast::Shared::Http.get_with_code login_uri

              if res[:code] == '200' && res[:body].include?('Powered by WordPress')
                return {result: res, uri: login_uri}
              else
                return nil
              end
            end

            def self.check_json_user_enum(uri)
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'wordpress_json_user_enum',
                                              {vulnerable: false, users: nil}

              json_uri = uri.copy
              json_uri.path = json_uri.path + 'wp-json/wp/v2/users'
              res = Yawast::Shared::Http.get_with_code json_uri

              if res[:code] == '200' && res[:body].include?('slug')
                # we have a likely hit
                users = nil
                begin
                  users = JSON.parse res[:body]
                rescue # rubocop:disable Style/RescueStandardError, Lint/HandleExceptions
                  # don't care why it failed
                end

                unless users.nil?
                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'wordpress_json_user_enum',
                                                  {vulnerable: true, users: users}
                  Yawast::Utilities.puts_warn "WordPress WP-JSON User Enumeration at #{json_uri}"

                  users.each do |user|
                    Yawast::Utilities.puts_raw "ID: #{user['id']}\tUser Slug: '#{user['slug']}'\t\tUser Name: '#{user['name']}'"
                  end

                  puts
                end
              end
            end
          end
        end
      end
    end
  end
end
