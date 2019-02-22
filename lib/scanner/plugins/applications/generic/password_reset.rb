require 'selenium-webdriver'
require 'securerandom'

module Yawast
  module Scanner
    module Plugins
      module Applications
        module Generic
          class PasswordReset
            def self.setup
              @reset_page = Yawast::Utilities.prompt 'What is the application password reset page?'
              @valid_user = Yawast::Utilities.prompt 'What is a valid user?'
            end

            def self.check_resp_user_enum
              # checks for user enum via differences in response

              good_user_res = fill_form_get_body @reset_page, @valid_user
              bad_user_res = fill_form_get_body @reset_page, SecureRandom.hex + '@invalid.example.com'

              puts
              if good_user_res != bad_user_res
                Yawast::Utilities.puts
                Yawast::Utilities.puts_warn 'Password Reset: Possible User Enumeration - Difference In Response (see below for details)'
                Yawast::Shared::Output.log_value 'vulnerabilities', 'password_reset_resp_user_enum', true
                Yawast::Utilities.puts
                Yawast::Utilities.puts Yawast::Utilities.diff_text(good_user_res, bad_user_res)
                Yawast::Utilities.puts
                Yawast::Utilities.puts
              else
                Yawast::Shared::Output.log_value 'vulnerabilities', 'password_reset_resp_user_enum', false
              end
            end

            def self.fill_form_get_body(uri, user)
              options = Selenium::WebDriver::Chrome::Options.new(args: ['headless'])
              driver = Selenium::WebDriver.for(:chrome, options: options)
              driver.get uri

              # find the page form element - this is going to be a best effort thing, and may not always be right
              element = driver.find_element(name: 'user_login')

              element.send_keys(user)
              element.submit

              res = driver.page_source
              img = driver.screenshot_as(:base64)

              # log response
              Yawast::Shared::Output.log_value "password_reset_body_#{user}", 'body', res
              Yawast::Shared::Output.log_value "password_reset_body_#{user}", 'img', img

              driver.close

              return res
            end

            def self.check_timing_user_enum
              # checks for user enum via timing differences
            end
          end
        end
      end
    end
  end
end
