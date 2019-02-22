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
              begin
                # checks for user enum via differences in response
                good_user_res = fill_form_get_body @reset_page, @valid_user, true
                bad_user_res = fill_form_get_body @reset_page, SecureRandom.hex + '@invalid.example.com', false

                puts
                if good_user_res != bad_user_res
                  Yawast::Utilities.puts_raw
                  Yawast::Utilities.puts_vuln 'Password Reset: Possible User Enumeration - Difference In Response (see below for details)'
                  Yawast::Shared::Output.log_value 'vulnerabilities', 'password_reset_resp_user_enum', true
                  Yawast::Utilities.puts_raw
                  Yawast::Utilities.puts_raw Yawast::Utilities.diff_text(good_user_res, bad_user_res)
                  Yawast::Utilities.puts_raw
                  Yawast::Utilities.puts_raw
                else
                  Yawast::Shared::Output.log_value 'vulnerabilities', 'password_reset_resp_user_enum', false
                end
              rescue ArgumentError => e
                Yawast::Utilities.puts "Unable to find a matching element to perform the User Enumeration via Password Reset Response test (#{e.message})"
              end
            end

            def self.fill_form_get_body(uri, user, valid)
              options = Selenium::WebDriver::Chrome::Options.new(args: ['headless'])

              # if we have a proxy set, use that
              if Yawast.options.proxy != nil
                proxy = Selenium::WebDriver::Proxy.new(:http => "http://#{Yawast.options.proxy}", :ssl => "http://#{Yawast.options.proxy}")
                caps = Selenium::WebDriver::Remote::Capabilities.chrome(acceptInsecureCerts: true, proxy: proxy)
              else
                caps = Selenium::WebDriver::Remote::Capabilities.chrome(acceptInsecureCerts: true)
              end

              driver = Selenium::WebDriver.for(:chrome, options: options, desired_capabilities: caps)
              driver.get uri

              # find the page form element - this is going to be a best effort thing, and may not always be right
              element = find_user_field driver

              element.send_keys user
              element.submit

              res = driver.page_source
              img = driver.screenshot_as(:base64)

              valid_text = 'valid'
              valid_text = 'invalid' unless valid

              # log response
              Yawast::Shared::Output.log_value 'application', "password_reset_body_#{valid_text}_body", res
              Yawast::Shared::Output.log_value 'application', "password_reset_body_#{valid_text}_img", img
              Yawast::Shared::Output.log_value 'application', "password_reset_body_#{valid_text}_user", user

              driver.close

              return res
            end

            def self.check_timing_user_enum
              # checks for user enum via timing differences
            end

            def self.find_user_field(driver)
              # find the page form element - this is going to be a best effort thing, and may not always be right
              element = find_element driver, 'user_login'
              return element if element != nil

              element = find_element driver, 'email'
              return element if element != nil

              element = find_element driver, 'email_address'
              return element if element != nil

              element = find_element driver, 'forgetPasswordEmailOrUsername'
              return element if element != nil

              # if we got here, it means that we don't have an element we know about, so we have to prompt
              Yawast::Utilities.puts_raw 'Unable to find a known element to enter the user name. Please identify the proper element.'
              Yawast::Utilities.puts_raw 'If this element name seems to be common, please request that it be added: https://github.com/adamcaudill/yawast/issues'
              element_name = Yawast::Utilities.prompt 'What is the user/email entry element name?'
              element = find_element driver, element_name
              return element if element != nil

              raise ArgumentError, 'No matching element found.'
            end

            def self.find_element(driver, name)
              begin
                return driver.find_element(name: name)
              rescue ArgumentError
                return nil
              end
            end
          end
        end
      end
    end
  end
end
