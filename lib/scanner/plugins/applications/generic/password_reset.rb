# frozen_string_literal: true

require 'selenium-webdriver'
require 'securerandom'

module Yawast
  module Scanner
    module Plugins
      module Applications
        module Generic
          class PasswordReset
            def self.setup
              @reset_page = if Yawast.options.pass_reset_page.nil?
                              Yawast::Utilities.prompt 'What is the application password reset page?'
                            else
                              Yawast.options.pass_reset_page
                            end

              @valid_user = if Yawast.options.user.nil?
                              Yawast::Utilities.prompt 'What is a valid user?'
                            else
                              Yawast.options.user
                            end

              @timing = {true => [], false => []}
            end

            def self.check_resp_user_enum
              begin
                # checks for user enum via differences in response
                # run each test 5 times to collect timing info
                good_user_res = fill_form_get_body @reset_page, @valid_user, true, true
                fill_form_get_body @reset_page, @valid_user, true, false
                fill_form_get_body @reset_page, @valid_user, true, false
                fill_form_get_body @reset_page, @valid_user, true, false
                fill_form_get_body @reset_page, @valid_user, true, false

                bad_user_res = fill_form_get_body @reset_page, SecureRandom.hex + '@invalid.example.com', false, true
                fill_form_get_body @reset_page, SecureRandom.hex + '@invalid.example.com', false, false
                fill_form_get_body @reset_page, SecureRandom.hex + '@invalid.example.com', false, false
                fill_form_get_body @reset_page, SecureRandom.hex + '@invalid.example.com', false, false
                fill_form_get_body @reset_page, SecureRandom.hex + '@invalid.example.com', false, false

                puts
                # check for difference in response
                if good_user_res != bad_user_res
                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'password_reset_resp_user_enum',
                                                  {vulnerable: true, url: @reset_page}

                  Yawast::Utilities.puts_raw
                  Yawast::Utilities.puts_vuln 'Password Reset: Possible User Enumeration - Difference In Response (see below for details)'
                  Yawast::Utilities.puts_raw
                  Yawast::Utilities.puts_raw Yawast::Utilities.diff_text(good_user_res, bad_user_res)
                  Yawast::Utilities.puts_raw
                  Yawast::Utilities.puts_raw
                else
                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'password_reset_resp_user_enum',
                                                  {vulnerable: false, url: @reset_page}
                end

                # check for timing issues
                valid_average = (@timing[true].inject(0, :+) / 5)
                invalid_average = (@timing[false].inject(0, :+) / 5)
                timing_diff = valid_average - invalid_average
                if timing_diff.abs > 10
                  # in this case, we have a difference in the averages of greater than 10ms.
                  # this is an arbitrary number, but 10ms is likely good enough
                  Yawast::Utilities.puts_vuln 'Password Reset: Possible User Enumeration - Response Timing (see below for details)'
                  Yawast::Utilities.puts_raw "\tDifference in average: #{timing_diff.abs.round(2)}ms  Valid user: #{valid_average.round(2)}ms  Invalid user: #{invalid_average.round(2)}ms"
                  Yawast::Utilities.puts_raw "\tValid Users     Invalid Users"
                  Yawast::Utilities.puts_raw "\t-----------------------------"
                  (0..4).each do |i|
                    Yawast::Utilities.puts_raw "\t#{format('%.2f', @timing[true][i].round(2)).rjust(11)}"\
                                                "     #{format('%.2f', @timing[false][i].round(2)).rjust(13)}"
                  end
                  puts

                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'password_reset_time_user_enum',
                                                  {vulnerable: true, difference: timing_diff,
                                                   valid_1: @timing[true][0], valid_2: @timing[true][1], valid_3: @timing[true][2],
                                                   valid_4: @timing[true][3], valid_5: @timing[true][4],
                                                   invalid_1: @timing[false][0], invalid_2: @timing[false][1], invalid_3: @timing[false][2],
                                                   invalid_4: @timing[false][3], invalid_5: @timing[false][4]}
                else
                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'password_reset_time_user_enum',
                                                  {vulnerable: false, difference: timing_diff,
                                                   valid_1: @timing[true][0], valid_2: @timing[true][1], valid_3: @timing[true][2],
                                                   valid_4: @timing[true][3], valid_5: @timing[true][4],
                                                   invalid_1: @timing[false][0], invalid_2: @timing[false][1], invalid_3: @timing[false][2],
                                                   invalid_4: @timing[false][3], invalid_5: @timing[false][4]}
                end
              rescue ArgumentError => e
                Yawast::Utilities.puts "Unable to find a matching element to perform the User Enumeration via Password Reset Response test (#{e.message})"
              end
            end

            def self.fill_form_get_body(uri, user, valid, log_output)
              options = Selenium::WebDriver::Chrome::Options.new({args: ['headless']})

              # if we have a proxy set, use that
              if !Yawast.options.proxy.nil?
                proxy = Selenium::WebDriver::Proxy.new({http: "http://#{Yawast.options.proxy}", ssl: "http://#{Yawast.options.proxy}"})
                caps = Selenium::WebDriver::Remote::Capabilities.chrome({acceptInsecureCerts: true, proxy: proxy})
              else
                caps = Selenium::WebDriver::Remote::Capabilities.chrome({acceptInsecureCerts: true})
              end

              driver = Selenium::WebDriver.for(:chrome, {options: options, desired_capabilities: caps})
              driver.get uri

              # find the page form element - this is going to be a best effort thing, and may not always be right
              element = find_user_field driver

              element.send_keys user

              beginning_time = Time.now
              element.submit
              end_time = Time.now
              @timing[valid].push((end_time - beginning_time) * 1000)

              res = driver.page_source
              img = driver.screenshot_as(:base64)

              valid_text = 'valid'
              valid_text = 'invalid' unless valid

              if log_output
                # log response
                Yawast::Shared::Output.log_hash 'applications',
                                                'password_reset_form',
                                                "pwd_reset_resp_#{valid_text}",
                                                {body: res, img: img, user: user}
              end

              driver.close

              res
            end

            def self.find_user_field(driver)
              # find the page form element - this is going to be a best effort thing, and may not always be right
              element = find_element driver, 'user_login'
              return element unless element.nil?

              element = find_element driver, 'email'
              return element unless element.nil?

              element = find_element driver, 'email_address'
              return element unless element.nil?

              element = find_element driver, 'forgetPasswordEmailOrUsername'
              return element unless element.nil?

              # if we got here, it means that we don't have an element we know about, so we have to prompt
              Yawast::Utilities.puts_raw 'Unable to find a known element to enter the user name. Please identify the proper element.'
              Yawast::Utilities.puts_raw 'If this element name seems to be common, please request that it be added: https://github.com/adamcaudill/yawast/issues'
              element_name = Yawast::Utilities.prompt 'What is the user/email entry element name?'
              element = find_element driver, element_name
              return element unless element.nil?

              raise ArgumentError, 'No matching element found.'
            end

            def self.find_element(driver, name)
              begin
                return driver.find_element({name: name})
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
