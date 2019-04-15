# frozen_string_literal: true

module Yawast
  module Scanner
    class VulnScan
      def self.scan(uri, options, head)
        puts 'Performing vulnerability scan (this will take a while)...'

        if options.spider
          links = Yawast::Scanner::Plugins::Spider::Spider.spider(uri)
        else
          puts 'Building site map...'
          links = Yawast::Scanner::Plugins::Spider::Spider.spider(uri, true)
        end

        # checks for interesting files
        Yawast::Scanner::Plugins::Http::FilePresence.check_all uri, options.files

        # server specific checks
        Yawast::Scanner::Plugins::Servers::Apache.check_all(uri, links)
        Yawast::Scanner::Plugins::Servers::Nginx.check_all(uri)
        Yawast::Scanner::Plugins::Servers::Iis.check_all(uri, head)

        # generic header checks
        Yawast::Scanner::Plugins::Http::Generic.check_propfind(uri)
        Yawast::Scanner::Plugins::Http::Generic.check_options(uri)
        Yawast::Scanner::Plugins::Http::Generic.check_trace(uri)

        # check for issues with the password reset form
        unless Yawast.options.pass_reset_page.nil?
          Yawast::Scanner::Plugins::Applications::Generic::PasswordReset.setup
          Yawast::Scanner::Plugins::Applications::Generic::PasswordReset.check_resp_user_enum
        end

        # check for framework specific issues
        Yawast::Scanner::Plugins::Applications::Framework::Rails.check_all uri, links
      end
    end
  end
end
