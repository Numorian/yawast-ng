module Yawast
  module Scanner
    class VulnScan
      def self.scan(uri, options, head)
        puts 'Performing vulnerability scan (this will take a while)...'

        # server specific checks
        Yawast::Scanner::Plugins::Servers::Apache.check_all(uri)
        Yawast::Scanner::Plugins::Servers::Iis.check_all(uri, head)

        #checks for interesting files
        Yawast::Scanner::Plugins::Http::FilePresence.check_all uri, options.files

        # generic header checks
        Yawast::Scanner::Plugins::Http::Generic.check_propfind(uri)
        Yawast::Scanner::Plugins::Http::Generic.check_options(uri)
        Yawast::Scanner::Plugins::Http::Generic.check_trace(uri)

        # check for issues with the password reset form
        Yawast::Scanner::Plugins::Applications::Generic::PasswordReset.setup
        Yawast::Scanner::Plugins::Applications::Generic::PasswordReset.check_resp_user_enum
      end
    end
  end
end
