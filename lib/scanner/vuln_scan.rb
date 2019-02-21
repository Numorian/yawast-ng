module Yawast
  module Scanner
    class VulnScan
      def self.scan(uri, options)
        puts 'Performing vulnerability scan (this will take a while)...'

        Yawast::Scanner::Plugins::Applications::Generic::PasswordReset.setup
        Yawast::Scanner::Plugins::Applications::Generic::PasswordReset.check_resp_user_enum
      end
    end
  end
end
