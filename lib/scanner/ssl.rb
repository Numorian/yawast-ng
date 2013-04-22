module Yawast
  module Scanner
    class Ssl
      def self.info(uri)
        begin
          #get the x509 cert so we can examine it
          cert = Yawast::Scanner::Http.peer_cert(uri)

          unless cert.nil?
            Yawast::Utilities.puts_info 'Found X509 Certificate:'
            Yawast::Utilities.puts_info "\t\tIssuer: #{cert.issuer}"
            Yawast::Utilities.puts_info "\t\tVersion: #{cert.version}"
            Yawast::Utilities.puts_info "\t\tSerial: #{cert.serial}"
            Yawast::Utilities.puts_info "\t\tSubject: #{cert.subject}"
            Yawast::Utilities.puts_info "\t\tExpires: #{cert.not_after}"
            Yawast::Utilities.puts_info "\t\tExtensions:"
            cert.extensions.each { |ext| Yawast::Utilities.puts_info "\t\t\t#{ext}" }
            puts ''
          end
        rescue => e
          Yawast::Utilities.puts_error "SSL: Error Reading X509 Details: #{e.message}"
        end
      end

      def self.check_hsts(head)
        found = ''

        head.each do |k, v|
          if k.downcase.include? 'strict-transport-security'
            found = "#{k}: #{v}"
          end
        end

        if found == ''
          Yawast::Utilities.puts_warn 'HSTS: Not Enabled'
        else
          Yawast::Utilities.puts_info "HSTS: Enabled (#{found})"
        end

        puts ''
      end
    end
  end
end
