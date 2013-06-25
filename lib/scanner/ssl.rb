require 'openssl'

module Yawast
  module Scanner
    class Ssl
      def self.info(uri)
        begin
          socket = TCPSocket.new(uri.host, uri.port)
          ssl = OpenSSL::SSL::SSLSocket.new(socket)
          ssl.connect

          cert = ssl.peer_cert

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

          cert_chain = ssl.peer_cert_chain

          unless cert_chain.nil?
            Yawast::Utilities.puts_info 'Certificate: Chain'
            cert_chain.each { |c| Yawast::Utilities.puts_info "\t\tIssuer: #{c.issuer}" }
            puts ''
          end

          cipher = ssl.cipher

          unless cipher.nil?
            Yawast::Utilities.puts_info 'Connection Cipher Information:'
            Yawast::Utilities.puts_info "\t\tName: #{cipher[0]}"
            Yawast::Utilities.puts_info "\t\tVersion: #{cipher[1]}"
            Yawast::Utilities.puts_info "\t\tBits: #{cipher[2]}"
            puts ''
          end

          ssl.sysclose
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
