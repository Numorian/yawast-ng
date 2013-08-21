require 'openssl'
require 'openssl-extensions/all'
require 'digest/sha1'

module Yawast
  module Scanner
    class Ssl
      def self.info(uri, check_ciphers)
        begin
          socket = TCPSocket.new(uri.host, uri.port)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ssl = OpenSSL::SSL::SSLSocket.new(socket, ctx)
          ssl.connect

          cert = ssl.peer_cert

          unless cert.nil?
            Yawast::Utilities.puts_info 'Found X509 Certificate:'
            Yawast::Utilities.puts_info "\t\tIssued To: #{cert.subject.common_name} / #{cert.subject.organization}"
            Yawast::Utilities.puts_info "\t\tIssuer: #{cert.issuer.common_name} / #{cert.issuer.organization}"
            Yawast::Utilities.puts_info "\t\tVersion: #{cert.version}"
            Yawast::Utilities.puts_info "\t\tSerial: #{cert.serial}"
            Yawast::Utilities.puts_info "\t\tSubject: #{cert.subject}"
            Yawast::Utilities.puts_info "\t\tExpires: #{cert.not_after}"
            Yawast::Utilities.puts_info "\t\tSignature Algorithm: #{cert.signature_algorithm}"
            Yawast::Utilities.puts_info "\t\tKey: #{cert.public_key.class.to_s.gsub('OpenSSL::PKey::', '')}-#{cert.public_key.strength}"
            Yawast::Utilities.puts_info "\t\t\tKey Hash: #{Digest::SHA1.hexdigest(cert.public_key.to_s)}"
            Yawast::Utilities.puts_info "\t\tExtensions:"
            cert.extensions.each { |ext| Yawast::Utilities.puts_info "\t\t\t#{ext}" }
            Yawast::Utilities.puts_info "\t\tHash: #{Digest::SHA1.hexdigest(cert.to_der)}"
            puts ''
          end

          cert_chain = ssl.peer_cert_chain

          unless cert_chain.nil?
            Yawast::Utilities.puts_info 'Certificate: Chain'
            cert_chain.each do |c|
              Yawast::Utilities.puts_info "\t\tIssued To: #{c.subject.common_name} / #{c.subject.organization}"
              Yawast::Utilities.puts_info "\t\t\tIssuer: #{c.issuer.common_name} / #{c.issuer.organization}"
              Yawast::Utilities.puts_info "\t\t\tExpires: #{c.not_after}"
              Yawast::Utilities.puts_info "\t\t\tKey: #{c.public_key.class.to_s.gsub('OpenSSL::PKey::', '')}-#{c.public_key.strength}"
              Yawast::Utilities.puts_info "\t\t\tSignature Algorithm: #{c.signature_algorithm}"
              Yawast::Utilities.puts_info "\t\t\tHash: #{Digest::SHA1.hexdigest(c.to_der)}"
              puts ''
            end

            puts ''
          end

          cipher = ssl.cipher

          unless cipher.nil?
            Yawast::Utilities.puts_info 'Connection Cipher Information:'

            if cipher[2] >= 128
              Yawast::Utilities.puts_info "\t\tName: #{cipher[0]} - #{cipher[2]} bits"
            else
              Yawast::Utilities.puts_warn "\t\tName: #{cipher[0]} - #{cipher[2]} bits"
            end

            puts ''
          end

          if check_ciphers
            get_ciphers(uri)
          end

          ssl.sysclose
        rescue => e
          Yawast::Utilities.puts_error "SSL: Error Reading X509 Details: #{e.message}"
        end
      end

      def self.get_ciphers(uri)
        Yawast::Utilities.puts_info 'Supported Ciphers:'

        #find all versions that don't include '_server' or '_client'
        versions = OpenSSL::SSL::SSLContext::METHODS.find_all { |v| !v.to_s.include?('_client') && !v.to_s.include?('_server')}
        versions.each do |version|
          ciphers = OpenSSL::SSL::SSLContext.new(version).ciphers
          ciphers.each do |cipher|
            #try to connect and see what happens
            begin
              socket = TCPSocket.new(uri.host, uri.port)
              context = OpenSSL::SSL::SSLContext.new(version)
              context.ciphers = cipher[0]
              context.verify_mode = OpenSSL::SSL::VERIFY_NONE
              ssl = OpenSSL::SSL::SSLSocket.new(socket, context)

              ssl.connect

              if cipher[2] >= 128
                Yawast::Utilities.puts_info "\t\tVersion: #{version}\tBits: #{cipher[2]}\tCipher: #{cipher[0]}"
              else
                Yawast::Utilities.puts_warn "\t\tVersion: #{version}\tBits: #{cipher[2]}\tCipher: #{cipher[0]}"
              end

              ssl.sysclose
            rescue
              #just ignore anything that goes wrong here; we don't care
            end
          end
        end

        puts ''
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
