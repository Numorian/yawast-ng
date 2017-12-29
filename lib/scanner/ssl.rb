require 'openssl'
require 'openssl-extensions/all'
require 'digest/sha1'
require 'sslshake'

module Yawast
  module Scanner
    class Ssl
      def self.info(uri, check_ciphers, tdes_session_count)
        begin
          socket = TCPSocket.new(uri.host, uri.port)

          ctx = OpenSSL::SSL::SSLContext.new
          ctx.ciphers = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]

          ssl = OpenSSL::SSL::SSLSocket.new(socket, ctx)
          ssl.hostname = uri.host
          ssl.connect

          cert = ssl.peer_cert

          get_cert_info cert unless cert.nil?

          cert_chain = ssl.peer_cert_chain
          get_cert_chain_info cert_chain, cert

          puts "\t\tQualys SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=#{uri.host}&hideResults=on"
          puts ''

          get_ciphers(uri) if check_ciphers

          ssl.sysclose

          Yawast::Scanner::Plugins::SSL::Sweet32.get_tdes_session_msg_count(uri) if tdes_session_count
        rescue => e
          Yawast::Utilities.puts_error "SSL: Error Reading X509 Details: #{e.message}"
        end
      end

      def self.get_cert_info(cert)
        Yawast::Utilities.puts_info 'Found X509 Certificate:'
        Yawast::Utilities.puts_info "\t\tIssued To: #{cert.subject.common_name} / #{cert.subject.organization}"
        Yawast::Utilities.puts_info "\t\tIssuer: #{cert.issuer.common_name} / #{cert.issuer.organization}"
        Yawast::Utilities.puts_info "\t\tVersion: #{cert.version}"
        Yawast::Utilities.puts_info "\t\tSerial: #{cert.serial}"
        Yawast::Utilities.puts_info "\t\tSubject: #{cert.subject}"

        # check to see if cert is expired
        if cert.not_after > Time.now
          Yawast::Utilities.puts_info "\t\tExpires: #{cert.not_after}"
        else
          Yawast::Utilities.puts_vuln "\t\tExpires: #{cert.not_after} (Expired)"
        end

        # check for SHA1 & MD5 certs
        if cert.signature_algorithm.include?('md5') || cert.signature_algorithm.include?('sha1')
          Yawast::Utilities.puts_vuln "\t\tSignature Algorithm: #{cert.signature_algorithm}"
        else
          Yawast::Utilities.puts_info "\t\tSignature Algorithm: #{cert.signature_algorithm}"
        end

        Yawast::Utilities.puts_info "\t\tKey: #{cert.public_key.class.to_s.gsub('OpenSSL::PKey::', '')}-#{get_x509_pub_key_strength(cert)}"
        Yawast::Utilities.puts_info "\t\t\tKey Hash: #{Digest::SHA1.hexdigest(cert.public_key.to_s)}"

        Yawast::Utilities.puts_info "\t\tExtensions:"
        cert.extensions.each do |ext|
          Yawast::Utilities.puts_info "\t\t\t#{ext}" unless ext.oid == 'subjectAltName' || ext.oid == 'ct_precert_scts'
        end

        # ct_precert_scts
        Yawast::Scanner::Plugins::SSL::SSL.print_precert cert

        # alt names
        alt_names = cert.extensions.find { |e| e.oid == 'subjectAltName' }
        unless alt_names.nil?
          Yawast::Utilities.puts_info "\t\tAlternate Names:"
          alt_names.value.split(',').each { |name| Yawast::Utilities.puts_info "\t\t\t#{name.strip.delete('DNS:')}" }
        end

        Yawast::Scanner::Plugins::SSL::SSL.print_cert_hash cert

        puts
      end

      def self.get_cert_chain_info(cert_chain, cert)
        if cert_chain.count == 1
          # HACK: This is an ugly way to guess if it's a missing intermediate, or self-signed
          # It looks like a change to Ruby's OpenSSL wrapper is needed to actually fix this right.

          if cert.issuer == cert.subject
            Yawast::Utilities.puts_vuln "\t\tCertificate Is Self-Singed"
          else
            Yawast::Utilities.puts_warn "\t\tCertificate Chain Is Incomplete"
          end

          puts ''
        end

        unless cert_chain.nil?
          Yawast::Utilities.puts_info 'Certificate: Chain'
          cert_chain.each do |c|
            Yawast::Utilities.puts_info "\t\tIssued To: #{c.subject.common_name} / #{c.subject.organization}"
            Yawast::Utilities.puts_info "\t\t\tIssuer: #{c.issuer.common_name} / #{c.issuer.organization}"
            Yawast::Utilities.puts_info "\t\t\tExpires: #{c.not_after}"
            Yawast::Utilities.puts_info "\t\t\tKey: #{c.public_key.class.to_s.gsub('OpenSSL::PKey::', '')}-" \
              "#{get_x509_pub_key_strength(c)}"
            Yawast::Utilities.puts_info "\t\t\tSignature Algorithm: #{c.signature_algorithm}"
            Yawast::Utilities.puts_info "\t\t\tHash: #{Digest::SHA1.hexdigest(c.to_der)}"
            puts ''
          end

          puts ''
        end
      end

      def self.get_ciphers(uri)
        puts 'Supported Ciphers:'

        dns = Resolv::DNS.new

        ip = if IPAddress.valid? uri.host
               IPAddress.parse uri.host
             else
               dns.getaddresses(uri.host)[0]
             end

        protocols = %w[ssl2 ssl3 tls1.0 tls1.1 tls1.2]

        protocols.each do |protocol|
          ciphers = case protocol
                      when 'ssl2'
                        SSLShake::SSLv2::CIPHERS
                      when 'ssl3'
                        SSLShake::TLS::SSL3_CIPHERS
                      else
                        SSLShake::TLS::TLS_CIPHERS
                    end

          puts "\tChecking for #{protocol} suites (#{ciphers.count} possible suites)"

          ciphers.each_key do |cipher|
            begin
              res = SSLShake.hello(ip.to_s, port: uri.port, protocol: protocol, ciphers: cipher, servername: uri.host)

              Yawast::Utilities.puts_info "\t\tCipher: #{res['cipher_suite']}" if res['error'] == nil
            rescue => e
              Yawast::Utilities.puts_error "SSL: Error Reading Cipher Details: #{e.message}"
            end
          end
        end

        puts ''
      end

      def self.check_cipher_strength(cipher, ssl)
        if cipher[2] < 112 || cipher[0].include?('RC4')
          # less than 112 bits or RC4, flag as a vuln
          Yawast::Utilities.puts_vuln "\t\tVersion: #{ssl.ssl_version.ljust(7)}\tBits: #{cipher[2]}\tCipher: #{cipher[0]}"
        elsif cipher[2] >= 128
          # secure, probably safe
          Yawast::Utilities.puts_info "\t\tVersion: #{ssl.ssl_version.ljust(7)}\tBits: #{cipher[2]}\tCipher: #{cipher[0]}"
        else
          # weak, but not "omg!" weak.
          Yawast::Utilities.puts_warn "\t\tVersion: #{ssl.ssl_version.ljust(7)}\tBits: #{cipher[2]}\tCipher: #{cipher[0]}"
        end
      end

      # private methods
      class << self
        private

        def get_x509_pub_key_strength(cert)
          begin
            if cert.public_key.class == OpenSSL::PKey::EC
              cert.public_key.group.curve_name
            else
              cert.public_key.strength
            end
          rescue => e
            "(Strength Unknown: #{e.message})"
          end
        end
      end
    end
  end
end
