require 'ssllabs'
require 'date'

module Yawast
  module Scanner
    class SslLabs
      def self.info(uri)
        puts 'Beginning SSL Labs scan (this could take a minute or two)'

        api = Ssllabs::Api.new

        info = api.info

        info.messages.each do |msg|
          puts "[SSL Labs]\t#{msg}"
        end

        begin
          api.analyse(host: uri.host, publish: 'off', fromCache: 'on', all: 'done', ignoreMismatch: 'on')

          status = ''
          host = nil
          until status == 'READY' || status == 'ERROR' || status == 'DNS'
            sleep(5)

            host = api.analyse(host: uri.host, publish: 'off', all: 'done', ignoreMismatch: 'on')
            status = host.status

            print '.'
          end
          puts
          puts

          host.endpoints.each do |ep|
            Yawast::Utilities.puts_info "IP: #{ep.ip_address} - Grade: #{ep.grade}"
            puts

            begin
              if ep.status_message == 'Ready'
                get_cert_info(ep)
                get_config_info(ep)
                get_proto_info(ep)
              else
                Yawast::Utilities.puts_error "Error getting information for IP: #{ep.ip_address}: #{ep.status_message}"
              end
            rescue => e
              Yawast::Utilities.puts_error "Error getting information for IP: #{ep.ip_address}: #{e.message}"
            end

            puts
          end
        rescue => e
          Yawast::Utilities.puts_error "SSL Labs Error: #{e.message}"
        end
      end

      def self.get_cert_info (ep)
        # get the ChainCert info for the server cert - needed for extra details
        cert = nil
        ep.details.chain.certs.each do |c|
          if c.subject == ep.details.cert.subject
            cert = c
          end
        end

        puts "\tCertificate Information:"
        unless ep.details.cert.valid?
          Yawast::Utilities.puts_vuln "\t\tCertificate Has Issues - Not Valid"

          if ep.details.cert.issues & 1 != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: no chain of trust"
          end

          if ep.details.cert.issues & (1<<1) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: certificate not yet valid"
          end

          if ep.details.cert.issues & (1<<2) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: certificate expired"
          end

          if ep.details.cert.issues & (1<<3) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: hostname mismatch"
          end

          if ep.details.cert.issues & (1<<4) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: revoked"
          end

          if ep.details.cert.issues & (1<<5) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: bad common name"
          end

          if ep.details.cert.issues & (1<<6) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: self-signed"
          end

          if ep.details.cert.issues & (1<<7) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: blacklisted"
          end

          if ep.details.cert.issues & (1<<8) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: insecure signature"
          end
        end

        Yawast::Utilities.puts_info "\t\tSubject: #{ep.details.cert.subject}"
        Yawast::Utilities.puts_info "\t\tCommon Names: #{ep.details.cert.common_names}"

        Yawast::Utilities.puts_info "\t\tAlternative names:"
        ep.details.cert.alt_names.each do |name|
          Yawast::Utilities.puts_info "\t\t\t#{name}"
        end

        # here we divide the time by 1000 to strip the fractions of a second off.
        Yawast::Utilities.puts_info "\t\tNot Before: #{Time.at(ep.details.cert.not_before / 1000).utc.to_datetime}"
        Yawast::Utilities.puts_info "\t\tNot After: #{Time.at(ep.details.cert.not_after / 1000).utc.to_datetime}"

        if cert.key_alg == 'EC'
          Yawast::Utilities.puts_info "\t\tKey: #{cert.key_alg} #{cert.key_size} (RSA equivalent: #{cert.key_strength})"
        else
          if cert.key_size < 2048
            Yawast::Utilities.puts_vuln "\t\tKey: #{cert.key_alg} #{cert.key_size}"
          else
            Yawast::Utilities.puts_info "\t\tKey: #{cert.key_alg} #{cert.key_size}"
          end
        end

        Yawast::Utilities.puts_info "\t\tIssuer: #{ep.details.cert.issuer_label}"

        if ep.details.cert.sig_alg.include?('SHA1') || ep.details.cert.sig_alg.include?('MD5')
          Yawast::Utilities.puts_vuln "\t\tSignature algorithm: #{ep.details.cert.sig_alg}"
        else
          Yawast::Utilities.puts_info "\t\tSignature algorithm: #{ep.details.cert.sig_alg}"
        end

        #todo - figure out what the options for this value are
        if ep.details.cert.validation_type == 'E'
          Yawast::Utilities.puts_info "\t\tExtended Validation: Yes"
        else
          Yawast::Utilities.puts_info "\t\tExtended Validation: No"
        end

        if ep.details.cert.sct?
          # check the first bit, SCT in cert
          if ep.details.has_sct & 1 != 0
            Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in certificate"
          end

          # check second bit, SCT in stapled OSCP response
          if ep.details.has_sct & (1<<1) != 0
            Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in the stapled OCSP response"
          end

          # check third bit, SCT in the TLS extension
          if ep.details.has_sct & (1<<2) != 0
            Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in the TLS extension (ServerHello)"
          end
        else
          Yawast::Utilities.puts_info "\t\tCertificate Transparency: No"
        end

        case ep.details.cert.must_staple
          when 0
            Yawast::Utilities.puts_info "\t\tOCSP Must Staple: No"
          when 1
            Yawast::Utilities.puts_warn "\t\tOCSP Must Staple: Supported, but OCSP response is not stapled"
          when 2
            Yawast::Utilities.puts_info "\t\tOCSP Must Staple: OCSP response is stapled"
          else
            Yawast::Utilities.puts_error "\t\tOCSP Must Staple: Unknown Response #{ep.details.cert.must_staple}"
        end

        if ep.details.cert.revocation_info & 1 != 0
          Yawast::Utilities.puts_info "\t\tRevocation information: CRL information available"
        end
        if ep.details.cert.revocation_info & (1<<1) != 0
          Yawast::Utilities.puts_info "\t\tRevocation information: OCSP information available"
        end

        case ep.details.cert.revocation_status
          when 0
            Yawast::Utilities.puts_info "\t\tRevocation status: not checked"
          when 1
            Yawast::Utilities.puts_vuln "\t\tRevocation status: certificate revoked"
          when 2
            Yawast::Utilities.puts_info "\t\tRevocation status: certificate not revoked"
          when 3
            Yawast::Utilities.puts_error "\t\tRevocation status: revocation check error"
          when 4
            Yawast::Utilities.puts_info "\t\tRevocation status: no revocation information"
          when 5
            Yawast::Utilities.puts_error "\t\tRevocation status: SSL Labs internal error"
          else
            Yawast::Utilities.puts_error "\t\tRevocation status: Unknown response #{ep.details.cert.revocation_status}"
        end

        puts
      end

      def self.get_config_info(ep)
        puts "\tConfiguration Information:"

        puts "\t\tProtocol Support:"
        ep.details.protocols.each do |proto|
          if proto.name == 'SSL'
            Yawast::Utilities.puts_vuln "\t\t\t#{proto.name} #{proto.version}"
          else
            Yawast::Utilities.puts_info "\t\t\t#{proto.name} #{proto.version}"
          end
        end
        puts

        puts "\t\tCipher Suite Support:"
        if ep.details.suites.list != nil
          ep.details.suites.list.each do |suite|
            ke = nil
            if suite.name.include? 'ECDHE'
              ke = "ECDHE-#{suite.ecdh_bits}-bits"
            elsif suite.name.include? 'ECDH'
              ke = "ECDH-#{suite.ecdh_bits}"
            elsif suite.name.include? 'DHE'
              ke = "DHE-#{suite.dh_strength}-bits"
            elsif suite.name.include? 'DH'
              ke = "DH-#{suite.dh_strength}-bits"
            end

            suite_info = nil
            if ke != nil
              suite_info = "#{suite.name.ljust(50)} - #{suite.cipher_strength}-bits - #{ke}"
            else
              suite_info = "#{suite.name.ljust(50)} - #{suite.cipher_strength}-bits"
            end

            if suite.secure?
              if suite.cipher_strength >= 128
                Yawast::Utilities.puts_info "\t\t\t#{suite_info}"
              else
                Yawast::Utilities.puts_warn "\t\t\t#{suite_info}"
              end
            else
              Yawast::Utilities.puts_vuln "\t\t\t#{suite_info}"
            end
          end
        else
          Yawast::Utilities.puts_error "\t\t\tInformation Not Available"
        end

        puts

        puts "\t\tHandshake Simulation:"
        if ep.details.sims.results != nil
          ep.details.sims.results.each do |sim|
            name = "#{sim.client.name} #{sim.client.version}"
            if sim.client.platform != nil
              name += " / #{sim.client.platform}"
            end
            name = name.ljust(28)

            if sim.success?
              protocol = nil
              ep.details.protocols.each do |proto|
                if sim.protocol_id == proto.id
                  protocol = "#{proto.name} #{proto.version}"
                end
              end

              suite_name = nil
              secure = true
              ep.details.suites.list.each do |suite|
                if sim.suite_id == suite.id
                  suite_name = suite.name
                  secure = suite.secure?
                end
              end

              if secure
                Yawast::Utilities.puts_info "\t\t\t#{name} - #{protocol} - #{suite_name}"
              else
                Yawast::Utilities.puts_vuln "\t\t\t#{name} - #{protocol} - #{suite_name}"
              end
            else
              Yawast::Utilities.puts_error "\t\t\t#{name} - Simulation Failed"
            end
          end
        else
          Yawast::Utilities.puts_error "\t\t\tInformation Not Available"
        end

        puts
      end

      def self.get_proto_info(ep)
        puts "\t\tProtocol & Vulnerability Information:"

        if ep.details.drown_vulnerable?
          Yawast::Utilities.puts_vuln "\t\t\tDROWN: Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tDROWN: No"
        end

        if ep.details.reneg_support & 1 != 0
          Yawast::Utilities.puts_vuln "\t\t\tSecure Renegotiation: insecure client-initiated renegotiation supported"
        elsif ep.details.reneg_support & (1<<1) != 0
          Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: secure renegotiation supported"
        elsif ep.details.reneg_support & (1<<2) != 0
          Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: secure client-initiated renegotiation supported"
        elsif ep.details.reneg_support & (1<<3) != 0
          Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: server requires secure renegotiation support"
        end

        if ep.details.poodle?
          Yawast::Utilities.puts_vuln "\t\t\tPOODLE (SSL): Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tPOODLE (SSL): No"
        end

        case ep.details.poodle_tls
          when -3
            Yawast::Utilities.puts_info "\t\t\tPOODLE (TLS): Inconclusive (Timeout)"
          when -2
            Yawast::Utilities.puts_info "\t\t\tPOODLE (TLS): TLS Not Supported"
          when -1
            Yawast::Utilities.puts_error "\t\t\tPOODLE (TLS): Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tPOODLE (TLS): Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tPOODLE (TLS): No"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tPOODLE (TLS): Vulnerable"
          else
            Yawast::Utilities.puts_error "\t\t\tPOODLE (TLS): Unknown Response #{ep.details.poodle_tls}"
        end

        if ep.details.fallback_scsv?
          Yawast::Utilities.puts_info "\t\t\tDowngrade Prevention: Yes"
        else
          Yawast::Utilities.puts_warn "\t\t\tDowngrade Prevention: No"
        end

        if ep.details.compression_methods & 1 != 0
          Yawast::Utilities.puts_warn "\t\t\tCompression: DEFLATE"
        else
          Yawast::Utilities.puts_info "\t\t\tCompression: No"
        end

        if ep.details.heartbleed?
          Yawast::Utilities.puts_vuln "\t\t\tHeartbleed: Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tHeartbleed: No"
        end

        case ep.details.open_ssl_ccs
          when -1
            Yawast::Utilities.puts_error "\t\t\tOpenSSL CCS (CVE-2014-0224): Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tOpenSSL CCS (CVE-2014-0224): Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tOpenSSL CCS (CVE-2014-0224): No"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tOpenSSL CCS (CVE-2014-0224): Vulnerable - Not Exploitable"
          when 3
            Yawast::Utilities.puts_vuln "\t\t\tOpenSSL CCS (CVE-2014-0224): Vulnerable"
          else
            Yawast::Utilities.puts_error "\t\t\tOpenSSL CCS (CVE-2014-0224): Unknown Response #{ep.details.open_ssl_ccs}"
        end

        case ep.details.open_ssl_lucky_minus20
          when -1
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): No"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Vulnerable"
          else
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Unknown Response #{ep.details.open_ssl_lucky_minus20}"
        end

        if ep.details.forward_secrecy & (1<<2) != 0
          Yawast::Utilities.puts_info "\t\t\tForward Secrecy: Yes (all simulated clients)"
        elsif ep.details.forward_secrecy & (1<<1) != 0
          Yawast::Utilities.puts_info "\t\t\tForward Secrecy: Yes (modern clients)"
        elsif ep.details.forward_secrecy & 1 != 0
          Yawast::Utilities.puts_warn "\t\t\tForward Secrecy: Yes (limited support)"
        else
          Yawast::Utilities.puts_vuln "\t\t\tForward Secrecy: No"
        end

        if ep.details.ocsp_stapling?
          Yawast::Utilities.puts_info "\t\t\tOCSP Stapling: Yes"
        else
          Yawast::Utilities.puts_warn "\t\t\tOCSP Stapling: No"
        end

        if ep.details.freak?
          Yawast::Utilities.puts_vuln "\t\t\tFREAK: Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tFREAK: No"
        end

        if ep.details.logjam?
          Yawast::Utilities.puts_vuln "\t\t\tLogjam: Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tLogjam: No"
        end

        case ep.details.dh_uses_known_primes
          when 0
            Yawast::Utilities.puts_info "\t\t\tUses common DH primes: No"
          when 1
            Yawast::Utilities.puts_warn "\t\t\tUses common DH primes: Yes (not weak)"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tUses common DH primes: Yes (weak)"
          else
            unless ep.details.dh_uses_known_primes == nil
              Yawast::Utilities.puts_error "\t\t\tUses common DH primes: Unknown Response #{ep.details.dh_uses_known_primes}"
            end
        end

        puts
      end
    end
  end
end
