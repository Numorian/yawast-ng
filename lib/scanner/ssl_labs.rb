require 'ssllabs'
require 'date'
require 'openssl'
require 'digest/sha1'
require 'json'

module Yawast
  module Scanner
    # noinspection RubyResolve
    class SslLabs
      def self.info(uri, tdes_session_count)
        puts 'Beginning SSL Labs scan (this could take a minute or two)'

        begin
          endpoint = Yawast::Commands::Utils.extract_uri(['https://api.ssllabs.com'])

          info_body = Yawast::Scanner::Plugins::SSL::SSLLabs::Info.call_info endpoint
          puts "[SSL Labs] #{Yawast::Scanner::Plugins::SSL::SSLLabs::Info.extract_msg(info_body)}"

          Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.start_scan endpoint, uri.host

          status = ''
          until status == 'READY' || status == 'ERROR' || status == 'DNS'
            # poll for updates every 5 seconds
            # don't want to poll faster, to avoid excess load / errors
            sleep(5)

            data_body = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.get_results endpoint, uri.host
            status = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.extract_status data_body

            print '.'
          end
          puts
          puts
          puts "\tSSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=#{uri.host}&hideResults=on"
          puts

          process_results uri, JSON.parse(data_body), tdes_session_count
        rescue => e
          puts
          Yawast::Utilities.puts_error "SSL Labs Error: #{e.message}"
        end
      end

      def self.process_results(uri, body, tdes_session_count)
        begin
          body['endpoints'].each do |ep|
            Yawast::Utilities.puts_info "IP: #{ep['ipAddress']} - Grade: #{ep['grade']}"
            puts

            begin
              if ep['statusMessage'] == 'Ready'
                get_cert_info ep, body
                get_config_info ep
                get_proto_info ep
              else
                Yawast::Utilities.puts_error "Error getting information for IP: #{ep['ipAddress']}: #{ep['statusMessage']}"
              end
            rescue => e
              Yawast::Utilities.puts_error "Error getting information for IP: #{ep['ipAddress']}: #{e.message}"
            end

            Yawast::Scanner::Plugins::SSL::Sweet32.get_tdes_session_msg_count(uri) if tdes_session_count

            puts
          end
        rescue => e
          puts
          Yawast::Utilities.puts_error "SSL Labs Error: #{e.message}"
        end
      end

      def self.get_cert_info (ep, body)
        # get the ChainCert info for the server cert - needed for extra details
        cert = nil
        ossl_cert = nil
        body['certs'].each do |c|
          if c['id'] == ep['details']['certChains'][0]['certIds'][0]
            cert = c
            ossl_cert = OpenSSL::X509::Certificate.new cert['raw']
          end
        end

        puts "\tCertificate Information:"
        unless cert['issues'] == 0
          Yawast::Utilities.puts_vuln "\t\tCertificate Has Issues - Not Valid"

          if cert['issues'] & 1 != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: no chain of trust"
          end

          if cert['issues'] & (1<<1) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: certificate not yet valid"
          end

          if cert['issues'] & (1<<2) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: certificate expired"
          end

          if cert['issues'] & (1<<3) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: hostname mismatch"
          end

          if cert['issues'] & (1<<4) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: revoked"
          end

          if cert['issues'] & (1<<5) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: bad common name"
          end

          if cert['issues'] & (1<<6) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: self-signed"
          end

          if cert['issues'] & (1<<7) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: blacklisted"
          end

          if cert['issues'] & (1<<8) != 0
            Yawast::Utilities.puts_vuln "\t\tCertificate Issue: insecure signature"
          end
        end

        Yawast::Utilities.puts_info "\t\tSubject: #{cert['subject']}"
        Yawast::Utilities.puts_info "\t\tCommon Names: #{cert['commonNames'].join(' ')}"

        Yawast::Utilities.puts_info "\t\tAlternative names:"
        cert['altNames'].each do |name|
          Yawast::Utilities.puts_info "\t\t\t#{name}"
        end

        # here we divide the time by 1000 to strip the fractions of a second off.
        Yawast::Utilities.puts_info "\t\tNot Before: #{Time.at(cert['notBefore'] / 1000).utc.to_datetime}"
        Yawast::Utilities.puts_info "\t\tNot After: #{Time.at(cert['notAfter'] / 1000).utc.to_datetime}"

        if cert['keyAlg'] == 'EC'
          Yawast::Utilities.puts_info "\t\tKey: #{cert['keyAlg']} #{cert['keySize']} (RSA equivalent: #{cert['keyStrength']})"
        else
          if cert['keySize'] < 2048
            Yawast::Utilities.puts_vuln "\t\tKey: #{cert['keyAlg']} #{cert['keySize']}"
          else
            Yawast::Utilities.puts_info "\t\tKey: #{cert['keyAlg']} #{cert['keySize']}"
          end
        end

        Yawast::Utilities.puts_info "\t\tPublic Key Hash: #{Digest::SHA1.hexdigest(ossl_cert.public_key.to_s)}"

        Yawast::Utilities.puts_info "\t\tVersion: #{ossl_cert.version}"

        Yawast::Utilities.puts_info "\t\tSerial: #{ossl_cert.serial}"

        Yawast::Utilities.puts_info "\t\tIssuer: #{cert['issuerSubject']}"

        if cert['sigAlg'].include?('SHA1') || cert['sigAlg'].include?('MD5')
          Yawast::Utilities.puts_vuln "\t\tSignature algorithm: #{cert['sigAlg']}"
        else
          Yawast::Utilities.puts_info "\t\tSignature algorithm: #{cert['sigAlg']}"
        end

        #todo - figure out what the options for this value are
        if cert['validationType'] == 'E'
          Yawast::Utilities.puts_info "\t\tExtended Validation: Yes"
        elsif cert['validationType'] == 'D'
          Yawast::Utilities.puts_info "\t\tExtended Validation: No (Domain Control)"
        else
          Yawast::Utilities.puts_info "\t\tExtended Validation: No"
        end

        if cert['sct']
          # check the first bit, SCT in cert
          if ep['details']['hasSct'] & 1 != 0
            Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in certificate"
          end

          # check second bit, SCT in stapled OSCP response
          if ep['details']['hasSct'] & (1<<1) != 0
            Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in the stapled OCSP response"
          end

          # check third bit, SCT in the TLS extension
          if ep['details']['hasSct'] & (1<<2) != 0
            Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in the TLS extension (ServerHello)"
          end
        else
          Yawast::Utilities.puts_info "\t\tCertificate Transparency: No"
        end

        Yawast::Utilities.puts_info "\t\tOCSP Must Staple: #{cert['mustStaple']}"

        if cert['revocationInfo'] & 1 != 0
          Yawast::Utilities.puts_info "\t\tRevocation information: CRL information available"
        end
        if cert['revocationInfo'] & (1<<1) != 0
          Yawast::Utilities.puts_info "\t\tRevocation information: OCSP information available"
        end

        case cert['revocationStatus']
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
            Yawast::Utilities.puts_error "\t\tRevocation status: Unknown response #{cert['revocationStatus']}"
        end

        Yawast::Utilities.puts_info "\t\tExtensions:"
        ossl_cert.extensions.each { |ext| Yawast::Utilities.puts_info "\t\t\t#{ext}" unless ext.oid == 'subjectAltName' }

        hash = Digest::SHA1.hexdigest(ossl_cert.to_der)
        Yawast::Utilities.puts_info "\t\tHash: #{hash}"
        puts "\t\t\thttps://censys.io/certificates?q=#{hash}"
        puts "\t\t\thttps://crt.sh/?q=#{hash}"

        puts
      end

      def self.get_config_info(ep)
        puts "\tConfiguration Information:"

        puts "\t\tProtocol Support:"
        protos = Hash.new
        ep['details']['protocols'].each do |proto|
          if proto['name'] == 'SSL'
            Yawast::Utilities.puts_vuln "\t\t\t#{proto['name']} #{proto['version']}"
          else
            Yawast::Utilities.puts_info "\t\t\t#{proto['name']} #{proto['version']}"
          end

          protos[proto['id']] = "#{proto['name']} #{proto['version']}"
        end
        puts

        puts "\t\tCipher Suite Support:"
        if ep['details']['suites'] != nil
          ep['details']['suites'].each do |proto_suites|
            Yawast::Utilities.puts_info "\t\t\t#{protos[proto_suites['protocol']]}"

            proto_suites['list'].each do |suite|
              ke = nil
              if suite['kxType'] != nil
                if suite['namedGroupBits'] != nil
                  ke = "#{suite['kxType']}-#{suite['namedGroupBits']} / #{suite['namedGroupName']} (#{suite['kxStrength']} equivalent)"
                else
                  ke = "#{suite['kxType']}-#{suite['kxStrength']}"
                end
              end

              strength = suite['cipherStrength']
              if suite['name'].include? '3DES'
                # in this case, the effective strength is only 112 bits,
                #  which is what we want to report. So override SSL Labs
                strength = 112
              end

              if ke != nil
                suite_info = "#{suite['name'].ljust(50)} - #{strength}-bits - #{ke}"
              else
                suite_info = "#{suite['name'].ljust(50)} - #{strength}-bits"
              end

              if cipher_suite_secure? suite
                if strength >= 128
                  Yawast::Utilities.puts_info "\t\t\t  #{suite_info}"
                else
                  Yawast::Utilities.puts_warn "\t\t\t  #{suite_info}"
                end
              else
                Yawast::Utilities.puts_vuln "\t\t\t  #{suite_info}"
              end
            end
          end
        else
          Yawast::Utilities.puts_error "\t\t\t  Information Not Available"
        end

        puts

        puts "\t\tHandshake Simulation:"
        if ep['details']['sims']['results'] != nil
          ep['details']['sims']['results'].each do |sim|
            name = "#{sim['client']['name']} #{sim['client']['version']}"
            if sim['client']['platform'] != nil
              name += " / #{sim['client']['platform']}"
            end
            name = name.ljust(28)

            if sim['errorCode'] == 0
              protocol = protos[sim['protocolId']]

              ke = nil
              if sim['kxType'] != nil
                if sim['namedGroupBits'] != nil
                  ke = "#{sim['kxType']}-#{sim['namedGroupBits']} / #{sim['namedGroupName']} (#{sim['kxStrength']} equivalent)"
                else
                  ke = "#{sim['kxType']}-#{sim['kxStrength']}"
                end
              end

              suite_name = "#{sim['suiteName']} - #{ke}"

              Yawast::Utilities.puts_info "\t\t\t#{name} - #{protocol} - #{suite_name}"
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

        if ep['details']['drownVulnerable']
          Yawast::Utilities.puts_vuln "\t\t\tDROWN: Vulnerable"

          ep['details']['drownHosts'].each do |dh|
            Yawast::Utilities.puts_vuln "\t\t\t\t#{dh['ip']}:#{dh['port']} - #{dh['status']}"
            puts "\t\t\t\thttps://test.drownattack.com/?site=#{dh['ip']}"
          end
        else
          Yawast::Utilities.puts_info "\t\t\tDROWN: No"
        end

        if ep['details']['renegSupport'] & 1 != 0
          Yawast::Utilities.puts_vuln "\t\t\tSecure Renegotiation: insecure client-initiated renegotiation supported"
        end
        if ep['details']['renegSupport'] & (1<<1) != 0
          Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: secure renegotiation supported"
        end
        if ep['details']['renegSupport'] & (1<<2) != 0
          Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: secure client-initiated renegotiation supported"
        end
        if ep['details']['renegSupport'] & (1<<3) != 0
          Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: server requires secure renegotiation support"
        end

        if ep['details']['poodle']
          Yawast::Utilities.puts_vuln "\t\t\tPOODLE (SSL): Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tPOODLE (SSL): No"
        end

        case ep['details']['poodleTls']
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
            Yawast::Utilities.puts_error "\t\t\tPOODLE (TLS): Unknown Response #{ep['details'].poodle_tls}"
        end

        if ep['details']['fallbackScsv']
          Yawast::Utilities.puts_info "\t\t\tDowngrade Prevention: Yes"
        else
          Yawast::Utilities.puts_warn "\t\t\tDowngrade Prevention: No"
        end

        if ep['details']['compressionMethods'] & 1 != 0
          Yawast::Utilities.puts_warn "\t\t\tCompression: DEFLATE"
        else
          Yawast::Utilities.puts_info "\t\t\tCompression: No"
        end

        if ep['details']['heartbleed']
          Yawast::Utilities.puts_vuln "\t\t\tHeartbleed: Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tHeartbleed: No"
        end

        case ep['details']['openSslCcs']
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
            Yawast::Utilities.puts_error "\t\t\tOpenSSL CCS (CVE-2014-0224): Unknown Response #{ep['details'].open_ssl_ccs}"
        end

        case ep['details']['openSSLLuckyMinus20']
          when -1
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): No"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Vulnerable"
          else
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Unknown Response #{ep['details']['openSSLLuckyMinus20']}"
        end

        if ep['details']['forwardSecrecy'] & (1<<2) != 0
          Yawast::Utilities.puts_info "\t\t\tForward Secrecy: Yes (all simulated clients)"
        elsif ep['details']['forwardSecrecy'] & (1<<1) != 0
          Yawast::Utilities.puts_info "\t\t\tForward Secrecy: Yes (modern clients)"
        elsif ep['details']['forwardSecrecy'] & 1 != 0
          Yawast::Utilities.puts_warn "\t\t\tForward Secrecy: Yes (limited support)"
        else
          Yawast::Utilities.puts_vuln "\t\t\tForward Secrecy: No"
        end

        if ep['details']['ocspStapling']
          Yawast::Utilities.puts_info "\t\t\tOCSP Stapling: Yes"
        else
          Yawast::Utilities.puts_warn "\t\t\tOCSP Stapling: No"
        end

        if ep['details']['freak']
          Yawast::Utilities.puts_vuln "\t\t\tFREAK: Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tFREAK: No"
        end

        if ep['details']['logjam']
          Yawast::Utilities.puts_vuln "\t\t\tLogjam: Vulnerable"
        else
          Yawast::Utilities.puts_info "\t\t\tLogjam: No"
        end

        case ep['details']['dhUsesKnownPrimes']
          when 0
            Yawast::Utilities.puts_info "\t\t\tUses common DH primes: No"
          when 1
            Yawast::Utilities.puts_warn "\t\t\tUses common DH primes: Yes (not weak)"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tUses common DH primes: Yes (weak)"
          else
            unless ep['details']['dhUsesKnownPrimes'] == nil
              Yawast::Utilities.puts_error "\t\t\tUses common DH primes: Unknown Response #{ep['details']['dhUsesKnownPrimes']}"
            end
        end

        if ep['details']['dhYsReuse']
          Yawast::Utilities.puts_vuln "\t\t\tDH public server param (Ys) reuse: Yes"
        else
          Yawast::Utilities.puts_info "\t\t\tDH public server param (Ys) reuse: No"
        end

        if ep['details']['protocolIntolerance'] > 0
          if ep['details']['protocolIntolerance'] & 1 != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.0"
          end

          if ep['details']['protocolIntolerance'] & (1<<1) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.1"
          end

          if ep['details']['protocolIntolerance'] & (1<<2) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.2"
          end

          if ep['details']['protocolIntolerance'] & (1<<3) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.3"
          end

          if ep['details']['protocolIntolerance'] & (1<<4) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.152"
          end

          if ep['details']['protocolIntolerance'] & (1<<5) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 2.152"
          end
        else
          Yawast::Utilities.puts_info "\t\t\tProtocol Intolerance: No"
        end

        puts
      end

      def self.cipher_suite_secure?(suite)
        secure = true

        # check for weak DH
        if suite['kxStrength'] != nil && suite['kxStrength'] < 2048
          secure = false
        end
        # check for RC4
        if suite['name'].include? 'RC4'
          secure = false
        end
        # check for weak suites
        if suite['cipherStrength'] < 112
          secure = false
        end

        secure
      end
    end
  end
end
