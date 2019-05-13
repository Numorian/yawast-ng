# frozen_string_literal: true

require 'date'
require 'openssl'
require 'digest/sha1'
require 'json'

module Yawast
  module Scanner
    class SslLabs < Yawast::Scanner::Base
      def self.info(uri, tdes_session_count)
        puts 'Beginning SSL Labs scan (this could take a minute or two)'

        begin
          endpoint = URI::DEFAULT_PARSER.parse 'https://api.ssllabs.com'

          info_body = Yawast::Scanner::Plugins::SSL::SSLLabs::Info.call_info endpoint

          Yawast::Scanner::Plugins::SSL::SSLLabs::Info.extract_msg(info_body).each do |msg|
            puts "[SSL Labs] #{msg}"
          end

          Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.scan endpoint, uri.host, true

          status = ''
          error_count = 0
          until status == 'READY' || status == 'ERROR' || status == 'DNS'
            # poll for updates every 5 seconds
            # don't want to poll faster, to avoid excess load / errors
            sleep(5)

            begin
              data_body = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.scan endpoint, uri.host, false
              status = Yawast::Scanner::Plugins::SSL::SSLLabs::Analyze.extract_status data_body
            rescue # rubocop:disable Style/RescueStandardError
              # if we find ourselves here, we want to try a couple more times before we give up for good
              error_count += 1

              if error_count > 3
                raise
              end
            end

            print '.'
          end
          puts
          puts
          puts "\tSSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=#{uri.host}&hideResults=on"
          puts

          json = nil
          begin
            json = JSON.parse data_body
          rescue => e # rubocop:disable Style/RescueStandardError
            raise Exception, "Invalid response from SSL Labs: '#{e.message}'"
          end

          process_results uri, json, tdes_session_count
        rescue => e # rubocop:disable Style/RescueStandardError
          puts
          Yawast::Utilities.puts_error "SSL Labs Error: #{e.message}"
        end
      end

      def self.process_results(uri, body, tdes_session_count)
        begin
          if !body['endpoints'].nil?
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
              rescue => e # rubocop:disable Style/RescueStandardError
                Yawast::Utilities.puts_error "Error getting information for IP: #{ep['ipAddress']}: #{e.message}"
              end

              Yawast::Scanner::Plugins::SSL::Sweet32.get_tdes_session_msg_count(uri) if tdes_session_count

              puts
            end
          else
            Yawast::Utilities.puts_error 'SSL Labs Error: No Endpoint Data Received.'

            # TODO: Remove this before release
            puts
            puts "DEBUG DATA (send to adam@adamcaudill.com): #{body}"
            puts
            puts
          end
        rescue => e # rubocop:disable Style/RescueStandardError
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
        unless cert['issues'].zero?
          Yawast::Utilities.puts_vuln "\t\tCertificate Has Issues - Not Valid"

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: no chain of trust" if cert['issues'] & 1 != 0

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: certificate not yet valid" if cert['issues'] & (1 << 1) != 0

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: certificate expired" if cert['issues'] & (1 << 2) != 0

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: hostname mismatch" if cert['issues'] & (1 << 3) != 0

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: revoked" if cert['issues'] & (1 << 4) != 0

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: bad common name" if cert['issues'] & (1 << 5) != 0

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: self-signed" if cert['issues'] & (1 << 6) != 0

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: blacklisted" if cert['issues'] & (1 << 7) != 0

          Yawast::Utilities.puts_vuln "\t\tCertificate Issue: insecure signature" if cert['issues'] & (1 << 8) != 0
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

        serial = format('%02x', ossl_cert.serial.to_i)
        serial = "0#{serial}" unless serial.length.even?
        Yawast::Utilities.puts_info "\t\tSerial: #{serial}"

        ## if the serial is exactly 16 hex digits, it may have an entropy issue.
        if serial.length == 16
          puts

          Yawast::Utilities.puts_warn "\t\tSerial number is exactly 64 bits. Serial may not comply with CA/B Forum requirements."
          Yawast::Utilities.puts_raw "\t\t\t See https://adamcaudill.com/2019/03/09/tls-64bit-ish-serial-numbers-mass-revocation/ for details."

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_serial_exactly_64_bits',
                                          {vulnerable: true, length: (serial.length / 2) * 8}

          puts
        elsif serial.length < 16
          puts

          Yawast::Utilities.puts_vuln "\t\tSerial number is less than 64 bits. Serial does not comply with CA/B Forum requirements."

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_serial_less_than_64_bits',
                                          {vulnerable: true, length: (serial.length / 2) * 8}

          puts
        else
          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_serial_exactly_64_bits',
                                          {vulnerable: false, length: (serial.length / 2) * 8}
          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_serial_less_than_64_bits',
                                          {vulnerable: false, length: (serial.length / 2) * 8}
        end

        Yawast::Utilities.puts_info "\t\tIssuer: #{cert['issuerSubject']}"

        if cert['sigAlg'].include?('SHA1') || cert['sigAlg'].include?('MD5')
          Yawast::Utilities.puts_vuln "\t\tSignature algorithm: #{cert['sigAlg']}"
          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_weak_sig_alg',
                                          {vulnerable: true, algorithm: cert['sigAlg']}
        else
          Yawast::Utilities.puts_info "\t\tSignature algorithm: #{cert['sigAlg']}"
          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_weak_sig_alg',
                                          {vulnerable: false, algorithm: cert['sigAlg']}
        end

        # TODO: figure out what the options for this value are
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
          if ep['details']['hasSct'] & (1 << 1) != 0
            Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in the stapled OCSP response"
          end

          # check third bit, SCT in the TLS extension
          if ep['details']['hasSct'] & (1 << 2) != 0
            Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in the TLS extension (ServerHello)"
          end
        else
          Yawast::Utilities.puts_info "\t\tCertificate Transparency: No"
        end

        Yawast::Utilities.puts_info "\t\tOCSP Must Staple: #{cert['mustStaple']}"

        if cert['revocationInfo'] & 1 != 0
          Yawast::Utilities.puts_info "\t\tRevocation information: CRL information available"
        end
        if cert['revocationInfo'] & (1 << 1) != 0
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
        ossl_cert.extensions.each { |ext| Yawast::Utilities.puts_info "\t\t\t#{ext}" unless ext.oid == 'subjectAltName' || ext.oid == 'ct_precert_scts' }

        # ct_precert_scts
        Yawast::Scanner::Plugins::SSL::SSL.print_precert ossl_cert

        Yawast::Scanner::Plugins::SSL::SSL.print_cert_hash ossl_cert

        puts
        Yawast::Utilities.puts_info "\t\tCertificate Chains:"
        ep['details']['certChains'].each do |chain|
          path_count = 0

          # build list of trust paths
          trust_paths = {}
          chain['trustPaths'].each do |path|
            trusts = nil
            # in practice, it seems there is only only per path, but just in case
            path['trust'].each do |trust|
              trust_line = if trust['isTrusted']
                             "#{trust['rootStore']} (trusted)"
                           else
                             "#{trust['rootStore']} (#{trust['trustErrorMessage']})"
                           end

              if trusts.nil?
                trusts = trust_line
              else
                trusts += " #{trust_line}"
              end
            end

            # build the hash and add the list of roots
            if trust_paths.has_key? path['certIds']
              trust_paths[path['certIds']] += " #{trusts}"
            else
              trust_paths[path['certIds']] = trusts
            end
          end

          # process each of the trust paths
          trust_paths.each_key do |key|
            path_count += 1
            puts "\t\t  Path #{path_count}:"
            puts "\t\t   Root Stores: #{trust_paths[key]}"

            # cert chain issues
            if chain['issues'] & (1 << 1) != 0
              Yawast::Utilities.puts_warn "\t\tCertificate Chain Issue: incomplete chain"
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'tls_chain_incomplete',
                                              {vulnerable: true}
            else
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'tls_chain_incomplete',
                                              {vulnerable: false}
            end

            if chain['issues'] & (1 << 2) != 0
              Yawast::Utilities.puts_warn "\t\tCertificate Chain Issue: chain contains unrelated/duplicate certificates"
            end

            Yawast::Utilities.puts_warn "\t\tCertificate Chain Issue: incorrect order" if chain['issues'] & (1 << 3) != 0

            Yawast::Utilities.puts_warn "\t\tCertificate Chain Issue: contains anchor" if chain['issues'] & (1 << 4) != 0

            Yawast::Utilities.puts_warn "\t\tCertificate Chain Issue: untrusted" if cert['issues'] & (1 << 5) != 0

            # setup the log entry for a symantec root - this will overwrite if one is found
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_symantec_root',
                                            {vulnerable: false, root_hash: ''}

            key.each do |path_cert|
              body['certs'].each do |c|
                if c['id'] == path_cert
                  Yawast::Utilities.puts_info "\t\t\t#{c['subject']}"
                  Yawast::Utilities.puts_info "\t\t\t  Signature: #{c['sigAlg']}  Key: #{c['keyAlg']}-#{c['keySize']}"

                  if Yawast::Scanner::Plugins::SSL::SSL.check_symantec_root(c['sha256Hash'])
                    Yawast::Utilities.puts_vuln "\t\t\t  Untrusted Symantec Root"
                    Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                    'tls_symantec_root',
                                                    {vulnerable: true, :root_hash => c['sha256Hash']}
                  end

                  Yawast::Utilities.puts_info "\t\t\t  https://crt.sh/?q=#{c['sha1Hash']}"

                  unless chain['certIds'].find_index(c['sha256Hash']).nil?
                    Yawast::Utilities.puts_info "\t\t\t  (provided by server)"
                  end

                  puts
                end
              end
            end
          end
        end

        puts
      end

      def self.get_config_info(ep)
        puts "\tConfiguration Information:"

        puts "\t\tProtocol Support:"
        # setup JSON output
        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_legacy_ssl',
                                        {vulnerable: false}
        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_tls10_enabled',
                                        {vulnerable: false}
        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_tls13_not_enabled',
                                        {vulnerable: true}

        # check protocols
        protos = {}
        tls13_enabled = false
        ep['details']['protocols'].each do |proto|
          if proto['name'] == 'SSL'
            # show a vuln for SSLvX
            Yawast::Utilities.puts_vuln "\t\t\t#{proto['name']} #{proto['version']}"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_legacy_ssl',
                                            {vulnerable: true}
          elsif proto['name'] == 'TLS' &&  proto['version'] == '1.0'
            # show a warn for TLSv1.0
            Yawast::Utilities.puts_warn "\t\t\t#{proto['name']} #{proto['version']}"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_tls10_enabled',
                                            {vulnerable: true}
          elsif proto['name'] == 'TLS' &&  proto['version'] == '1.3'
            # capture TLS 1.3 status
            tls13_enabled = true
            Yawast::Utilities.puts_info "\t\t\t#{proto['name']} #{proto['version']}"
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_tls13_not_enabled',
                                            {vulnerable: false}
          else
            Yawast::Utilities.puts_info "\t\t\t#{proto['name']} #{proto['version']}"
          end

          protos[proto['id']] = "#{proto['name']} #{proto['version']}"
        end

        Yawast::Utilities.puts_warn "\t\t\tTLS 1.3 Is Not Enabled" unless tls13_enabled
        puts

        puts "\t\tNamed Group Support:"
        unless ep['details']['namedGroups'].nil?
          ep['details']['namedGroups']['list'].each do |group|
            Yawast::Utilities.puts_info "\t\t\t#{group['name']} #{group['bits']}"
          end
          puts
        end

        puts "\t\tCipher Suite Support:"
        # setup JSON output
        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_insecure_cipher_suites',
                                        {vulnerable: false}
        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_weak_cipher_suites',
                                        {vulnerable: false}
        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_3des_enabled',
                                        {vulnerable: false, suite: ''}
        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_rc4_enabled',
                                        {vulnerable: false, suite: ''}

        if !ep['details']['suites'].nil?
          ep['details']['suites'].each do |proto_suites|
            Yawast::Utilities.puts_info "\t\t\t#{protos[proto_suites['protocol']]}"

            proto_suites['list'].each do |suite|
              ke = get_key_exchange suite

              strength = suite['cipherStrength']
              if suite['name'].include? '3DES'
                # in this case, the effective strength is only 112 bits,
                #  which is what we want to report. So override SSL Labs
                strength = 112

                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'tls_3des_enabled',
                                                {vulnerable: true, suite: suite['name']}
              end

              if suite['name'].include? 'RC4'
                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'tls_rc4_enabled',
                                                {vulnerable: true, suite: suite['name']}
              end

              suite_info = if !ke.nil?
                             "#{suite['name'].ljust(50)} - #{strength}-bits - #{ke}"
                           else
                             "#{suite['name'].ljust(50)} - #{strength}-bits"
                           end

              if cipher_suite_secure? suite
                if strength >= 128
                  Yawast::Utilities.puts_info "\t\t\t  #{suite_info}"
                else
                  Yawast::Utilities.puts_warn "\t\t\t  #{suite_info}"

                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'tls_weak_cipher_suites',
                                                  {vulnerable: true}
                end
              else
                Yawast::Utilities.puts_vuln "\t\t\t  #{suite_info}"

                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'tls_insecure_cipher_suites',
                                                {vulnerable: true}
              end
            end
          end
        else
          Yawast::Utilities.puts_error "\t\t\t  Information Not Available"
        end

        puts

        puts "\t\tHandshake Simulation:"
        if !ep['details']['sims']['results'].nil?
          ep['details']['sims']['results'].each do |sim|
            name = "#{sim['client']['name']} #{sim['client']['version']}"
            name += " / #{sim['client']['platform']}" unless sim['client']['platform'].nil?
            name = name.ljust(28)

            if sim['errorCode'].zero?
              protocol = protos[sim['protocolId']]

              ke = get_key_exchange sim

              suite_name = "#{sim['suiteName']} - #{ke}"

              Yawast::Utilities.puts_info "\t\t\t#{name} - #{protocol} - #{suite_name}"
            else
              Yawast::Utilities.puts_warn"\t\t\t#{name} - Simulation Failed"
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

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_drown',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tDROWN: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_drown',
                                          {vulnerable: false}
        end

        unless ep['details']['zeroRTTEnabled'].nil?
          case ep['details']['zeroRTTEnabled']
            when -2
              Yawast::Utilities.puts_error "\t\t\tTLS 1.3 0-RTT Support: Test Failed"
            when -1
              Yawast::Utilities.puts_info "\t\t\tTLS 1.3 0-RTT Support: Test Not Performed"
            when 0
              Yawast::Utilities.puts_info "\t\t\tTLS 1.3 0-RTT Support: No"
            when 1
              Yawast::Utilities.puts_warn "\t\t\tTLS 1.3 0-RTT Support: Yes"
            else
              Yawast::Utilities.puts_error "\t\t\tTLS 1.3 0-RTT Support: Unknown Response #{ep['details']['zeroRTTEnabled']}"
          end
        end

        unless ep['details']['renegSupport'].nil?
          if ep['details']['renegSupport'] & 1 != 0
            Yawast::Utilities.puts_vuln "\t\t\tSecure Renegotiation: insecure client-initiated renegotiation supported"
          end
          if ep['details']['renegSupport'] & (1 << 1) != 0
            Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: secure renegotiation supported"
          end
          if ep['details']['renegSupport'] & (1 << 2) != 0
            Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: secure client-initiated renegotiation supported"
          end
          if ep['details']['renegSupport'] & (1 << 3) != 0
            Yawast::Utilities.puts_info "\t\t\tSecure Renegotiation: server requires secure renegotiation support"
          end
        end

        if ep['details']['poodle']
          Yawast::Utilities.puts_vuln "\t\t\tPOODLE (SSL): Vulnerable"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_poodle_ssl',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tPOODLE (SSL): No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_poodle_ssl',
                                          {vulnerable: false}
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_zombie_poodle',
                                        {vulnerable: false, exploitable: false}
        case ep['details']['zombiePoodle']
          when -1
            Yawast::Utilities.puts_error "\t\t\tZombie POODLE: Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tZombie POODLE: Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tZombie POODLE: No"
          when 2
            Yawast::Utilities.puts_warn "\t\t\tZombie POODLE: Vulnerable - Not Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_zombie_poodle',
                                            {vulnerable: true, exploitable: false}
          when 3
            Yawast::Utilities.puts_vuln "\t\t\tZombie POODLE: Vulnerable - Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_zombie_poodle',
                                            {vulnerable: true, exploitable: true}
          when nil
            # do nothing, this means they aren't sending the result
          else
            Yawast::Utilities.puts_error "\t\t\tZombie POODLE: Unknown Response #{ep['details']['zombiePoodle']}"
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_goldendoodle',
                                        {vulnerable: false, exploitable: false}
        case ep['details']['goldenDoodle']
          when -1
            Yawast::Utilities.puts_error "\t\t\tGOLDENDOODLE: Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tGOLDENDOODLE: Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tGOLDENDOODLE: No"
          when 4
            Yawast::Utilities.puts_warn "\t\t\tGOLDENDOODLE: Vulnerable - Not Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_goldendoodle',
                                            {vulnerable: true, exploitable: false}
          when 5
            Yawast::Utilities.puts_vuln "\t\t\tGOLDENDOODLE: Vulnerable - Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_goldendoodle',
                                            {vulnerable: true, exploitable: true}
          when nil
            # do nothing, this means they aren't sending the result
          else
            Yawast::Utilities.puts_error "\t\t\tGOLDENDOODLE: Unknown Response #{ep['details']['goldenDoodle']}"
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_openssl_cve_2019_1559',
                                        {vulnerable: false, exploitable: false}
        case ep['details']['zeroLengthPaddingOracle']
          when -1
            Yawast::Utilities.puts_error "\t\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): No"
          when 6
            Yawast::Utilities.puts_warn "\t\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Vulnerable - Not Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_openssl_cve_2019_1559',
                                            {vulnerable: true, exploitable: false}
          when 7
            Yawast::Utilities.puts_vuln "\t\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Vulnerable - Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_openssl_cve_2019_1559',
                                            {vulnerable: true, exploitable: true}
          when nil
            # do nothing, this means they aren't sending the result
          else
            Yawast::Utilities.puts_error "\t\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Unknown Response #{ep['details']['zeroLengthPaddingOracle']}"
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_goldendoodle',
                                        {vulnerable: false, exploitable: false}
        case ep['details']['sleepingPoodle']
          when -1
            Yawast::Utilities.puts_error "\t\t\tSleeping POODLE: Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tSleeping POODLE: Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tSleeping POODLE: No"
          when 10
            Yawast::Utilities.puts_warn "\t\t\tSleeping POODLE: Vulnerable - Not Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_sleeping_poodle',
                                            {vulnerable: true, exploitable: false}
          when 11
            Yawast::Utilities.puts_vuln "\t\t\tSleeping POODLE: Vulnerable - Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_sleeping_poodle',
                                            {vulnerable: true, exploitable: true}
          when nil
            # do nothing, this means they aren't sending the result
          else
            Yawast::Utilities.puts_error "\t\t\tSleeping POODLE: Unknown Response #{ep['details']['sleepingPoodle']}"
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_poodle',
                                        {vulnerable: false}
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

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_poodle',
                                            {vulnerable: true}
          when nil
          # do nothing, this means they aren't sending the result
          else
            Yawast::Utilities.puts_error "\t\t\tPOODLE (TLS): Unknown Response #{ep['details']['poodleTls']}"
        end

        if ep['details']['fallbackScsv']
          Yawast::Utilities.puts_info "\t\t\tDowngrade Prevention: Yes"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_missing_fallback_scsv',
                                          {vulnerable: false}
        else
          Yawast::Utilities.puts_warn "\t\t\tDowngrade Prevention: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_missing_fallback_scsv',
                                          {vulnerable: true}
        end

        if ep['details']['compressionMethods'] & 1 != 0
          Yawast::Utilities.puts_warn "\t\t\tCompression: DEFLATE"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_compression_enabled',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tCompression: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_compression_enabled',
                                          {vulnerable: false}
        end

        if ep['details']['heartbeat']
          Yawast::Utilities.puts_warn "\t\t\tHeartbeat: Enabled"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_heartbeat_enabled',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tHeartbeat: Disabled"
          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_heartbeat_enabled',
                                          {vulnerable: false}
        end

        if ep['details']['heartbleed']
          Yawast::Utilities.puts_vuln "\t\t\tHeartbleed: Vulnerable"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_heartblead',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tHeartbleed: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_heartblead',
                                          {vulnerable: false}
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_ticketbleed',
                                        {vulnerable: false}
        case ep['details']['ticketbleed']
          when -1
            Yawast::Utilities.puts_error "\t\t\tTicketbleed (CVE-2016-9244): Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tTicketbleed (CVE-2016-9244): Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tTicketbleed (CVE-2016-9244): No"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tTicketbleed (CVE-2016-9244): Vulnerable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_ticketbleed',
                                            {vulnerable: true}
          else
            Yawast::Utilities.puts_error "\t\t\tTicketbleed (CVE-2016-9244): Unknown Response #{ep['details']['ticketbleed']}"
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_openssl_ccs_cve20140224',
                                        {vulnerable: false, exploitable: false}
        case ep['details']['openSslCcs']
          when -1
            Yawast::Utilities.puts_error "\t\t\tOpenSSL CCS (CVE-2014-0224): Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tOpenSSL CCS (CVE-2014-0224): Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tOpenSSL CCS (CVE-2014-0224): No"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tOpenSSL CCS (CVE-2014-0224): Vulnerable - Not Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_openssl_ccs_cve20140224',
                                            {vulnerable: true, exploitable: false}
          when 3
            Yawast::Utilities.puts_vuln "\t\t\tOpenSSL CCS (CVE-2014-0224): Vulnerable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_openssl_ccs_cve20140224',
                                            {vulnerable: true, exploitable: true}
          else
            Yawast::Utilities.puts_error "\t\t\tOpenSSL CCS (CVE-2014-0224): Unknown Response #{ep['details']['openSslCcs']}"
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_openssl_lunckyminus20',
                                        {vulnerable: false}

        case ep['details']['openSSLLuckyMinus20']
          when -1
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): No"
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Vulnerable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_openssl_lunckyminus20',
                                            {vulnerable: true}
          else
            Yawast::Utilities.puts_error "\t\t\tOpenSSL Padding Oracle (CVE-2016-2107): Unknown Response #{ep['details']['openSSLLuckyMinus20']}"
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_robot',
                                        {vulnerable: false, exploitable: false}
        case ep['details']['bleichenbacher']
          when -1
            Yawast::Utilities.puts_error "\t\t\tROBOT: Test Failed"
          when 0
            Yawast::Utilities.puts_error "\t\t\tROBOT: Test Failed (Unknown)"
          when 1
            Yawast::Utilities.puts_info "\t\t\tROBOT: No"
          when 2
            Yawast::Utilities.puts_warn "\t\t\tROBOT: Not Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_robot',
                                            {vulnerable: true, exploitable: false}
          when 3
            Yawast::Utilities.puts_vuln "\t\t\tROBOT: Exploitable"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_robot',
                                            {vulnerable: true, exploitable: true}
          when nil
            # if it's null, we don't care
          else
            Yawast::Utilities.puts_error "\t\t\tROBOT: Unknown Response #{ep['details']['bleichenbacher']}"
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_missing_forward_secrecy',
                                        {vulnerable: false}

        if ep['details']['forwardSecrecy'] & (1 << 2) != 0
          Yawast::Utilities.puts_info "\t\t\tForward Secrecy: Yes (all simulated clients)"
        elsif ep['details']['forwardSecrecy'] & (1 << 1) != 0
          Yawast::Utilities.puts_info "\t\t\tForward Secrecy: Yes (modern clients)"
        elsif ep['details']['forwardSecrecy'] & 1 != 0
          Yawast::Utilities.puts_warn "\t\t\tForward Secrecy: Yes (limited support)"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_missing_forward_secrecy',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_vuln "\t\t\tForward Secrecy: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_missing_forward_secrecy',
                                          {vulnerable: true}
        end

        if ep['details']['supportsAead']
          Yawast::Utilities.puts_info "\t\t\tAEAD Cipher Suites Supported: Yes"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_aead_support_missing',
                                          {vulnerable: false}
        else
          Yawast::Utilities.puts_warn "\t\t\tAEAD Cipher Suites Supported: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_aead_support_missing',
                                          {vulnerable: true}
        end

        if ep['details']['supportsCBC']
          Yawast::Utilities.puts_warn "\t\t\tCBC Cipher Suites Supported: Yes"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_cbc_support',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tCBC Cipher Suites Supported: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_cbc_support',
                                          {vulnerable: false}
        end

        Yawast::Utilities.puts_info "\t\t\tALPN: #{ep['details']['alpnProtocols']}"

        Yawast::Utilities.puts_info "\t\t\tNPN: #{ep['details']['npnProtocols']}"

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_session_resumption',
                                        {vulnerable: false}

        case ep['details']['sessionResumption']
          when 0
            Yawast::Utilities.puts_info "\t\t\tSession Resumption: Not Enabled / Empty Tickets"
          when 1
            Yawast::Utilities.puts_info "\t\t\tSession Resumption: Enabled / No Resumption"
          when 2
            Yawast::Utilities.puts_warn "\t\t\tSession Resumption: Enabled"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_session_resumption',
                                            {vulnerable: true}
          else
            Yawast::Utilities.puts_error "\t\t\tSession Resumption: Unknown Response #{ep['details']['sessionResumption']}"
        end

        if ep['details']['ocspStapling']
          Yawast::Utilities.puts_info "\t\t\tOCSP Stapling: Yes"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_ocsp_stapling_missing',
                                          {vulnerable: false}
        else
          Yawast::Utilities.puts_warn "\t\t\tOCSP Stapling: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_ocsp_stapling_missing',
                                          {vulnerable: true}
        end

        if ep['details']['miscIntolerance'].positive?
          if ep['details']['miscIntolerance'] & 1 != 0
            Yawast::Utilities.puts_warn "\t\t\tTLS Extension Intolerance: Yes"
          end

          if ep['details']['miscIntolerance'] & (1 << 1) != 0
            Yawast::Utilities.puts_warn "\t\t\tLong Handshake Intolerance: Yes"
          end

          if ep['details']['miscIntolerance'] & (1 << 2) != 0
            Yawast::Utilities.puts_warn "\t\t\tLong Handshake Intolerance: Workaround Success"
          end
        end

        if ep['details']['protocolIntolerance'].positive?
          if ep['details']['protocolIntolerance'] & 1 != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.0"
          end

          if ep['details']['protocolIntolerance'] & (1 << 1) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.1"
          end

          if ep['details']['protocolIntolerance'] & (1 << 2) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.2"
          end

          if ep['details']['protocolIntolerance'] & (1 << 3) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.3"
          end

          if ep['details']['protocolIntolerance'] & (1 << 4) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 1.152"
          end

          if ep['details']['protocolIntolerance'] & (1 << 5) != 0
            Yawast::Utilities.puts_warn "\t\t\tProtocol Intolerance: TLS 2.152"
          end
        else
          Yawast::Utilities.puts_info "\t\t\tProtocol Intolerance: No"
        end

        if ep['details']['freak']
          Yawast::Utilities.puts_vuln "\t\t\tFREAK: Vulnerable (512-bit key exchange supported)"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_freak',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tFREAK: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_freak',
                                          {vulnerable: false}
        end

        if ep['details']['logjam']
          Yawast::Utilities.puts_vuln "\t\t\tLogjam: Vulnerable (DH key exchange with keys smaller than 1024 bits)"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_logjam',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tLogjam: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_logjam',
                                          {vulnerable: false}
        end

        Yawast::Shared::Output.log_hash 'vulnerabilities',
                                        'tls_dh_known_primes',
                                        {vulnerable: false, weak: false}

        case ep['details']['dhUsesKnownPrimes']
          when 0
            Yawast::Utilities.puts_info "\t\t\tUses common DH primes: No"
          when 1
            Yawast::Utilities.puts_warn "\t\t\tUses common DH primes: Yes (not weak)"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_dh_known_primes',
                                            {vulnerable: true, weak: false}
          when 2
            Yawast::Utilities.puts_vuln "\t\t\tUses common DH primes: Yes (weak)"

            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'tls_dh_known_primes',
                                            {vulnerable: true, weak: true}
          else
            unless ep['details']['dhUsesKnownPrimes'].nil?
              Yawast::Utilities.puts_error "\t\t\tUses common DH primes: Unknown Response #{ep['details']['dhUsesKnownPrimes']}"
            end
        end

        if ep['details']['dhYsReuse']
          Yawast::Utilities.puts_vuln "\t\t\tDH public server param (Ys) reuse: Yes"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_dh_public_server_param_reuse',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tDH public server param (Ys) reuse: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_dh_public_server_param_reuse',
                                          {vulnerable: false}
        end

        if ep['details']['ecdhParameterReuse']
          Yawast::Utilities.puts_vuln "\t\t\tECDH Public Server Param Reuse: Yes"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_ecdh_public_server_param_reuse',
                                          {vulnerable: true}
        else
          Yawast::Utilities.puts_info "\t\t\tECDH Public Server Param Reuse: No"

          Yawast::Shared::Output.log_hash 'vulnerabilities',
                                          'tls_ecdh_public_server_param_reuse',
                                          {vulnerable: false}
        end

        puts
      end

      def self.cipher_suite_secure?(suite)
        secure = true

        # check for weak DH
        secure = false if !suite['kxStrength'].nil? && suite['kxStrength'] < 2048
        # check for RC4
        secure = false if suite['name'].include? 'RC4'
        # check for weak suites
        secure = false if suite['cipherStrength'] < 112

        secure
      end

      def self.get_key_exchange(suite)
        ke = nil
        unless suite['kxType'].nil?
          ke = if !suite['namedGroupBits'].nil?
                 "#{suite['kxType']}-#{suite['namedGroupBits']} / #{suite['namedGroupName']} (#{suite['kxStrength']} equivalent)"
               else
                 "#{suite['kxType']}-#{suite['kxStrength']}"
               end
        end

        ke
      end
    end
  end
end
