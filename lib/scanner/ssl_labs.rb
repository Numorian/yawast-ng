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

              if ep.details.cert.issues & 1
                Yawast::Utilities.puts_vuln "\t\tCertificate Issue: no chain of trust"
              end

              if ep.details.cert.issues & (1<<1)
                Yawast::Utilities.puts_vuln "\t\tCertificate Issue: certificate not yet valid"
              end

              if ep.details.cert.issues & (1<<2)
                Yawast::Utilities.puts_vuln "\t\tCertificate Issue: certificate expired"
              end

              if ep.details.cert.issues & (1<<3)
                Yawast::Utilities.puts_vuln "\t\tCertificate Issue: hostname mismatch"
              end

              if ep.details.cert.issues & (1<<4)
                Yawast::Utilities.puts_vuln "\t\tCertificate Issue: revoked"
              end

              if ep.details.cert.issues & (1<<5)
                Yawast::Utilities.puts_vuln "\t\tCertificate Issue: bad common name"
              end

              if ep.details.cert.issues & (1<<6)
                Yawast::Utilities.puts_vuln "\t\tCertificate Issue: self-signed"
              end

              if ep.details.cert.issues & (1<<7)
                Yawast::Utilities.puts_vuln "\t\tCertificate Issue: blacklisted"
              end

              if ep.details.cert.issues & (1<<8)
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
              if ep.details.has_sct & 1
                Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in certificate"
              end

              # check second bit, SCT in stapled OSCP response
              if ep.details.has_sct & (1<<1)
                Yawast::Utilities.puts_info "\t\tCertificate Transparency: SCT in the stapled OCSP response"
              end

              # check third bit, SCT in the TLS extension
              if ep.details.has_sct & (1<<2)
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
                Yawast::Utilities.puts_error "\t\tOCSP Must Staple: Unknown Response"
            end

            if ep.details.cert.revocation_info & 1
              Yawast::Utilities.puts_info "\t\tRevocation information: CRL information available"
            end
            if ep.details.cert.revocation_info & (1<<1)
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
                Yawast::Utilities.puts_error "\t\tRevocation status: Unknown response"
            end

            puts
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
            ep.details.suites.list.each do |suite|
              if suite.secure?
                Yawast::Utilities.puts_info "\t\t\t#{suite.name} - #{suite.cipher_strength}"
              else
                Yawast::Utilities.puts_vuln "\t\t\t#{suite.name} - #{suite.cipher_strength}"
              end
            end
            puts

            puts "\t\tHandshake Simulation:"
            ep.details.sims.results.each do |sim|
              name = "#{sim.client.name} #{sim.client.version}"
              if sim.client.platform != nil
                name += " / #{sim.client.platform}"
              end

              if sim.success?
                protocol = nil
                ep.details.protocols.each do |proto|
                  if sim.protocol_id == proto.id
                    protocol = "#{proto.name} #{proto.version}"
                  end
                end

                suite_name = nil
                ep.details.suites.list.each do |suite|
                  if sim.suite_id == suite.id
                    suite_name = suite.name
                  end
                end

                Yawast::Utilities.puts_info "\t\t\t#{name} - #{protocol} - #{suite_name}"
              else
                Yawast::Utilities.puts_error "\t\t\t#{name} - Simulation Failed"
              end
            end

            puts
          end

        rescue => e
          Yawast::Utilities.puts_error "SSL Labs Error: #{e.message}"
        end
      end
    end
  end
end
