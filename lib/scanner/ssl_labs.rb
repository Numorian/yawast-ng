require 'ssllabs'

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
              Yawast::Utilities.puts_vuln "\t\tCertificate Not Valid"
            end

            Yawast::Utilities.puts_info "\t\tSubject: #{ep.details.cert.subject}"
            Yawast::Utilities.puts_info "\t\tCommon Names: #{ep.details.cert.common_names}"

            Yawast::Utilities.puts_info "\t\tAlternative names:"
            ep.details.cert.alt_names.each do |name|
              Yawast::Utilities.puts_info "\t\t\t#{name}"
            end

            Yawast::Utilities.puts_info "\t\tNot Before: #{ep.details.cert.not_before}"
            Yawast::Utilities.puts_info "\t\tNot After: #{ep.details.cert.not_after}"

            Yawast::Utilities.puts_info "\t\tKey: #{cert.key_alg} #{cert.key_size}"

            puts
          end

        rescue => e
          Yawast::Utilities.puts_error "SSL Labs Error: #{e.message}"
        end
      end
    end
  end
end
