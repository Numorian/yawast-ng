require 'ssllabs'

module Yawast
  module Scanner
    class SslLabs
      def self.info(uri)
        puts 'Beginning SSL Labs scan (this could take a minute)'

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
            Yawast::Utilities.puts_info "IP: #{ep.ip_address}"
            Yawast::Utilities.puts_info "\tGrade#{ep.grade}"
            puts
          end

        rescue => e
          Yawast::Utilities.puts_error "SSL Labs Error: #{e.message}"
        end
      end
    end
  end
end
