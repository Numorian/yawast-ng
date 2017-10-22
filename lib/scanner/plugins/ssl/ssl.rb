module Yawast
  module Scanner
    module Plugins
      module SSL
        class SSL
          def self.print_precert(cert)
            scts = cert.extensions.find {|e| e.oid == 'ct_precert_scts'}

            unless scts.nil?
              Yawast::Utilities.puts_info "\t\tSCTs:"
              scts.value.split("\n").each { |line| puts "\t\t\t#{line}" }
            end
          end

          def self.print_cert_hash(cert)
            hash = Digest::SHA1.hexdigest(cert.to_der)
            Yawast::Utilities.puts_info "\t\tHash: #{hash}"
            puts "\t\t\thttps://censys.io/certificates?q=#{hash}"
            puts "\t\t\thttps://crt.sh/?q=#{hash}"
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
          end

          def self.check_hsts_preload(uri)
            begin
              info = JSON.parse(Net::HTTP.get(URI("https://hstspreload.com/api/v1/status/#{uri.host}")))

              chrome = info['chrome'] != nil
              firefox = info['firefox'] != nil
              tor = info['tor'] != nil

              Yawast::Utilities.puts_info "HSTS Preload: Chrome - #{chrome}; Firefox - #{firefox}; Tor - #{tor}"
            rescue => e
              Yawast::Utilities.puts_error "Error getting HSTS preload information: #{e.message}"
            end
          end
        end
      end
    end
  end
end
