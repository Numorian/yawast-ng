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
        end
      end
    end
  end
end
