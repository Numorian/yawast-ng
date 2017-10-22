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
        end
      end
    end
  end
end
