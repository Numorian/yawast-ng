module Yawast
  module Commands
    class Cert
      def self.process(options)
        scan = Yawast::Scanner::Cert.new
        scan.get_certs(options)
      end
    end
  end
end
