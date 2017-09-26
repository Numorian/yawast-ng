module Yawast
  module Commands
    class DNS
      def self.process(args, options)
        uri = Yawast::Commands::Utils.extract_uri(args)

        Yawast.header

        puts "Scanning: #{@uri}"
        puts

        Yawast::Scanner::Plugins::DNS::Generic.dns_info uri, options
      end
    end
  end
end
