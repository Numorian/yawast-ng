module Yawast
  module Commands
    class DNS
      def self.process(args, options)
        uri = Yawast::Commands::Utils.extract_uri(args)

        Yawast.header

        if options.output != nil
          Yawast::Shared::Output.setup uri, options
        end

        puts "Scanning: #{uri}"
        puts

        Yawast::Scanner::Plugins::DNS::Generic.dns_info uri, options
        Yawast::Shared::Output.write_file
      end
    end
  end
end
