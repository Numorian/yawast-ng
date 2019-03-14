# frozen_string_literal: true

module Yawast
  module Commands
    class DNS
      def self.process(args, options)
        uri = Yawast::Commands::Utils.extract_uri(args)

        Yawast.header

        Yawast::Shared::Output.setup uri, options unless options.output.nil?

        puts "Scanning: #{uri}"
        puts

        Yawast::Scanner::Plugins::DNS::Generic.dns_info uri, options
        Yawast::Shared::Output.write_file
      end
    end
  end
end
