module Yawast
  module Commands
    class Scan
      def self.process(args, options)
        uri = Yawast::Commands::Utils.extract_uri(args)

        Yawast::Scanner::Core.process(uri, options)
      end
    end
  end
end
