module Yawast
  module Commands
    class Scan
      def self.process(args, options)
        uri = Yawast::Commands::Utils.ExtractUri(args)

        Yawast::Scanner::Core.process(uri, options)
      end
    end
  end
end
