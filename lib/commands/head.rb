module Yawast
  module Commands
    class Head
      def self.process(args, options)
        uri = Yawast::Commands::Utils.ExtractUri(args)

        options.head = true
        Yawast::Scanner::Core.process(uri, options)
      end
    end
  end
end
