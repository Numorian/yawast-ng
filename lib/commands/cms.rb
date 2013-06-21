module Yawast
  module Commands
    class Cms
      def self.process(args, options)
        uri = Yawast::Commands::Utils.extract_uri(args)
        Yawast::Scanner::Core.get_cms(uri, options)
      end
    end
  end
end
