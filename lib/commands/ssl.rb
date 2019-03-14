# frozen_string_literal: true

module Yawast
  module Commands
    class Ssl
      def self.process(args, options)
        uri = Yawast::Commands::Utils.extract_uri(args)

        Yawast::Scanner::Core.check_ssl(uri, options, nil)
      end
    end
  end
end
