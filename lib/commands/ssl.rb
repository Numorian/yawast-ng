# frozen_string_literal: true

module Yawast
  module Commands
    class Ssl
      def self.process(args, options)
        args.each do |arg|
          uri = Yawast::Commands::Utils.extract_uri([arg])

          Yawast::Scanner::Core.check_ssl(uri, options, nil)
        end
      end
    end
  end
end
