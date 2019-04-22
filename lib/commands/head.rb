# frozen_string_literal: true

module Yawast
  module Commands
    class Head
      def self.process(args, options)
        args.each do |arg|
          uri = Yawast::Commands::Utils.extract_uri([arg])

          options.head = true
          Yawast::Scanner::Core.process(uri, options)
        end
      end
    end
  end
end
