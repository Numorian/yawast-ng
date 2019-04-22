# frozen_string_literal: true

module Yawast
  module Commands
    class Cms
      def self.process(args, options)
        args.each do |arg|
          uri = Yawast::Commands::Utils.extract_uri([arg])

          Yawast::Scanner::Core.get_cms(uri, options)
        end
      end
    end
  end
end
