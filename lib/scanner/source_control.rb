module Yawast
  module Scanner
    class SourceControl
      def self.check_all(uri)
        check_path(uri, '.git')
        check_path(uri, '.hg')
        check_path(uri, '.svn')
        check_path(uri, '.bzr')
      end

      def self.check_path(uri, path)
        #note: this only checks directly at the root, I'm not sure if this is what we want
        # should probably be relative to what's passed in, instead of overriding the path.
        uri.path = "/#{path}/"
        code = Yawast::Shared::Http.get_status_code(uri)

        if code == 200
          Yawast::Utilities.puts_vuln "'#{path}' Source Control Directory found: #{uri}"
          puts ''
        end
      end
    end
  end
end
