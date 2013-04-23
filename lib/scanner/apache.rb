module Yawast
  module Scanner
    class Apache
      def self.check_banner(banner)
        #don't bother if this doesn't look like Apache
        return if !banner.include? 'Apache'
        @apache = true

        modules = banner.split(' ')

        if modules.count == 1
          #if there's only one item, it's just the server, no modules
          Yawast::Utilities.puts_info "Apache Server: #{banner}"
        else
          Yawast::Utilities.puts_warn 'Apache Server: Module listing enabled'
          modules.each { |mod| Yawast::Utilities.puts_warn "\t\t#{mod}" }
          puts ''

          #check for special items
          modules.each do |mod|
            if mod.include? 'OpenSSL'
              Yawast::Utilities.puts_warn "OpenSSL Version Disclosure: #{mod}"
              puts ''
            end
          end
        end
      end

      def self.check_all(uri, head)
        #run all the defined checks
        check_server_status(uri)
        check_server_info(uri)
      end

      def self.check_server_status(uri)
        #this may yield false negatives.. meh.
        return if !@apache

        uri.path = '/server-status'
        uri.query = '' if uri.query != nil

        ret = Yawast::Shared::Http.get(uri)

        if ret.include? 'Apache Server Status'
          Yawast::Utilities.puts_vuln "Apache Server Status page found: #{uri}"
          puts ''
        end
      end

      def self.check_server_info(uri)
        #this may yield false negatives.. meh.
        return if !@apache

        uri.path = '/server-info'
        uri.query = '' if uri.query != nil

        ret = Yawast::Shared::Http.get(uri)

        if ret.include? 'Apache Server Information'
          Yawast::Utilities.puts_vuln "Apache Server Info page found: #{uri}"
          puts ''
        end
      end
    end
  end
end
