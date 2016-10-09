module Yawast
  module Scanner
    class Apache
      def self.check_banner(banner)
        #don't bother if this doesn't look like Apache
        return unless banner.include? 'Apache'
        @apache = true

        modules = banner.split(' ')
        server = modules[0]

        #fix '(distro)' issue, such as with 'Apache/2.2.22 (Ubuntu)'
        # if we don't do this, it triggers a false positive on the module check
        if /\(\w*\)/.match modules[1]
          server += " #{modules[1]}"
          modules.delete_at 1
        end

        #print the server info no matter what we do next
        Yawast::Utilities.puts_info "Apache Server: #{server}"
        modules.delete_at 0

        if modules.count > 0
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

      def self.check_all(uri)
        #this check for @apache may yield false negatives.. meh.
        if @apache
          #run all the defined checks
          check_server_status(uri.copy)
          check_server_info(uri.copy)
        end
      end

      def self.check_server_status(uri)
        uri.path = '/server-status'
        uri.query = '' if uri.query != nil

        ret = Yawast::Shared::Http.get(uri)

        if ret.include? 'Apache Server Status'
          Yawast::Utilities.puts_vuln "Apache Server Status page found: #{uri}"
          puts ''
        end
      end

      def self.check_server_info(uri)
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
