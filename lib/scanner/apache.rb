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
        #run all the defined checks
        check_server_status(uri.copy)
        check_server_info(uri.copy)
        check_tomcat_manager(uri.copy)
      end

      def self.check_server_status(uri)
        check_page_for_string uri, '/server-status', 'Apache Server Status'
      end

      def self.check_server_info(uri)
        check_page_for_string uri, '/server-info', 'Apache Server Information'
      end

      def self.check_tomcat_manager(uri)
        uri.path = '/manager/html'
        uri.query = '' if uri.query != nil

        ret = Yawast::Shared::Http.get(uri)

        if ret.include? '<tt>conf/tomcat-users.xml</tt>'
          #this will get Tomcat 7+
          Yawast::Utilities.puts_warn "Apache Tomcat Manager page found: #{uri}"
          check_tomcat_manager_passwords uri

          puts ''
        else
          #check for Tomcat 6 and below
          uri.path = '/manager'
          ret = Yawast::Shared::Http.get(uri)

          if ret.include? '<tt>conf/tomcat-users.xml</tt>'
            Yawast::Utilities.puts_warn "Apache Tomcat Manager page found: #{uri}"
            check_tomcat_manager_passwords uri

            puts ''
          end
        end
      end

      def self.check_tomcat_manager_passwords(uri)
        #check for known passwords
        ret = Yawast::Shared::Http.get(uri, {'Authorization' => 'Basic dG9tY2F0OnRvbWNhdA=='}) #tomcat:tomcat
        if ret.include? '<font size="+2">Tomcat Web Application Manager</font>'
          Yawast::Utilities.puts_vuln 'Apache Tomcat Manager weak password: tomcat:tomcat'
        end
        ret = Yawast::Shared::Http.get(uri, {'Authorization' => 'Basic YWRtaW46YWRtaW4='}) #admin:admin
        if ret.include? '<font size="+2">Tomcat Web Application Manager</font>'
          Yawast::Utilities.puts_vuln 'Apache Tomcat Manager weak password: admin:admin'
        end
        ret = Yawast::Shared::Http.get(uri, {'Authorization' => 'Basic YWRtaW46'}) #admin:(blank)
        if ret.include? '<font size="+2">Tomcat Web Application Manager</font>'
          Yawast::Utilities.puts_vuln 'Apache Tomcat Manager weak password: admin:(blank)'
        end
      end

      def self.check_page_for_string(uri, path, search)
        uri.path = path
        uri.query = '' if uri.query != nil

        ret = Yawast::Shared::Http.get(uri)

        if ret.include? search
          Yawast::Utilities.puts_vuln "#{search} page found: #{uri}"
          puts ''
        end
      end
    end
  end
end
