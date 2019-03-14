# frozen_string_literal: true

require 'base64'
require 'securerandom'

module Yawast
  module Scanner
    module Plugins
      module Servers
        class Apache
          def self.check_banner(banner)
            # don't bother if this doesn't look like Apache
            return unless banner.include? 'Apache'
            @apache = true

            modules = banner.split(' ')
            server = modules[0]

            # fix '(distro)' issue, such as with 'Apache/2.2.22 (Ubuntu)'
            # if we don't do this, it triggers a false positive on the module check
            if /\(\w*\)/.match? modules[1]
              server += " #{modules[1]}"
              modules.delete_at 1
            end

            # print the server info no matter what we do next
            Yawast::Utilities.puts_info "Apache Server: #{server}"
            modules.delete_at 0

            if modules.count.positive?
              Yawast::Utilities.puts_warn 'Apache Server: Module listing enabled'
              modules.each { |mod| Yawast::Utilities.puts_warn "\t\t#{mod}" }
              puts ''

              # check for special items
              modules.each do |mod|
                if mod.include? 'OpenSSL'
                  Yawast::Utilities.puts_warn "OpenSSL Version Disclosure: #{mod}"
                  puts ''
                end
              end
            end
          end

          def self.check_all(uri)
            # run all the defined checks
            check_server_status(uri.copy)
            check_server_info(uri.copy)
            check_tomcat_manager(uri.copy)
            check_tomcat_version(uri.copy)
            check_tomcat_put_rce(uri.copy)
            check_struts2_samples(uri.copy)
          end

          def self.check_server_status(uri)
            check_page_for_string uri, '/server-status', 'Apache Server Status'
          end

          def self.check_server_info(uri)
            check_page_for_string uri, '/server-info', 'Apache Server Information'
          end

          def self.check_tomcat_version(uri)
            begin
              req = Yawast::Shared::Http.get_http(uri)
              req.use_ssl = uri.scheme == 'https'
              headers = Yawast::Shared::Http.get_headers
              res = req.request(Xyz.new('/', headers))

              if !res.body.nil? && res.body.include?('Apache Tomcat') && res.code == '501'
                # check to see if there's a version number
                version = /Apache Tomcat\/\d*.\d*.\d*\b/.match res.body

                if !version.nil? && !version[0].nil?
                  Yawast::Utilities.puts_warn "Apache Tomcat Version Found: #{version[0]}"
                  Yawast::Shared::Output.log_value 'apache', 'tomcat_version', version[0]

                  puts "\t\t\"curl -X XYZ #{uri}\""

                  puts ''
                end
              end
            end
          end

          def self.check_tomcat_manager(uri)
            check_tomcat_manager_paths uri.copy, 'manager', 'Manager'
            check_tomcat_manager_paths uri.copy, 'host-manager', 'Host Manager'
          end

          def self.check_tomcat_manager_paths(uri, base_path, manager)
            uri.path = "/#{base_path}/html"
            uri.query = '' unless uri.query.nil?

            ret = Yawast::Shared::Http.get(uri)

            if ret.include? '<tt>conf/tomcat-users.xml</tt>'
              # this will get Tomcat 7+
              Yawast::Utilities.puts_warn "Apache Tomcat #{manager} page found: #{uri}"
              Yawast::Shared::Output.log_value 'apache', 'tomcat_mgr', manager, uri
              check_tomcat_manager_passwords uri, manager

              puts ''
            else
              # check for Tomcat 6 and below
              uri = uri.copy
              uri.path = "/#{base_path}"
              ret = Yawast::Shared::Http.get(uri)

              if ret.include? '<tt>conf/tomcat-users.xml</tt>'
                Yawast::Utilities.puts_warn "Apache Tomcat #{manager} page found: #{uri}"
                Yawast::Shared::Output.log_value 'apache', 'tomcat_mgr', manager, uri
                check_tomcat_manager_passwords uri, manager

                puts ''
              end
            end
          end

          def self.check_tomcat_manager_passwords(uri, manager)
            # check for known passwords
            check_tomcat_manager_pwd_check uri, manager, 'tomcat:tomcat'
            check_tomcat_manager_pwd_check uri, manager, 'tomcat:password'
            check_tomcat_manager_pwd_check uri, manager, 'tomcat:'
            check_tomcat_manager_pwd_check uri, manager, 'admin:admin'
            check_tomcat_manager_pwd_check uri, manager, 'admin:password'
            check_tomcat_manager_pwd_check uri, manager, 'admin:'
          end

          def self.check_tomcat_manager_pwd_check(uri, manager, credentials)
            ret = Yawast::Shared::Http.get(uri, {'Authorization' => "Basic #{Base64.encode64(credentials)}"})
            if ret.include?('<font size="+2">Tomcat Web Application Manager</font>') ||
               ret.include?('<font size="+2">Tomcat Virtual Host Manager</font>')
              Yawast::Utilities.puts_vuln "Apache Tomcat #{manager} weak password: #{credentials}"

              Yawast::Shared::Output.log_value 'apache', 'tomcat_mgr_pwd', uri, credentials
            end
          end

          def self.check_tomcat_put_rce(uri)
            # CVE-2017-12615
            uri.path = "/#{SecureRandom.hex}.jsp/"
            uri.query = '' unless uri.query.nil?

            Yawast::Shared::Output.log_value 'apache', 'cve_2017_12615', 'path', uri

            # we'll use this to verify that it actually worked
            check_value = SecureRandom.hex

            Yawast::Shared::Output.log_value 'apache', 'cve_2017_12615', 'check_value', check_value

            # upload the JSP file
            req_data = "<% out.println(\"#{check_value}\");%>"
            Yawast::Shared::Http.put(uri, req_data)

            # check to see of we get check_value back
            uri.path = uri.path.chomp('/')
            res = Yawast::Shared::Http.get(uri)

            Yawast::Shared::Output.log_value 'apache', 'cve_2017_12615', 'body', res

            if res.include? check_value
              Yawast::Utilities.puts_vuln "Apache Tomcat PUT RCE (CVE-2017-12615): #{uri}"
              Yawast::Shared::Output.log_value 'apache', 'cve_2017_12615', 'vulnerable', true
            else
              Yawast::Shared::Output.log_value 'apache', 'cve_2017_12615', 'vulnerable', false
            end
          end

          def self.check_struts2_samples(uri)
            search = []
            search.push '/Struts2XMLHelloWorld/User/home.action'
            search.push '/struts2-showcase/showcase.action'
            search.push '/struts2-showcase/titles/index.action'
            search.push '/struts2-bootstrap-showcase/'
            search.push '/struts2-showcase/index.action'
            search.push '/struts2-bootstrap-showcase/index.action'
            search.push '/struts2-rest-showcase/'

            search.each do |path|
              uri = uri.copy
              uri.path = path

              ret = Yawast::Shared::Http.get_status_code uri
              Yawast::Shared::Output.log_value 'apache', 'struts2_sample_files', uri, ret

              Yawast::Utilities.puts_warn "Apache Struts2 Sample Files: #{uri}" if ret == 200
            end
          end

          def self.check_page_for_string(uri, path, search)
            uri.path = path
            uri.query = '' unless uri.query.nil?

            ret = Yawast::Shared::Http.get(uri)

            if ret.include? search
              Yawast::Utilities.puts_vuln "#{search} page found: #{uri}"
              Yawast::Shared::Output.log_value 'apache', 'page_search', search, uri
              puts ''
            end
          end
        end

        # Custom class to allow using the XYZ verb
        class Xyz < Net::HTTPRequest
          METHOD = 'XYZ'
          REQUEST_HAS_BODY = false
          RESPONSE_HAS_BODY = true
        end
      end
    end
  end
end
