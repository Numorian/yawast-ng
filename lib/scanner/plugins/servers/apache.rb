# frozen_string_literal: true

require 'base64'
require 'securerandom'

module Yawast
  module Scanner
    module Plugins
      module Servers
        class Apache
          def self.check_banner(banner)
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_openssl_version_exposed',
                                            {vulnerable: false, version: nil}
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_httpd_version_exposed',
                                            {vulnerable: false, version: nil}
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_httpd_modules_exposed',
                                            {vulnerable: false, modules: nil}

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
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_httpd_version_exposed',
                                            {vulnerable: true, version: server}

            if modules.count.positive?
              Yawast::Utilities.puts_warn 'Apache Server: Module listing enabled'
              modules.each { |mod| Yawast::Utilities.puts_warn "\t\t#{mod}" }
              puts ''
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'apache_httpd_modules_exposed',
                                              {vulnerable: true, modules: banner}

              # check for special items
              modules.each do |mod|
                if mod.include? 'OpenSSL'
                  Yawast::Utilities.puts_warn "OpenSSL Version Disclosure: #{mod}"
                  puts ''

                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'apache_openssl_version_exposed',
                                                  {vulnerable: true, version: mod}
                end
              end
            end
          end

          def self.check_all(uri, links = nil)
            # run all the defined checks
            check_server_status(uri.copy)
            check_server_info(uri.copy)
            check_tomcat_manager(uri.copy)
            check_tomcat_version(uri.copy)
            check_tomcat_put_rce(uri.copy)
            check_struts2_samples(uri.copy)

            unless links.nil?
              check_cve_2019_0232(links)
            end
          end

          def self.check_server_status(uri)
            check_page_for_string uri, '/server-status', 'Apache Server Status'
          end

          def self.check_server_info(uri)
            check_page_for_string uri, '/server-info', 'Apache Server Information'
          end

          def self.check_tomcat_version(uri)
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_tomcat_version_exposed',
                                            {vulnerable: false, version: nil, body: nil}

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
                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'apache_tomcat_version_exposed',
                                                  {vulnerable: true, version: version[0], body: res.body}

                  puts "\t\t\"curl -X XYZ #{uri}\""

                  puts ''
                else
                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'apache_tomcat_version_exposed',
                                                  {vulnerable: false, version: nil, body: res.body}
                end
              end
            end
          end

          def self.check_tomcat_manager(uri)
            check_tomcat_manager_paths uri.copy, 'manager', 'Manager'
            check_tomcat_manager_paths uri.copy, 'host-manager', 'Host Manager'
          end

          def self.check_tomcat_manager_paths(uri, base_path, manager)
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_tomcat_manager_exposed',
                                            {vulnerable: false, uri: nil}
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_tomcat_host_manager_exposed',
                                            {vulnerable: false, uri: nil}

            uri.path = "/#{base_path}/html"
            uri.query = '' unless uri.query.nil?

            ret = Yawast::Shared::Http.get(uri)

            if ret.include? '<tt>conf/tomcat-users.xml</tt>'
              # this will get Tomcat 7+
              Yawast::Utilities.puts_warn "Apache Tomcat #{manager} page found: #{uri}"
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'apache_tomcat_manager_exposed',
                                              {vulnerable: true, uri: uri}
              check_tomcat_manager_passwords uri, manager

              puts ''
            else
              # check for Tomcat 6 and below
              uri = uri.copy
              uri.path = "/#{base_path}"
              ret = Yawast::Shared::Http.get(uri)

              if ret.include? '<tt>conf/tomcat-users.xml</tt>'
                Yawast::Utilities.puts_warn "Apache Tomcat #{manager} page found: #{uri}"
                Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                'apache_tomcat_host_manager_exposed',
                                                {vulnerable: true, uri: uri}
                check_tomcat_manager_passwords uri, manager

                puts ''
              end
            end
          end

          def self.check_tomcat_manager_passwords(uri, manager)
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_tomcat_manager_weak_pass',
                                            {vulnerable: false, uri: nil, credentials: nil}
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

              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'apache_tomcat_manager_weak_pass',
                                              {vulnerable: true, uri: uri, credentials: credentials}
            end
          end

          def self.check_tomcat_put_rce(uri)
            # CVE-2017-12615
            uri.path = "/#{SecureRandom.hex}.jsp/"
            uri.query = '' unless uri.query.nil?

            # we'll use this to verify that it actually worked
            check_value = SecureRandom.hex

            # upload the JSP file
            req_data = "<% out.println(\"#{check_value}\");%>"
            Yawast::Shared::Http.put(uri, req_data)

            # check to see of we get check_value back
            uri.path = uri.path.chomp('/')
            res = Yawast::Shared::Http.get(uri)

            if res.include? check_value
              Yawast::Utilities.puts_vuln "Apache Tomcat PUT RCE (CVE-2017-12615): #{uri}"
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'apache_tomcat_cve_2017_12615',
                                              {vulnerable: true, uri: uri, check_value: check_value, body: res}
            else
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'apache_tomcat_cve_2017_12615',
                                              {vulnerable: false, uri: uri, check_value: check_value, body: res}
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

          def self.check_cve_2019_0232(links)
            Yawast::Shared::Output.log_hash 'vulnerabilities',
                                            'apache_tomcat_cve_2019_0232',
                                            {vulnerable: false, uri: nil, body: nil}

            # create a list of possible targets - this would be links that include "cgi-bin"
            targets = []
            links.each do |link|
              targets.push link if link.include? '/cgi-bin/'
            end

            # check to see if we have any targets
            unless targets.count.zero?
              # we have targets
              targets.each do |target|
                # now, we need to build the URI we'll use
                target = if target.include? '?'
                           target + '&dir'
                         else
                           target + '?dir'
                         end

                # now, send the request and see if it includes "<DIR>"
                target_uri = URI.parse target
                body = Yawast::Shared::Http.get(target_uri)

                if body.include? '<DIR>'
                  # we have a hit

                  Yawast::Utilities.puts_vuln "Apache Tomcat RCE (CVE-2019-0232): #{uri}"

                  Yawast::Shared::Output.log_hash 'vulnerabilities',
                                                  'apache_tomcat_cve_2019_0232',
                                                  {vulnerable: true, uri: target_uri, body: body}

                  break
                end
              end
            end
          end

          def self.check_page_for_string(uri, path, search)
            uri.path = path
            uri.query = '' unless uri.query.nil?

            body = Yawast::Shared::Http.get(uri)

            if body.include? search
              Yawast::Utilities.puts_vuln "#{search} page found: #{uri}"
              Yawast::Shared::Output.log_value 'apache', 'page_search', search, uri

              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              "apache_#{path.tr('-', '_').tr('/', '')}_found",
                                              {vulnerable: true, uri: uri, body: body}

              puts ''
            else
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              "apache_#{path.tr('-', '_').chomp('/')}_found",
                                              {vulnerable: false, uri: uri, body: body}
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
