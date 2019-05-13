# frozen_string_literal: true

require 'dnsruby'

module Yawast
  module Scanner
    module Plugins
      module DNS
        class CAA < Yawast::Scanner::Base
          include Dnsruby

          def self.caa_info(uri)
            # force DNS resolver to something that works
            # this is done to ensure that ISP resolvers don't get in the way
            # at some point, should probably do something else, but works for now
            @res = Resolver.new({nameserver: ['8.8.8.8']})

            # setup a list of domains already checked, so we can skip them
            @checked = []

            # setup a counter, so we can see if we actually got anything
            @records = 0

            domain = uri.host.to_s

            chase_domain domain

            if @records.zero?
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'missing_caa_records',
                                              {vulnerable: true, record_count: 0}

              puts
              Yawast::Utilities.puts_vuln 'DNS CAA: No records found.'
            else
              Yawast::Shared::Output.log_hash 'vulnerabilities',
                                              'missing_caa_records',
                                              {vulnerable: false, record_count: @records}
            end
          end

          def self.chase_domain(domain)
            while domain != ''
              begin
                # check to see if we've already ran into this one
                return if @checked.include? domain
                @checked.push domain

                # first, see if this is a CNAME. we do this explicitly because
                # some resolvers flatten in an odd way that prevents just checking
                # for the CAA record directly
                cname = get_cname_record(domain)
                if !cname.nil?
                  Yawast::Utilities.puts_info "\t\tCAA (#{domain}): CNAME Found: -> #{cname}"
                  Yawast::Shared::Output.log_value 'dns', 'caa', domain, "CNAME: #{cname}"

                  chase_domain cname.to_s
                else
                  print_caa_record domain
                end
              rescue => e # rubocop:disable Style/RescueStandardError
                Yawast::Utilities.puts_error "\t\tCAA (#{domain}): #{e.message}"
              end

              # strip the leading element off the domain
              domain = domain.partition('.').last
            end
          end

          def self.get_cname_record(domain)
            ans = @res.query(domain, 'CNAME')

            if !ans.answer[0].nil?
              return ans.answer[0].rdata
            else
              return nil
            end
          end

          def self.print_caa_record(domain)
            ans = @res.query(domain, 'CAA')

            if ans.answer.count.positive?
              ans.answer.each do |rec|
                # check for RDATA
                if !rec.rdata.nil?
                  Yawast::Utilities.puts_info "\t\tCAA (#{domain}): #{rec.rdata}"

                  Yawast::Shared::Output.log_append_value 'dns', 'caa', domain, rec.rdata
                  @records += 1
                else
                  Yawast::Utilities.puts_error "\t\tCAA (#{domain}): Invalid Response: #{ans.answer}"
                end
              end
            else
              # no answer, so no records
              Yawast::Utilities.puts_info "\t\tCAA (#{domain}): No Records Found"

              Yawast::Shared::Output.log_value 'dns', 'caa', domain, 'nil'
            end
          end
        end
      end
    end
  end
end
