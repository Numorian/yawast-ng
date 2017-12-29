require 'dnsruby'
include Dnsruby

module Yawast
  module Scanner
    module Plugins
      module DNS
        class CAA
          def self.caa_info(uri)
            # force DNS resolver to something that works
            # this is done to ensure that ISP resolvers don't get in the way
            # at some point, should probably do something else, but works for now
            @res = Resolver.new(nameserver: ['8.8.8.8'])

            # setup a list of domains already checked, so we can skip them
            @checked = []

            domain = uri.host.to_s

            chase_domain domain
          end

          def self.chase_domain(domain)
            while domain != '' do
              begin
                # check to see if we've already ran into this one
                if @checked.include? domain
                  return
                end
                @checked.push domain

                # first, see if this is a CNAME. we do this explicitly because
                # some resolvers flatten in an odd way that prevents just checking
                # for the CAA record directly
                cname = get_cname_record(domain)
                if !cname.nil?
                  Yawast::Utilities.puts_info "\t\tCAA (#{domain}): CNAME Found: -> #{cname}"
                  chase_domain cname.to_s
                else
                  print_caa_record domain
                end
              rescue => e
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

            if ans.answer.count > 0
              ans.answer.each do |rec|
                # check for RDATA
                if !rec.rdata.nil?
                  Yawast::Utilities.puts_info "\t\tCAA (#{domain}): #{rec.rdata}"
                else
                  Yawast::Utilities.puts_error "\t\tCAA (#{domain}): Invalid Response: #{ans.answer}"
                end
              end
            else
              # no answer, so no records
              Yawast::Utilities.puts_info "\t\tCAA (#{domain}): No Records Found"
            end
          end
        end
      end
    end
  end
end
