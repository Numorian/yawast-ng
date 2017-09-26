require 'dnsruby'
include Dnsruby

module Yawast
  module Scanner
    module Plugins
      module DNS
        class CAA
          def self.caa_info(uri)
            # force DNS resolver to something that works
            res = Resolver.new({:nameserver => ['8.8.8.8']})

            domain = uri.host.to_s

            #BUG: this is a basic implementation that ignores CNAMEs/etc
            while domain != '' do
              begin
                ans = res.query(domain, 'CAA')

                # check if we have any response
                if ans.answer.count > 0
                  ans.answer.each do |rec|
                    # check for CNAME first
                    if rec.type == 'CNAME'
                      Yawast::Utilities.puts_info "\t\tCAA (#{domain}): CNAME Found: -> #{rec.rdata}"

                      follow_cname res,rec
                    else
                      # check for RDATA
                      if rec.rdata != nil
                        Yawast::Utilities.puts_info "\t\tCAA (#{domain}): #{rec.rdata}"
                      else
                        Yawast::Utilities.puts_error "\t\tCAA (#{domain}): Invalid Response: #{ans.answer}"
                      end
                    end
                  end
                else
                  Yawast::Utilities.puts_info "\t\tCAA (#{domain}): No Records Found"
                end

              rescue => e
                Yawast::Utilities.puts_error "\t\tCAA (#{domain}): #{e.message}"
              end

              # strip the leading element off the domain
              domain = domain.partition('.').last
            end
          end

          def self.follow_cname(res, rec)
            # we have a CNAME, so we should check the target, and see if it has anything
            #  then, we'll continue searching the chain.
            cname = rec.rdata
            while cname != ''
              cname_ans = res.query(cname, 'CAA')

              if cname_ans.answer.count > 0
                ans.answer.each do |record|
                  if record.type == 'CNAME'
                    # another CNAME
                    Yawast::Utilities.puts_info "\t\tCAA (#{domain}): CNAME Found: -> #{rec.rdata}"
                    cname = rec.rdata
                  else
                    if record.rdata != nil
                      Yawast::Utilities.puts_info "\t\tCAA (#{domain}): #{record.rdata}"
                    else
                      Yawast::Utilities.puts_error "\t\tCAA (#{domain}): Invalid Response: #{record.answer}"
                    end

                    cname = ''
                  end
                end
              else
                Yawast::Utilities.puts_info "\t\tCAA (#{cname}): No Records Found"
                cname = ''
              end
            end
          end
        end
      end
    end
  end
end
