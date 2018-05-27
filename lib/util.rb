require 'colorize'

module Yawast
  class Utilities
    def self.puts_msg(type, msg)
      puts "#{type} #{msg}"
    end

    def self.puts_error(msg)
      puts_msg('[E]'.red, msg)
      Yawast::Shared::Output.log_append_value 'messages', 'error', msg
    end

    def self.puts_vuln(msg)
      puts_msg('[V]'.magenta, msg)
      Yawast::Shared::Output.log_append_value 'messages', 'vulnerability', msg
    end

    def self.puts_warn(msg)
      puts_msg('[W]'.yellow, msg)
      Yawast::Shared::Output.log_append_value 'messages', 'warning', msg
    end

    def self.puts_info(msg)
      puts_msg('[I]'.green, msg)
      Yawast::Shared::Output.log_append_value 'messages', 'info', msg
    end
  end
end
