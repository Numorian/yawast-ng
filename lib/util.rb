require 'colorize'

module Yawast
  class Utilities
    def self.puts_msg(type, msg)
      puts "#{type} #{msg}"
    end

    def self.puts_error(msg)
      puts_msg('[E]'.red, msg)
    end

    def self.puts_vuln(msg)
      puts_msg('[V]'.magenta, msg)
    end

    def self.puts_warn(msg)
      puts_msg('[W]'.yellow, msg)
    end

    def self.puts_info(msg)
      puts_msg('[I]'.green, msg)
    end
  end
end
