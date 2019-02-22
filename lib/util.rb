require 'colorize'
require 'diffy'

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

    def self.puts(msg = '')
      puts msg

      if msg != ''
        Yawast::Shared::Output.log_append_value 'messages', 'raw', msg
      end
    end

    def self.prompt(msg)
      puts
      puts msg
      print '> '
      val = $stdin.gets.chomp

      Yawast::Shared::Output.log_append_value 'prompt', msg, val

      return val
    end

    def self.indent_text(msg)
      return msg.gsub!(/^/, "\t")
    end

    def self.diff_text(txt1, txt2)

      return indent_text(Diffy::Diff.new(txt1, txt2, :context => 1).to_s(:color))
    end
  end
end
