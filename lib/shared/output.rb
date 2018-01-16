require 'json'

module Yawast
  module Shared
    class Output
      def self.setup(uri, options)
        unless @setup
          @setup = true

          time = Time.new.to_i.to_s
          @file = options.output

          # get the absolute path
          @file = File.absolute_path @file

          # see if this is a file or directory
          if File.directory? @file
            # in this case, the user just gave us a directory, se we will create a file name
            @file = File.join(@file, uri.hostname + '_' + time + '.json')
          else
            # this means that it's a file, or doesn't exist
            # so, let's see if it exists, if so, warn
            if File.exist? @file
              puts 'WARNING: Output file already exists; it will be replaced.'
            end
          end

          puts "Saving output to '#{@file}'"
          puts

          @data = Hash.new

          # add the initial entries to the output
          log_value 'start_time', time
          log_value 'yawast_version', VERSION
          log_value 'ruby_version', "#{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}"
          log_value 'openssl_version', OpenSSL::OPENSSL_VERSION
          log_value 'platform', RUBY_PLATFORM
          log_value 'target_uri', uri
          log_value 'options', options.__hash__
        end
      end

      def self.log_value(parent = nil, key, value)
        if @setup
          if parent != nil
            if @data[parent] == nil
              @data[parent] = Hash.new
            end

            @data[parent][key] = value
          else
            @data[key] = value
          end
        end
      end

      def self.log_append_value(parent = nil, key, value)
        if @setup
          if parent != nil
            if @data[parent] == nil
              @data[parent] = Hash.new
            end
            if @data[parent][key] == nil
              @data[parent][key] = Array.new
            end

            @data[parent][key].push value
          else
            if @data[key] == nil
              @data[key] = Array.new
            end

            @data[key].push value
          end
        end
      end

      def self.log_json(key, json_block)
        if @setup
          @data[key] = JSON.parse(json_block)
        end
      end

      def self.write_file
        if @setup
          # note the ending time
          log_value 'end_time', Time.new.to_i.to_s

          json = JSON.pretty_generate @data
          File.open(@file, 'w') { |file| file.write(json) }
        end
      end
    end
  end
end
