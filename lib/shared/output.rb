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
          log_value 'encoding', __ENCODING__
        end
      end

      def self.log_value(super_parent = nil, parent = nil, key, value)
        if @setup
          target = get_target super_parent, parent

          target[key] = encode_utf8(value.to_s)
        end
      end

      def self.log_append_value(super_parent = nil, parent = nil, key, value)
        if @setup
          target = get_target super_parent, parent

          if target[key] == nil
            target[key] = Array.new
          end

          target[key].push encode_utf8(value.to_s)
        end
      end

      def self.log_json(super_parent = nil, parent = nil, key, json_block)
        if @setup
          target = get_target super_parent, parent

          target[key] = JSON.parse(json_block)
        end
      end

      def self.log_hash(super_parent = nil, parent = nil, key, hash)
        if @setup
          target = get_target super_parent, parent

          target[key] = hash
        end
      end

      def self.encode_utf8(str)
        str = str.dup

        if [Encoding::ASCII_8BIT, Encoding::US_ASCII].include?(str.encoding)
          str = str.force_encoding('UTF-8')
        end

        return str
      end

      def self.get_target(super_parent = nil, parent = nil)
        target = @data

        # fix parent vs super confusion
        if parent == nil && super_parent != nil
          parent = super_parent
          super_parent = nil
        end

        if super_parent != nil
          if target[super_parent] == nil
            target[super_parent] = Hash.new
          end

          target = target[super_parent]
        end

        if parent != nil
          if target[parent] == nil
            target[parent] = Hash.new
          end

          target = target[parent]
        end

        return target
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
