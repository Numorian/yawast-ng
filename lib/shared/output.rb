# frozen_string_literal: true

require 'json'
require 'base64'

module Yawast
  module Shared
    class Output
      def self.setup(uri, options)
        return if @setup

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
          puts 'WARNING: Output file already exists; it will be replaced.' if File.exist? @file
        end

        puts "Saving output to '#{@file}'"
        puts

        @data = {}

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

      def self.log_value(super_parent = nil, parent = nil, key, value)
        return unless @setup

        target = get_target super_parent, parent

        target[key] = encode_utf8(value.to_s)
      end

      def self.log_append_value(super_parent = nil, parent = nil, key, value)
        return unless @setup

        target = get_target super_parent, parent

        target[key] = [] if target[key].nil?

        # add value, after checking if it's already included
        target[key].push encode_utf8(value.to_s) unless target[key].include? encode_utf8(value.to_s)
      end

      def self.log_json(super_parent = nil, parent = nil, key, json_block)
        return unless @setup

        target = get_target super_parent, parent

        target[key] = escape_hash(JSON.parse(json_block))
      end

      def self.log_hash(super_parent = nil, parent = nil, key, hash)
        return unless @setup

        target = get_target super_parent, parent

        target[key] = escape_hash hash
      end

      def self.encode_utf8(str)
        str = str.dup

        str = str.force_encoding('UTF-8') if [Encoding::ASCII_8BIT, Encoding::US_ASCII].include?(str.encoding)

        str
      end

      def self.get_target(super_parent = nil, parent = nil)
        target = @data

        # fix parent vs super confusion
        if parent.nil? && !super_parent.nil?
          parent = super_parent
          super_parent = nil
        end

        unless super_parent.nil?
          target[super_parent] = {} if target[super_parent].nil?

          target = target[super_parent]
        end

        unless parent.nil?
          target[parent] = {} if target[parent].nil?

          target = target[parent]
        end

        target
      end

      def self.escape_hash(hash)
        hash.each_pair do |k, v|
          if v.is_a?(Hash)
            escape_hash(v)
          elsif v.is_a?(String)
            # first, attempt to force utf-8
            v = encode_utf8 v
            hash[k] = v

            # if needed, Base64 encode to ensure that we can produce the JSON output
            hash[k] = Base64.encode64 v unless v.valid_encoding?
          end
        end
      end

      def self.write_file
        return unless @setup

        # note the ending time
        log_value 'end_time', Time.new.to_i.to_s

        begin
          json = JSON.pretty_generate @data
        rescue JSON::GeneratorError
          # this means that we don't have valid data to encode - need to perform some cleanup
          @data = escape_hash @data
          json = JSON.pretty_generate @data
        end

        File.open(@file, 'w') { |file| file.write(json) }
      end
    end
  end
end
