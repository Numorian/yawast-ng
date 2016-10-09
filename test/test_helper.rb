require 'minitest/reporters'
require 'simplecov'
require 'coveralls'

SimpleCov.start do
  add_filter do |source_file|
    source_file.filename =~ /test/
  end
end

MiniTest::Reporters.use!
Coveralls.wear!
