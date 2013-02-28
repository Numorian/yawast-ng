require 'net/http'

def head(uri)
  Net::HTTP.start(uri.host,uri.port) do |http|
    http.head(uri.path)
  end
end
