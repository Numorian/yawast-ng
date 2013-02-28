require 'net/http'

def http_head(uri)
  Net::HTTP.start(uri.host,uri.port) do |http|
    http.head(uri.path)
  end
end

def http_get(uri)
  body = ''

  begin
    req = Net::HTTP.new(uri.host, uri.port)
    res = req.request_get(uri.path)
    body = res.read_body
  rescue
    #do nothing for now
  end

  body
end
