require 'net/http'

def http_head(uri)
  req = Net::HTTP.new(uri.host, uri.port)
  req.use_ssl = uri.scheme == 'https'
  headers = { 'User-Agent' => HTTP_UA }
  req.head(uri.path, headers)
end

def http_get(uri)
  body = ''

  begin
    req = Net::HTTP.new(uri.host, uri.port)
    req.use_ssl = uri.scheme == 'https'
    headers = { 'User-Agent' => HTTP_UA }
    res = req.request_get(uri.path, headers)
    body = res.read_body
  rescue
    #do nothing for now
  end

  body
end

def http_peer_cert(uri)
  req = Net::HTTP.new(uri.host, uri.port)
  req.use_ssl = uri.scheme == 'https'
  req.start { |http| return http.peer_cert }
end
