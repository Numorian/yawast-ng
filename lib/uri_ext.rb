module URI
  def copy
    URI.parse(to_s)
  end
end
