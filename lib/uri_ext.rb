module URI
  def copy
    URI.parse(self.to_s)
  end
end
