class String
  #see if string is numeric
  def is_number?
    true if Float(self) rescue false
  end

  def trim
    trimmed = self.strip

    if trimmed == nil
      self
    else
      trimmed
    end
  end
end
