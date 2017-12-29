class String
  # see if string is numeric
  def is_number?
    begin
      true if Float(self)
    rescue
      false
    end
  end

  def trim
    trimmed = strip

    if trimmed.nil?
      self
    else
      trimmed
    end
  end
end
