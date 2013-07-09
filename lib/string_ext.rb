class String
  #see if string is numeric
  def is_number?
    true if Float(self) rescue false
  end
end
