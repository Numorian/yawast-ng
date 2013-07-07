class String
  # colorization
  def colorize(color_code)
    raise ArgumentError, 'color_code must be numeric' unless color_code.is_a? Integer || color_code.is_number?

    "\e[#{color_code}m#{self}\e[0m"
  end

  def red
    colorize(31)
  end

  def green
    colorize(32)
  end

  def yellow
    colorize(33)
  end

  def pink
    colorize(35)
  end

  #see if string is numeric
  def is_number?
    true if Float(self) rescue false
  end
end
