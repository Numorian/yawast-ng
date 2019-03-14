# frozen_string_literal: true

class String
  # see if string is numeric
  def is_number?
    begin
      true if Float(self)
    rescue # rubocop:disable Style/RescueStandardError
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
