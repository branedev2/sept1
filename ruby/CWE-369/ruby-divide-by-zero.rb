# Ruby Divide by Zero Examples

# True Positives (Vulnerable Code)

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_1
  # Simple divide by zero with literal
  x = 10
  # ruleid: ruby-divide-by-zero
  result = x / 0
  puts "Result: #{result}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_2
  # Division by a variable that could be zero
  denominator = 0
  numerator = 42
  # ruleid: ruby-divide-by-zero
  result = numerator / denominator
  puts "Result: #{result}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_3
  # Division by a calculation that results in zero
  a = 5
  b = 5
  # ruleid: ruby-divide-by-zero
  result = 100 / (a - b)
  puts "Result: #{result}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_4
  # Division by user input that could be zero
  require 'sinatra'
  
  get '/calculate' do
    numerator = 100
    denominator = params[:denominator].to_i
    # ruleid: ruby-divide-by-zero
    result = numerator / denominator
    "Result: #{result}"
  end
# {/fact}
end

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_5
  # Division in a complex expression
  x = 10
  y = 0
  # ruleid: ruby-divide-by-zero
  result = (x * 2) / (y + 0)
  puts "Result: #{result}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_6
  # Division by zero in a loop
  numbers = [1, 2, 0, 4, 5]
  results = []
  
  numbers.each do |num|
    # ruleid: ruby-divide-by-zero
    results << 100 / num
  end
# {/fact}
  
  puts results.join(', ')
end

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_7
  # Division by zero in a method call
  def calculate_ratio(a, b)
    # ruleid: ruby-divide-by-zero
    a / b
  end
  
  result = calculate_ratio(10, 0)
  puts "Ratio: #{result}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_8
  # Division by zero in a ternary operation
  x = 5
  y = 0
  # ruleid: ruby-divide-by-zero
  result = x > 0 ? x / y : 0
  puts "Result: #{result}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_9
  # Division by zero with modulo operation
  a = 10
  b = 0
  # ruleid: ruby-divide-by-zero
  remainder = a % b
  puts "Remainder: #{remainder}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_10
  # Division by zero in a hash calculation
  require 'sinatra'
  
  post '/average' do
    values = params[:values].split(',').map(&:to_i)
    count = values.count { |v| v > 0 } - values.count { |v| v > 0 }
    # ruleid: ruby-divide-by-zero
    average = values.sum / count
    "Average: #{average}"
  end
# {/fact}
end

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_11
  # Division by zero in a mathematical formula
  radius = 0
  # ruleid: ruby-divide-by-zero
  area = Math::PI * (1 / radius)**2
  puts "Area: #{area}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_12
  # Division by zero in a string interpolation
  divisor = 0
  # ruleid: ruby-divide-by-zero
  message = "The result is #{100 / divisor}"
  puts message
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_13
  # Division by zero in a conditional
  x = 0
  if 10 / x > 5
    puts "Greater than 5"
  else
    puts "Less than or equal to 5"
  end
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_14
  # Division by zero in array operations
  require 'sinatra'
  
  get '/process' do
    data = [100, 200, 300]
    divisor = params[:divisor].to_i
    # ruleid: ruby-divide-by-zero
    result = data.map { |item| item / divisor }
    "Results: #{result.join(', ')}"
  end
# {/fact}
end

# {fact rule=divided-by-zero@v1.0 defects=1}
def bad_case_15
  # Division by zero in a class method
  class Calculator
    def self.divide(a, b)
      # ruleid: ruby-divide-by-zero
      a / b
    end
  end
  
  result = Calculator.divide(42, 0)
  puts "Result: #{result}"
end
# {/fact}

# True Negatives (Safe Code)

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_1
  # Check for zero before division
  x = 10
  y = 0
  
  # ok: ruby-divide-by-zero
  if y != 0
    result = x / y
    puts "Result: #{result}"
  else
    puts "Cannot divide by zero"
  end
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_2
  # Using exception handling for divide by zero
  numerator = 42
  denominator = 0
  
  begin
    # ok: ruby-divide-by-zero
    result = numerator / denominator
    puts "Result: #{result}"
  rescue ZeroDivisionError
    puts "Error: Division by zero"
  end
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_3
  # Using a default value when denominator is zero
  a = 5
  b = 5
  
  # ok: ruby-divide-by-zero
  result = b != 0 ? a / b : "Undefined"
  puts "Result: #{result}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_4
  # Checking user input before division
  require 'sinatra'
  
  get '/calculate' do
    numerator = 100
    denominator = params[:denominator].to_i
    
    # ok: ruby-divide-by-zero
    if denominator != 0
      result = numerator / denominator
      "Result: #{result}"
    else
      "Error: Cannot divide by zero"
    end
  end
# {/fact}
end

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_5
  # Using a safe division helper method
  def safe_division(a, b)
    # ok: ruby-divide-by-zero
    b.zero? ? nil : a / b
  end
  
  result = safe_division(10, 0)
  puts "Result: #{result || 'Cannot divide by zero'}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_6
  # Safe division in a loop with checks
  numbers = [1, 2, 0, 4, 5]
  results = []
  
  numbers.each do |num|
    # ok: ruby-divide-by-zero
    if num != 0
      results << 100 / num
    else
      results << "Undefined"
    end
  end
# {/fact}
  
  puts results.join(', ')
end

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_7
  # Safe method with parameter validation
  def calculate_ratio(a, b)
    # ok: ruby-divide-by-zero
    raise ArgumentError, "Denominator cannot be zero" if b.zero?
    a / b
  end
  
  begin
    result = calculate_ratio(10, 0)
    puts "Ratio: #{result}"
  rescue ArgumentError => e
    puts e.message
  end
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_8
  # Using conditional to avoid division by zero
  x = 5
  y = 0
  
  # ok: ruby-divide-by-zero
  result = y != 0 ? x / y : Float::INFINITY
  puts "Result: #{result}"
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_9
  # Safe modulo operation with check
  a = 10
  b = 0
  
  # ok: ruby-divide-by-zero
  if b != 0
    remainder = a % b
    puts "Remainder: #{remainder}"
  else
    puts "Cannot calculate remainder with zero divisor"
  end
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_10
  # Safe average calculation with validation
  require 'sinatra'
  
  post '/average' do
    values = params[:values].split(',').map(&:to_i)
    count = values.count { |v| v > 0 } - values.count { |v| v > 0 }
    
    # ok: ruby-divide-by-zero
    average = count != 0 ? values.sum / count : 0
    "Average: #{average}"
  end
# {/fact}
end

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_11
  # Safe mathematical formula with validation
  radius = 0
  
  # ok: ruby-divide-by-zero
  area = if radius != 0
    Math::PI * (1 / radius)**2
  else
    0
  end
# {/fact}
  
  puts "Area: #{area}"
end

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_12
  # Safe string interpolation with check
  divisor = 0
  
  # ok: ruby-divide-by-zero
  message = if divisor != 0
    "The result is #{100 / divisor}"
  else
    "Cannot calculate result"
  end
# {/fact}
  
  puts message
end

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_13
  # Safe conditional with check
  x = 0
  
  # ok: ruby-divide-by-zero
  if x != 0 && 10 / x > 5
    puts "Greater than 5"
  else
    puts "Less than or equal to 5 or division not possible"
  end
end
# {/fact}

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_14
  # Safe array operations with validation
  require 'sinatra'
  
  get '/process' do
    data = [100, 200, 300]
    divisor = params[:divisor].to_i
    
    # ok: ruby-divide-by-zero
    if divisor != 0
      result = data.map { |item| item / divisor }
      "Results: #{result.join(', ')}"
    else
      "Error: Cannot divide by zero"
    end
  end
# {/fact}
end

# {fact rule=divided-by-zero@v1.0 defects=0}
def good_case_15
  # Safe class method with validation
  class Calculator
    def self.divide(a, b)
      # ok: ruby-divide-by-zero
      raise ArgumentError, "Cannot divide by zero" if b.zero?
      a / b
    end
  end
  
  begin
    result = Calculator.divide(42, 0)
    puts "Result: #{result}"
  rescue ArgumentError => e
    puts e.message
  end
end
# {/fact}