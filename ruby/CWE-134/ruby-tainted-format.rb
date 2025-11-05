# Examples for ruby-tainted-format vulnerability (CWE-134)
require 'sinatra'
require 'erb'

# True Positive Examples (Vulnerable Code)

# Bad case 1: Using user input directly in sprintf
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_1
  get '/format1' do
    user_input = params[:input]
    # ruleid: ruby-tainted-format
    result = sprintf("User said: %s", user_input)
    "Result: #{result}"
  end
# {/fact}
end

# Bad case 2: Using user input directly in format
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_2
  get '/format2' do
    user_input = params[:message]
    # ruleid: ruby-tainted-format
    result = "Message: %s".format(user_input)
    "Formatted: #{result}"
  end
# {/fact}
end

# Bad case 3: Using user input in string interpolation for logging
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_3
  get '/log' do
    user_input = params[:query]
    # ruleid: ruby-tainted-format
    logger.info("User searched for #{user_input}")
    "Search logged"
  end
# {/fact}
end

# Bad case 4: Using user input in printf
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_4
  get '/print' do
    user_input = request.env['HTTP_USER_AGENT']
    # ruleid: ruby-tainted-format
    printf("User agent: %s\n", user_input)
    "Printed user agent"
  end
# {/fact}
end

# Bad case 5: Using user input in ERB template
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_5
  get '/template' do
    user_input = params[:name]
    template = "<%= 'Hello, ' + user_input %>"
    # ruleid: ruby-tainted-format
    result = ERB.new(template).result(binding)
    "Template result: #{result}"
  end
# {/fact}
end

# Bad case 6: Using header value in format string
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_6
  get '/header_format' do
    header_value = request.env['HTTP_X_CUSTOM_HEADER']
    # ruleid: ruby-tainted-format
    result = "Header value: %s".format(header_value)
    "Result: #{result}"
  end
# {/fact}
end

# Bad case 7: Using cookie value in format string
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_7
  get '/cookie_format' do
    cookie_value = request.cookies['user_preference']
    # ruleid: ruby-tainted-format
    message = sprintf("Your preference is: %s", cookie_value)
    "Message: #{message}"
  end
# {/fact}
end

# Bad case 8: Using form data in format string
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_8
  post '/form_format' do
    form_data = request.POST['comment']
    # ruleid: ruby-tainted-format
    formatted = "Comment: %s".format(form_data)
    "Formatted comment: #{formatted}"
  end
# {/fact}
end

# Bad case 9: Using URL path parameter in format string
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_9
  get '/user/:username' do
    username = params[:username]
    # ruleid: ruby-tainted-format
    result = sprintf("Profile for %s", username)
    "Result: #{result}"
  end
# {/fact}
end

# Bad case 10: Using query string in multiple format specifiers
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_10
  get '/search' do
    query = params[:q]
    category = params[:category]
    # ruleid: ruby-tainted-format
    result = sprintf("Searching for %s in category %s", query, category)
    "Search result: #{result}"
  end
# {/fact}
end

# Bad case 11: Using user input in format with multiple variables
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_11
  get '/multi_format' do
    name = params[:name]
    age = params[:age]
    # ruleid: ruby-tainted-format
    result = "Name: %s, Age: %s".format(name, age)
    "Result: #{result}"
  end
# {/fact}
end

# Bad case 12: Using request body in format string
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_12
  post '/body_format' do
    body = request.body.read
    # ruleid: ruby-tainted-format
    result = sprintf("Received: %s", body)
    "Result: #{result}"
  end
# {/fact}
end

# Bad case 13: Using JSON data in format string
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_13
  post '/json_format' do
    data = JSON.parse(request.body.read)
    user_message = data['message']
    # ruleid: ruby-tainted-format
    result = "Message: %s".format(user_message)
    "Result: #{result}"
  end
# {/fact}
end

# Bad case 14: Using user input in custom logger with format
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_14
  get '/custom_log' do
    user_input = params[:data]
    # ruleid: ruby-tainted-format
    custom_logger("User data: %s", user_input)
    "Logged user data"
  end
# {/fact}
  
  def custom_logger(format_string, *args)
    puts sprintf(format_string, *args)
  end
end

# Bad case 15: Using user input in format with string concatenation
# {fact rule=untrusted-format-strings@v1.0 defects=1}
def bad_case_15
  get '/concat_format' do
    user_input = params[:input]
    format_string = "Input: %s"
    # ruleid: ruby-tainted-format
    result = sprintf(format_string, user_input)
    "Result: #{result}"
  end
# {/fact}
end

# True Negative Examples (Secure Code)

# Good case 1: Sanitizing user input before using in sprintf
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_1
  get '/safe_format1' do
    user_input = params[:input]
    sanitized_input = CGI.escape(user_input.to_s)
    # ok: ruby-tainted-format
    result = sprintf("User said: %s", sanitized_input)
    "Result: #{result}"
  end
# {/fact}
end

# Good case 2: Using constants in format
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_2
  get '/safe_format2' do
    message = "Hello, world!"
    # ok: ruby-tainted-format
    result = "Message: %s".format(message)
    "Formatted: #{result}"
  end
# {/fact}
end

# Good case 3: Using validated input in string interpolation
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_3
  get '/safe_log' do
    user_input = params[:query]
    if user_input =~ /^[a-zA-Z0-9\s]+$/
      # ok: ruby-tainted-format
      logger.info("User searched for #{user_input}")
      "Search logged"
    else
      "Invalid input"
    end
  end
# {/fact}
end

# Good case 4: Using hardcoded values in printf
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_4
  get '/safe_print' do
    agent = "Mozilla"
    # ok: ruby-tainted-format
    printf("User agent: %s\n", agent)
    "Printed user agent"
  end
# {/fact}
end

# Good case 5: Using sanitized input in ERB template
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_5
  get '/safe_template' do
    user_input = params[:name]
    sanitized_name = CGI.escapeHTML(user_input.to_s)
    template = "<%= 'Hello, ' + sanitized_name %>"
    # ok: ruby-tainted-format
    result = ERB.new(template).result(binding)
    "Template result: #{result}"
  end
# {/fact}
end

# Good case 6: Using validated header value in format string
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_6
  get '/safe_header_format' do
    header_value = request.env['HTTP_X_CUSTOM_HEADER']
    if header_value && header_value.match?(/^[a-zA-Z0-9\s]+$/)
      # ok: ruby-tainted-format
      result = "Header value: %s".format(header_value)
      "Result: #{result}"
    else
      "Invalid header"
    end
  end
# {/fact}
end

# Good case 7: Using sanitized cookie value in format string
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_7
  get '/safe_cookie_format' do
    cookie_value = request.cookies['user_preference']
    sanitized_value = cookie_value.to_s.gsub(/[^a-zA-Z0-9\s]/, '')
    # ok: ruby-tainted-format
    message = sprintf("Your preference is: %s", sanitized_value)
    "Message: #{message}"
  end
# {/fact}
end

# Good case 8: Using constant in format string
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_8
  get '/safe_constant_format' do
    # ok: ruby-tainted-format
    formatted = "Comment: %s".format("This is a static comment")
    "Formatted comment: #{formatted}"
  end
# {/fact}
end

# Good case 9: Using whitelisted value in format string
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_9
  get '/safe_whitelist' do
    username = params[:username]
    allowed_users = ["admin", "user", "guest"]
    if allowed_users.include?(username)
      # ok: ruby-tainted-format
      result = sprintf("Profile for %s", username)
      "Result: #{result}"
    else
      "Unknown user"
    end
  end
# {/fact}
end

# Good case 10: Using integer conversion for numeric input
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_10
  get '/safe_numeric' do
    age = params[:age].to_i  # Convert to integer, removing any non-numeric content
    # ok: ruby-tainted-format
    result = sprintf("Age: %d", age)
    "Result: #{result}"
  end
# {/fact}
end

# Good case 11: Using format with constant values
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_11
  get '/safe_multi_format' do
    # ok: ruby-tainted-format
    result = "Name: %s, Age: %s".format("John", "30")
    "Result: #{result}"
  end
# {/fact}
end

# Good case 12: Using format with validated input
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_12
  post '/safe_body_format' do
    body = request.body.read
    if body.length <= 100 && body =~ /^[a-zA-Z0-9\s]+$/
      # ok: ruby-tainted-format
      result = sprintf("Received: %s", body)
      "Result: #{result}"
    else
      "Invalid input"
    end
  end
# {/fact}
end

# Good case 13: Using format with JSON data after validation
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_13
  post '/safe_json_format' do
    begin
      data = JSON.parse(request.body.read)
      user_message = data['message'].to_s
      if user_message =~ /^[a-zA-Z0-9\s.,!?]+$/
        # ok: ruby-tainted-format
        result = "Message: %s".format(user_message)
        "Result: #{result}"
      else
        "Invalid message format"
      end
    rescue JSON::ParserError
      "Invalid JSON"
    end
  end
# {/fact}
end

# Good case 14: Using format with sanitized input in custom logger
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_14
  get '/safe_custom_log' do
    user_input = params[:data]
    sanitized = user_input.to_s.gsub(/[^a-zA-Z0-9\s]/, '')
    # ok: ruby-tainted-format
    custom_logger("User data: %s", sanitized)
    "Logged user data"
  end
# {/fact}
  
  def custom_logger(format_string, *args)
    puts sprintf(format_string, *args)
  end
end

# Good case 15: Using format with type checking
# {fact rule=untrusted-format-strings@v1.0 defects=0}
def good_case_15
  get '/safe_type_check' do
    user_input = params[:input]
    if user_input.is_a?(String) && user_input =~ /^[a-zA-Z0-9\s]+$/
      # ok: ruby-tainted-format
      result = sprintf("Input: %s", user_input)
      "Result: #{result}"
    else
      "Invalid input type or format"
    end
  end
# {/fact}
end