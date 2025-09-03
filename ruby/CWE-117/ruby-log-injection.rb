require 'logger'
require 'sinatra'
require 'rack'
require 'cgi'

# Set up a logger
logger = Logger.new(STDOUT)

# True Positive Examples (Vulnerable Code)

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_1
  # User input directly logged without sanitization
  user_input = params[:username]
  
  # ruleid: ruby-log-injection
  logger.info("User logged in: #{user_input}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_2
  # User input from request headers directly logged
  user_agent = request.env["HTTP_USER_AGENT"]
  
  # ruleid: ruby-log-injection
  logger.warn("Request from user agent: #{user_agent}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_3
  # User input from POST data directly logged
  email = request.POST["email"]
  
  # ruleid: ruby-log-injection
  logger.error("Failed login attempt for email: #{email}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_4
  # User input from URL path parameter directly logged
  username = params[:username]
  ip_address = request.ip
  
  # ruleid: ruby-log-injection
  logger.info("User #{username} connected from #{ip_address}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_5
  # User input from query string directly logged
  search_term = params[:q]
  
  # ruleid: ruby-log-injection
  Rails.logger.info("Search performed for: #{search_term}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_6
  # User input from cookie directly logged
  session_id = request.cookies["session_id"]
  
  # ruleid: ruby-log-injection
  logger.debug("Session activity: #{session_id}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_7
  # Multiple user inputs concatenated and logged
  username = params[:username]
  action = params[:action]
  
  # ruleid: ruby-log-injection
  logger.info("User #{username} performed action: #{action}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_8
  # User input logged with string interpolation
  referer = request.env["HTTP_REFERER"]
  
  # ruleid: ruby-log-injection
  logger.info("Request referred from: #{referer}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_9
  # User input logged with string concatenation
  ip = request.ip
  
  # ruleid: ruby-log-injection
  logger.warn("Suspicious activity from IP: " + ip)
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_10
  # User input in formatted log message
  user_id = params[:id]
  
  # ruleid: ruby-log-injection
  logger.info(format("User ID %s accessed the system", user_id))
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_11
  # User input in exception logging
  begin
    # Some code that might raise an exception
    raise "Error for user: #{params[:username]}"
  rescue => e
    # ruleid: ruby-log-injection
    logger.error("Exception occurred: #{e.message}")
  end
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_12
  # User input logged in conditional block
  user_input = params[:input]
  
  if user_input.length > 10
    # ruleid: ruby-log-injection
    logger.warn("Long input received: #{user_input}")
  else
    # ruleid: ruby-log-injection
    logger.info("Short input received: #{user_input}")
  end
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_13
  # User input logged after minimal processing
  user_input = params[:comment].upcase
  
  # ruleid: ruby-log-injection
  logger.info("Received comment: #{user_input}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_14
  # User input logged with custom logger
  custom_logger = Logger.new('custom.log')
  user_data = params[:data]
  
  # ruleid: ruby-log-injection
  custom_logger.info("Processing data: #{user_data}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_15
  # User input logged with multiple parameters
  username = params[:username]
  action = params[:action]
  item = params[:item]
  
  # ruleid: ruby-log-injection
  logger.info("User #{username} #{action} item #{item}")
end
# {/fact}

# True Negative Examples (Safe Code)

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_1
  # User input sanitized before logging
  user_input = params[:username]
  sanitized_input = CGI.escape(user_input)
  
  # ok: ruby-log-injection
  logger.info("User logged in: #{sanitized_input}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_2
  # User input from request headers sanitized before logging
  user_agent = request.env["HTTP_USER_AGENT"]
  sanitized_agent = user_agent.gsub(/[\r\n]/, '')
  
  # ok: ruby-log-injection
  logger.warn("Request from user agent: #{sanitized_agent}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_3
  # User input from POST data sanitized before logging
  email = request.POST["email"]
  sanitized_email = email.to_s.gsub(/[\r\n]/, '_')
  
  # ok: ruby-log-injection
  logger.error("Failed login attempt for email: #{sanitized_email}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_4
  # Logging only safe, server-generated data
  timestamp = Time.now.to_s
  request_id = SecureRandom.uuid
  
  # ok: ruby-log-injection
  logger.info("Request processed at #{timestamp} with ID #{request_id}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_5
  # User input sanitized with custom function
  search_term = params[:q]
  
  def sanitize_for_logs(input)
    return "REDACTED" if input.nil?
    input.to_s.gsub(/[\r\n\t]/, ' ').slice(0, 100)
  end
  
  safe_term = sanitize_for_logs(search_term)
  
  # ok: ruby-log-injection
  Rails.logger.info("Search performed for: #{safe_term}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_6
  # Using a safe logging pattern with explicit toString
  session_id = request.cookies["session_id"].to_s.gsub(/[^\w-]/, '')
  
  # ok: ruby-log-injection
  logger.debug("Session activity: #{session_id}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_7
  # Sanitizing multiple inputs before logging
  username = params[:username].to_s.gsub(/[\r\n]/, '')
  action = params[:action].to_s.gsub(/[\r\n]/, '')
  
  # ok: ruby-log-injection
  logger.info("User #{username} performed action: #{action}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_8
  # Using a logging library's built-in sanitization
  user_input = params[:input]
  
  # Assuming a hypothetical safe_log method that sanitizes input
  def safe_log(logger, level, message, *args)
    sanitized_args = args.map { |arg| arg.to_s.gsub(/[\r\n]/, '') }
    logger.send(level, message, *sanitized_args)
  end
  
  # ok: ruby-log-injection
  safe_log(logger, :info, "User input: %s", user_input)
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_9
  # Using structured logging instead of string interpolation
  username = params[:username]
  ip = request.ip
  
  # ok: ruby-log-injection
  logger.info({ event: "user_login", username: username.to_s.gsub(/[\r\n]/, ''), ip: ip })
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_10
  # Validating input before logging
  user_id = params[:id]
  
  if user_id =~ /\A\d+\z/
    # ok: ruby-log-injection
    logger.info("Valid user ID accessed the system: #{user_id}")
  else
    logger.warn("Invalid user ID format attempted")
  end
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_11
  # Sanitizing exception messages before logging
  begin
    # Some code that might raise an exception
    raise "Error for user: #{params[:username]}"
  rescue => e
    sanitized_message = e.message.to_s.gsub(/[\r\n]/, ' ')
    
    # ok: ruby-log-injection
    logger.error("Exception occurred: #{sanitized_message}")
  end
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_12
  # Using constants or server-generated values in logs
  LOG_LEVELS = ["INFO", "WARNING", "ERROR"]
  level = LOG_LEVELS[0]
  timestamp = Time.now.to_i
  
  # ok: ruby-log-injection
  logger.info("Log entry [#{level}] at #{timestamp}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_13
  # Encoding user input before logging
  user_input = params[:comment]
  encoded_input = Base64.strict_encode64(user_input.to_s)
  
  # ok: ruby-log-injection
  logger.info("Received encoded comment: #{encoded_input}")
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_14
  # Using a whitelist approach for logging
  action = params[:action]
  allowed_actions = ["view", "edit", "delete"]
  
  if allowed_actions.include?(action)
    # ok: ruby-log-injection
    logger.info("User performed allowed action: #{action}")
  else
    logger.warn("User attempted disallowed action")
  end
end
# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_15
  # Truncating and sanitizing user input before logging
  user_data = params[:data]
  safe_data = user_data.to_s.gsub(/[\r\n]/, '')[0...50]
  
  # ok: ruby-log-injection
  logger.info("Processing data (truncated): #{safe_data}")
end
# {/fact}