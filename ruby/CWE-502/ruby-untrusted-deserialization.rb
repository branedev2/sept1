# Ruby Untrusted Deserialization Examples

require 'yaml'
require 'json'
require 'marshal'
require 'sinatra'
require 'rack'
require 'securerandom'
require 'base64'
require 'oj'
require 'psych'
require 'net/http'
require 'uri'
require 'csv'

# True Positive Examples (Vulnerable Code)

# Example 1: Using Marshal.load with user input from HTTP parameter
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_1
  get '/deserialize' do
    data = params[:data]
    # ruleid: ruby-untrusted-deserialization
    Marshal.load(data)
    "Data processed"
  end
# {/fact}
end

# Example 2: Using YAML.load with user input from request body
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_2
  post '/process_yaml' do
    request_body = request.body.read
    # ruleid: ruby-untrusted-deserialization
    result = YAML.load(request_body)
    "Processed YAML data: #{result.inspect}"
  end
# {/fact}
end

# Example 3: Using JSON.load with user input from HTTP parameter
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_3
  get '/json_process' do
    user_data = params[:json_data]
    # ruleid: ruby-untrusted-deserialization
    parsed = JSON.load(user_data)
    "JSON processed: #{parsed['name']}"
  end
# {/fact}
end

# Example 4: Using Psych.load with data from HTTP header
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_4
  get '/psych_deserialize' do
    header_data = request.env['HTTP_X_CUSTOM_DATA']
    # ruleid: ruby-untrusted-deserialization
    result = Psych.load(header_data)
    "Processed header data: #{result}"
  end
# {/fact}
end

# Example 5: Using Marshal.load with data from cookie
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_5
  get '/cookie_data' do
    cookie_data = request.cookies['user_data']
    # ruleid: ruby-untrusted-deserialization
    user_obj = Marshal.load(Base64.decode64(cookie_data))
    "Welcome back, #{user_obj[:name]}"
  end
# {/fact}
end

# Example 6: Using YAML.unsafe_load with user input
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_6
  post '/config_load' do
    config_data = params[:config]
    # ruleid: ruby-untrusted-deserialization
    config = YAML.unsafe_load(config_data)
    "Configuration loaded with #{config.keys.length} keys"
  end
# {/fact}
end

# Example 7: Using Oj.load with user input and unsafe mode
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_7
  get '/oj_process' do
    data = params[:data]
    # ruleid: ruby-untrusted-deserialization
    result = Oj.load(data, mode: :object)
    "Processed with Oj: #{result.inspect}"
  end
# {/fact}
end

# Example 8: Using Marshal.load with data from HTTP POST form
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_8
  post '/form_process' do
    serialized_data = params[:serialized]
    # ruleid: ruby-untrusted-deserialization
    obj = Marshal.load(Base64.decode64(serialized_data))
    "Form processed for: #{obj[:user]}"
  end
# {/fact}
end

# Example 9: Using YAML.load with data from URL parameter in a complex flow
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_9
  get '/process_config/:config_id' do
    config_data = params[:config_data]
    if config_data && !config_data.empty?
      begin
        # ruleid: ruby-untrusted-deserialization
        config = YAML.load(config_data)
        return "Config processed with #{config['settings'].size} settings"
      rescue => e
        return "Error: #{e.message}"
      end
    end
    "No config data provided"
  end
# {/fact}
end

# Example 10: Using Marshal.load with data from an uploaded file
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_10
  post '/upload' do
    if params[:file]
      content = params[:file][:tempfile].read
      # ruleid: ruby-untrusted-deserialization
      data = Marshal.load(content)
      "File processed with #{data.keys.join(', ')} keys"
    else
      "No file uploaded"
    end
  end
# {/fact}
end

# Example 11: Using JSON.load with user input and allowing arbitrary objects
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_11
  post '/json_objects' do
    json_data = request.body.read
    # ruleid: ruby-untrusted-deserialization
    result = JSON.load(json_data, nil, allow_nan: true, create_additions: true)
    "Processed JSON with objects: #{result.inspect}"
  end
# {/fact}
end

# Example 12: Using Marshal.load with data from an external API
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_12
  get '/external_data' do
    external_url = params[:source_url]
    response = Net::HTTP.get(URI(external_url))
    # ruleid: ruby-untrusted-deserialization
    data = Marshal.load(response)
    "External data processed: #{data.inspect}"
  end
# {/fact}
end

# Example 13: Using YAML.load in a background job with user input
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_13
  post '/schedule_job' do
    user_config = params[:config]
    # This would typically be saved and processed later, but vulnerability exists
    process_job = lambda do |config|
      # ruleid: ruby-untrusted-deserialization
      settings = YAML.load(config)
      # Process with settings...
    end
# {/fact}
    
    process_job.call(user_config)
    "Job scheduled with your configuration"
  end
end

# Example 14: Using Psych.unsafe_load with user input from query parameter
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_14
  get '/search' do
    filter = params[:filter]
    # ruleid: ruby-untrusted-deserialization
    search_params = Psych.unsafe_load(filter)
    "Search results for: #{search_params['term']}"
  end
# {/fact}
end

# Example 15: Using Marshal.load with Base64 encoded user input
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_15
  post '/import_data' do
    encoded_data = params[:encoded]
    # ruleid: ruby-untrusted-deserialization
    imported = Marshal.load(Base64.strict_decode64(encoded_data))
    "Imported #{imported.length} items"
  end
# {/fact}
end

# True Negative Examples (Safe Code)

# Example 1: Using Marshal.load with trusted, hardcoded data
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_1
  get '/default_config' do
    serialized_config = "\x04\b{\x06:\ncolor:\bred"
    # ok: ruby-untrusted-deserialization
    config = Marshal.load(serialized_config)
    "Default config loaded: #{config[:color]}"
  end
# {/fact}
end

# Example 2: Using YAML.safe_load instead of YAML.load
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_2
  post '/safe_yaml' do
    yaml_data = request.body.read
    # ok: ruby-untrusted-deserialization
    result = YAML.safe_load(yaml_data, permitted_classes: [Symbol, Time])
    "Safely processed YAML: #{result.inspect}"
  end
# {/fact}
end

# Example 3: Using JSON.parse instead of JSON.load
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_3
  get '/parse_json' do
    json_data = params[:data]
    # ok: ruby-untrusted-deserialization
    parsed = JSON.parse(json_data)
    "JSON parsed safely: #{parsed['name']}"
  end
# {/fact}
end

# Example 4: Using a whitelist approach with YAML.safe_load
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_4
  post '/config' do
    config_yaml = request.body.read
    # ok: ruby-untrusted-deserialization
    config = YAML.safe_load(config_yaml, permitted_classes: [], permitted_symbols: [], aliases: false)
    "Config loaded with #{config.keys.length} keys"
  end
# {/fact}
end

# Example 5: Using a custom deserializer that validates structure
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_5
  post '/custom_format' do
    data = params[:data]
    # Custom parsing instead of using Marshal or YAML
    # ok: ruby-untrusted-deserialization
    parsed_data = data.split(',').map { |item| item.split(':') }.to_h
    "Parsed custom format: #{parsed_data.inspect}"
  end
# {/fact}
end

# Example 6: Using Oj in safe mode
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_6
  post '/safe_oj' do
    json_data = request.body.read
    # ok: ruby-untrusted-deserialization
    result = Oj.load(json_data, mode: :strict)
    "Safely processed with Oj: #{result.inspect}"
  end
# {/fact}
end

# Example 7: Using JSON.parse with symbolize_names option
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_7
  get '/json_config' do
    config_data = params[:config]
    # ok: ruby-untrusted-deserialization
    config = JSON.parse(config_data, symbolize_names: true)
    "Config loaded with keys: #{config.keys.join(', ')}"
  end
# {/fact}
end

# Example 8: Using CSV parsing instead of deserialization
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_8
  post '/import_csv' do
    csv_data = request.body.read
    # ok: ruby-untrusted-deserialization
    records = CSV.parse(csv_data, headers: true).map(&:to_h)
    "Imported #{records.length} records"
  end
# {/fact}
end

# Example 9: Using a schema validator before parsing JSON
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_9
  post '/validated_json' do
    json_data = request.body.read
    
    # Simple schema validation
    begin
      # ok: ruby-untrusted-deserialization
      parsed = JSON.parse(json_data)
      
      # Validate expected structure
      unless parsed.is_a?(Hash) && 
             parsed['name'].is_a?(String) && 
             parsed['age'].is_a?(Integer)
        return "Invalid data structure"
      end
      
      "Valid data for #{parsed['name']}"
    rescue JSON::ParserError
      "Invalid JSON"
    end
  end
# {/fact}
end

# Example 10: Using Marshal with trusted, application-generated data
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_10
  get '/session_data' do
    # Generate our own trusted data
    session_data = {user_id: 123, permissions: ['read', 'write']}
    serialized = Marshal.dump(session_data)
    
    # Later in the code
    # ok: ruby-untrusted-deserialization
    data = Marshal.load(serialized)
    "Session loaded for user #{data[:user_id]}"
  end
# {/fact}
end

# Example 11: Using YAML.safe_load with explicit permitted classes
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_11
  post '/safe_config' do
    yaml_data = request.body.read
    # ok: ruby-untrusted-deserialization
    config = YAML.safe_load(yaml_data, 
                           permitted_classes: [Date, Time, Symbol], 
                           permitted_symbols: [:status, :environment],
                           aliases: false)
    "Config loaded safely with #{config.keys.length} keys"
  end
# {/fact}
end

# Example 12: Using a custom JSON parser with validation
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_12
  post '/validated_input' do
    input_data = params[:data]
    
    # Custom validation and parsing
    # ok: ruby-untrusted-deserialization
    begin
      parsed = JSON.parse(input_data)
      # Additional validation logic
      if parsed.is_a?(Hash) && parsed.keys.all? { |k| k =~ /\A[a-zA-Z0-9_]+\z/ }
        "Valid input with keys: #{parsed.keys.join(', ')}"
      else
        "Invalid input structure"
      end
    rescue JSON::ParserError
      "Invalid JSON format"
    end
  end
# {/fact}
end

# Example 13: Using a structured data format instead of serialization
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_13
  post '/structured_data' do
    data = params[:data]
    # Parse as structured data instead of using deserialization
    # ok: ruby-untrusted-deserialization
    lines = data.split("\n")
    result = {}
    lines.each do |line|
      key, value = line.split('=', 2)
      result[key.strip] = value.strip if key && value
    end
# {/fact}
    "Processed #{result.keys.length} items"
  end
end

# Example 14: Using JSON schema validation before parsing
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_14
  post '/schema_validated' do
    json_data = request.body.read
    
    # First parse with standard JSON parser
    begin
      parsed = JSON.parse(json_data)
      
      # Then validate against schema
      valid = parsed.is_a?(Hash) && 
              parsed.has_key?('type') && 
              parsed.has_key?('data') &&
              parsed['type'].is_a?(String) &&
              parsed['data'].is_a?(Hash)
              
      if valid
        # ok: ruby-untrusted-deserialization
        # Process the validated data
        "Valid data of type: #{parsed['type']}"
      else
        "Invalid data structure"
      end
    rescue JSON::ParserError
      "Invalid JSON"
    end
  end
# {/fact}
end

# Example 15: Using a whitelist approach for configuration
# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_15
  post '/whitelist_config' do
    config_data = params[:config]
    
    begin
      # Parse the JSON
      # ok: ruby-untrusted-deserialization
      parsed = JSON.parse(config_data)
      
      # Only extract known keys with type checking
      safe_config = {}
      safe_config[:name] = parsed['name'] if parsed['name'].is_a?(String)
      safe_config[:timeout] = parsed['timeout'].to_i if parsed['timeout'].is_a?(Numeric)
      safe_config[:enabled] = !!parsed['enabled'] # Convert to boolean
      
      "Config processed with keys: #{safe_config.keys.join(', ')}"
    rescue JSON::ParserError
      "Invalid configuration format"
    end
  end
# {/fact}
end