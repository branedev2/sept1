# Examples for ruby-unsafe-code-construction (CWE-94)
# This file contains examples of safe and unsafe dynamic code execution in Ruby

require 'sinatra'
require 'erb'
require 'json'

# True Positive Examples (Vulnerable Code)

# Bad case 1: Using eval with user input from URL parameter
get '/bad_case_1' do
  user_input = params[:code]
  # ruleid: ruby-unsafe-code-construction
  eval(user_input)
  "Code executed"
end

# Bad case 2: Using instance_eval with user input from POST request
post '/bad_case_2' do
  request_body = JSON.parse(request.body.read)
  user_input = request_body['command']
  # ruleid: ruby-unsafe-code-construction
  Object.new.instance_eval(user_input)
  "Command executed"
end

# Bad case 3: Using class_eval with user input from query parameter
get '/bad_case_3' do
  user_input = params[:class_code]
  # ruleid: ruby-unsafe-code-construction
  String.class_eval(user_input)
  "Class modified"
end

# Bad case 4: Using module_eval with user input from form data
post '/bad_case_4' do
  user_input = params[:module_code]
  # ruleid: ruby-unsafe-code-construction
  Module.new.module_eval(user_input)
  "Module code executed"
end

# Bad case 5: Using send with user-provided method name
get '/bad_case_5' do
  method_name = params[:method]
  args = params[:args].split(',')
  obj = Object.new
  # ruleid: ruby-unsafe-code-construction
  obj.send(method_name, *args)
  "Method called"
end

# Bad case 6: Using define_method with user input
post '/bad_case_6' do
  method_name = params[:name]
  method_body = params[:body]
  # ruleid: ruby-unsafe-code-construction
  Object.define_method(method_name) do |*args|
    eval(method_body)
  end
  "Method defined"
end

# Bad case 7: Using binding.eval with user input
get '/bad_case_7' do
  user_code = params[:code]
  binding_obj = binding
  # ruleid: ruby-unsafe-code-construction
  binding_obj.eval(user_code)
  "Code executed in binding"
end

# Bad case 8: Using ERB with user input as template
post '/bad_case_8' do
  template = params[:template]
  # ruleid: ruby-unsafe-code-construction
  ERB.new(template).result(binding)
  "Template rendered"
end

# Bad case 9: Using Kernel.system with user input
get '/bad_case_9' do
  command = params[:cmd]
  # ruleid: ruby-unsafe-code-construction
  Kernel.system(command)
  "Command executed"
end

# Bad case 10: Using `eval` with string interpolation containing user input
post '/bad_case_10' do
  user_value = params[:value]
  # ruleid: ruby-unsafe-code-construction
  eval("puts #{user_value}")
  "Evaluated with interpolation"
end

# Bad case 11: Using instance_exec with user input
get '/bad_case_11' do
  user_code = params[:code]
  obj = Object.new
  # ruleid: ruby-unsafe-code-construction
  obj.instance_exec { eval(user_code) }
  "Code executed in object context"
end

# Bad case 12: Using class_exec with user input
post '/bad_case_12' do
  user_code = params[:code]
  # ruleid: ruby-unsafe-code-construction
  String.class_exec { eval(user_code) }
  "Code executed in class context"
end

# Bad case 13: Using public_send with user input
get '/bad_case_13' do
  method_name = params[:method]
  args = params[:args].split(',')
  obj = Object.new
  # ruleid: ruby-unsafe-code-construction
  obj.public_send(method_name, *args)
  "Method called via public_send"
end

# Bad case 14: Using Kernel.exec with user input
post '/bad_case_14' do
  command = params[:cmd]
  # ruleid: ruby-unsafe-code-construction
  Kernel.exec(command)
  "Command executed via exec"
end

# Bad case 15: Using `%x` syntax with user input
get '/bad_case_15' do
  command = params[:cmd]
  # ruleid: ruby-unsafe-code-construction
  result = %x(#{command})
  "Command executed via %x: #{result}"
end

# True Negative Examples (Safe Code)

# Good case 1: Using a whitelist for allowed commands
get '/good_case_1' do
  command = params[:cmd]
  allowed_commands = ['date', 'uptime', 'whoami']
  
  # ok: ruby-unsafe-code-construction
  if allowed_commands.include?(command)
    system(command)
    "Command executed safely"
  else
    "Command not allowed"
  end
end

# Good case 2: Using static code in eval
get '/good_case_2' do
  # ok: ruby-unsafe-code-construction
  eval("puts 'Hello, World!'")
  "Static code executed"
end

# Good case 3: Using ERB with static template
post '/good_case_3' do
  user_name = params[:name]
  # ok: ruby-unsafe-code-construction
  template = ERB.new("<h1>Hello, <%= h(user_name) %></h1>")
  result = template.result_with_hash(user_name: user_name)
  "Template rendered safely: #{result}"
end

# Good case 4: Using send with hardcoded method name
get '/good_case_4' do
  args = params[:args].split(',')
  obj = Object.new
  # ok: ruby-unsafe-code-construction
  obj.send(:to_s, *args)
  "Method called safely"
end

# Good case 5: Using system with command arguments as separate parameters
post '/good_case_5' do
  user_input = params[:input]
  # ok: ruby-unsafe-code-construction
  system('echo', user_input)
  "Command executed safely with arguments"
end

# Good case 6: Using define_method with static code
get '/good_case_6' do
  # ok: ruby-unsafe-code-construction
  Object.define_method(:safe_method) do |arg|
    puts "Received: #{arg}"
  end
  "Method defined safely"
end

# Good case 7: Using a case statement instead of dynamic method dispatch
post '/good_case_7' do
  action = params[:action]
  value = params[:value].to_i
  
  result = case action
  # ok: ruby-unsafe-code-construction
  when 'double'
    value * 2
  when 'square'
    value * value
  when 'increment'
    value + 1
  else
    value
  end
  
  "Result: #{result}"
end

# Good case 8: Using a hash to map user input to functions
get '/good_case_8' do
  operation = params[:op]
  x = params[:x].to_i
  y = params[:y].to_i
  
  operations = {
    'add' => ->(a, b) { a + b },
    'subtract' => ->(a, b) { a - b },
    'multiply' => ->(a, b) { a * b },
    'divide' => ->(a, b) { b.zero? ? 'Cannot divide by zero' : a / b }
  }
  
  # ok: ruby-unsafe-code-construction
  if operations.key?(operation)
    result = operations[operation].call(x, y)
    "Result: #{result}"
  else
    "Unknown operation"
  end
end

# Good case 9: Using binding.local_variable_set instead of eval
post '/good_case_9' do
  var_name = params[:var]
  var_value = params[:value]
  
  # ok: ruby-unsafe-code-construction
  binding.local_variable_set(var_name.to_sym, var_value)
  "Variable set safely"
end

# Good case 10: Using JSON.parse instead of eval for JSON
get '/good_case_10' do
  json_input = params[:json]
  
  # ok: ruby-unsafe-code-construction
  parsed_data = JSON.parse(json_input)
  "JSON parsed safely: #{parsed_data.inspect}"
end

# Good case 11: Using a template engine with escaping
post '/good_case_11' do
  user_input = params[:input]
  
  require 'erb'
  template = "<p><%= ERB::Util.html_escape(user_input) %></p>"
  
  # ok: ruby-unsafe-code-construction
  result = ERB.new(template).result(binding)
  "Template rendered safely: #{result}"
end

# Good case 12: Using respond_to? before send
get '/good_case_12' do
  method_name = params[:method]
  obj = "test string"
  
  # ok: ruby-unsafe-code-construction
  if obj.respond_to?(method_name) && !method_name.start_with?('_')
    obj.send(method_name)
    "Method called safely"
  else
    "Method not allowed"
  end
end

# Good case 13: Using static code in instance_eval
post '/good_case_13' do
  obj = Object.new
  
  # ok: ruby-unsafe-code-construction
  obj.instance_eval do
    @value = 42
    def get_value
      @value
    end
  end
  
  "Object modified safely"
end

# Good case 14: Using a DSL safely
get '/good_case_14' do
  config = Object.new
  
  # ok: ruby-unsafe-code-construction
  config.instance_eval do
    def database(name)
      @db_name = name
    end
    
    def username(user)
      @username = user
    end
    
    def password(pass)
      @password = pass
    end
  end
  
  config.instance_eval do
    database 'production_db'
    username 'app_user'
    password ENV['DB_PASSWORD']
  end
  
  "DSL used safely"
end

# Good case 15: Using a method whitelist with send
post '/good_case_15' do
  method_name = params[:method]
  args = params[:args].split(',')
  obj = "test string"
  
  safe_methods = ['upcase', 'downcase', 'capitalize', 'strip']
  
  # ok: ruby-unsafe-code-construction
  if safe_methods.include?(method_name)
    result = obj.send(method_name, *args)
    "Method called safely: #{result}"
  else
    "Method not allowed"
  end
end