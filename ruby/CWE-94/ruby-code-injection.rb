# Ruby Code Injection Examples
require 'sinatra'
require 'erb'

# True Positive Examples (Vulnerable Code)

# Example 1: Using eval with user input from params
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  user_input = params[:code]
  # ruleid: ruby-code-injection
  eval(user_input)
end
# {/fact}

# Example 2: Using instance_eval with user input from request body
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  user_input = request.body.read
  obj = Object.new
  # ruleid: ruby-code-injection
  obj.instance_eval(user_input)
end
# {/fact}

# Example 3: Using class_eval with user input from query parameter
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  user_input = params[:command]
  # ruleid: ruby-code-injection
  String.class_eval(user_input)
end
# {/fact}

# Example 4: Using send with user input for method name
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  method_name = params[:method]
  args = params[:args]
  obj = Object.new
  # ruleid: ruby-code-injection
  obj.send(method_name, args)
end
# {/fact}

# Example 5: Using system with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  command = params[:cmd]
  # ruleid: ruby-code-injection
  system(command)
end
# {/fact}

# Example 6: Using backticks for command execution with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  command = request.env['HTTP_X_CUSTOM_HEADER']
  # ruleid: ruby-code-injection
  result = `#{command}`
  return result
end
# {/fact}

# Example 7: Using ERB to evaluate user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  template = params[:template]
  renderer = ERB.new(template)
  # ruleid: ruby-code-injection
  result = renderer.result(binding)
  return result
end
# {/fact}

# Example 8: Using define_method with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  method_name = params[:method_name]
  method_body = params[:method_body]
  # ruleid: ruby-code-injection
  self.class.send(:define_method, method_name) do
    eval(method_body)
  end
# {/fact}
end

# Example 9: Using public_send with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  method_name = params[:action]
  args = params[:arguments]
  obj = Object.new
  # ruleid: ruby-code-injection
  obj.public_send(method_name, args)
end
# {/fact}

# Example 10: Using Kernel.const_get with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  class_name = params[:class]
  # ruleid: ruby-code-injection
  klass = Kernel.const_get(class_name)
  klass.new
end
# {/fact}

# Example 11: Using module_eval with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  code = request.cookies['code']
  # ruleid: ruby-code-injection
  Module.module_eval(code)
end
# {/fact}

# Example 12: Using IO.popen with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  command = params[:command]
  # ruleid: ruby-code-injection
  IO.popen(command) do |io|
    result = io.read
  end
# {/fact}
end

# Example 13: Using Kernel.exec with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  command = request.env['HTTP_COMMAND']
  # ruleid: ruby-code-injection
  Kernel.exec(command)
end
# {/fact}

# Example 14: Using binding.eval with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  code = params[:script]
  # ruleid: ruby-code-injection
  binding.eval(code)
end
# {/fact}

# Example 15: Using method_missing to dynamically call methods based on user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  method_name = params[:method]
  args = params[:args]
  
  def method_missing(name, *args)
    # ruleid: ruby-code-injection
    eval("#{name}(#{args.join(',')})")
  end
  
  send(method_name, args)
end
# {/fact}

# True Negative Examples (Safe Code)

# Example 1: Using a whitelist for eval
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  allowed_commands = ['puts "Hello"', 'puts "World"']
  user_input = params[:code]
  
  # ok: ruby-code-injection
  if allowed_commands.include?(user_input)
    eval(user_input)
  else
    puts "Command not allowed"
  end
end
# {/fact}

# Example 2: Using case statement instead of dynamic method dispatch
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  action = params[:action]
  
  # ok: ruby-code-injection
  case action
  when 'create'
    create_resource
  when 'update'
    update_resource
  when 'delete'
    delete_resource
  else
    default_action
  end
end
# {/fact}

# Example 3: Using a hash to map user input to methods
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  action = params[:action]
  
  actions = {
    'create' => method(:create_resource),
    'update' => method(:update_resource),
    'delete' => method(:delete_resource)
  }
  
  # ok: ruby-code-injection
  if actions.key?(action)
    actions[action].call
  else
    default_action
  end
end
# {/fact}

# Example 4: Using safe template rendering with variables
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  user_name = params[:name]
  template = "Hello, <%= name %>"
  
  # ok: ruby-code-injection
  renderer = ERB.new(template)
  result = renderer.result_with_hash(name: user_name)
  return result
end
# {/fact}

# Example 5: Using system with hardcoded command and sanitized arguments
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  filename = params[:filename]
  sanitized_filename = filename.gsub(/[^a-zA-Z0-9._-]/, '')
  
  # ok: ruby-code-injection
  system("ls", sanitized_filename)
end
# {/fact}

# Example 6: Using a predefined set of methods for send
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  method_name = params[:method]
  allowed_methods = ['to_s', 'to_i', 'to_f']
  obj = "test"
  
  # ok: ruby-code-injection
  if allowed_methods.include?(method_name)
    obj.send(method_name)
  else
    "Method not allowed"
  end
end
# {/fact}

# Example 7: Using Open3 with command array to prevent shell injection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  require 'open3'
  
  filename = params[:filename]
  sanitized_filename = filename.gsub(/[^a-zA-Z0-9._-]/, '')
  
  # ok: ruby-code-injection
  stdout, stderr, status = Open3.capture3('ls', sanitized_filename)
  return stdout
end
# {/fact}

# Example 8: Using safe constant lookup with validation
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  class_name = params[:class]
  allowed_classes = ['String', 'Array', 'Hash']
  
  # ok: ruby-code-injection
  if allowed_classes.include?(class_name)
    klass = Object.const_get(class_name)
    klass.new
  else
    "Class not allowed"
  end
end
# {/fact}

# Example 9: Using a command builder pattern
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  command_builder = CommandBuilder.new
  action = params[:action]
  
  # ok: ruby-code-injection
  if action == 'list'
    command_builder.list_files
  elsif action == 'count'
    command_builder.count_files
  else
    command_builder.default_action
  end
end
# {/fact}

# Example 10: Using safe template rendering with explicit variables
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  user_name = params[:name]
  template = ERB.new("<p>Hello, <%= name %></p>")
  
  # ok: ruby-code-injection
  result = template.result_with_hash(name: user_name)
  return result
end
# {/fact}

# Example 11: Using a configuration file instead of dynamic code
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  config = YAML.load_file('config.yml')
  action = params[:action]
  
  # ok: ruby-code-injection
  if config['allowed_actions'].include?(action)
    perform_action(action)
  else
    "Action not allowed"
  end
end
# {/fact}

# Example 12: Using a safe subprocess execution
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  require 'open3'
  
  user_input = params[:input]
  sanitized_input = user_input.gsub(/[^a-zA-Z0-9]/, '')
  
  # ok: ruby-code-injection
  stdout, stderr, status = Open3.capture3('./safe_script.rb', sanitized_input)
  return stdout
end
# {/fact}

# Example 13: Using a DSL instead of eval
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  expression = params[:expression]
  parser = ExpressionParser.new
  
  # ok: ruby-code-injection
  result = parser.parse_and_evaluate(expression)
  return result
end
# {/fact}

# Example 14: Using reflection safely with type checking
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  method_name = params[:method]
  obj = SomeClass.new
  
  # ok: ruby-code-injection
  if obj.respond_to?(method_name) && !Object.instance_methods.include?(method_name.to_sym)
    obj.public_send(method_name)
  else
    "Method not available"
  end
end
# {/fact}

# Example 15: Using a strategy pattern instead of dynamic code
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  strategy_name = params[:strategy]
  strategies = {
    'fast' => FastStrategy.new,
    'secure' => SecureStrategy.new,
    'balanced' => BalancedStrategy.new
  }
  
  # ok: ruby-code-injection
  if strategies.key?(strategy_name)
    strategies[strategy_name].execute
  else
    default_strategy.execute
  end
end
# {/fact}

# Helper classes for true negative examples
class CommandBuilder
  def list_files
    # Safe implementation
    Dir.entries('.')
  end
  
  def count_files
    # Safe implementation
    Dir.entries('.').size
  end
  
  def default_action
    # Safe implementation
    "No action specified"
  end
end

class ExpressionParser
  def parse_and_evaluate(expression)
    # Safe implementation that doesn't use eval
    # This would be a custom parser for a limited expression language
    "Result of parsing #{expression}"
  end
end

class FastStrategy
  def execute
    "Executing fast strategy"
  end
end

class SecureStrategy
  def execute
    "Executing secure strategy"
  end
end

class BalancedStrategy
  def execute
    "Executing balanced strategy"
  end
end

# Helper methods for examples
def create_resource
  "Resource created"
end

def update_resource
  "Resource updated"
end

def delete_resource
  "Resource deleted"
end

def default_action
  "Default action performed"
end

def perform_action(action)
  "Performing #{action}"
end