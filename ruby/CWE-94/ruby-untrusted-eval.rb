# Examples of vulnerable and safe uses of eval in Ruby

# True Positives (Vulnerable Code)

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  require 'sinatra'
  
  get '/execute' do
    code = params[:code]
    # ruleid: ruby-untrusted-eval
    eval(code)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  require 'sinatra'
  
  post '/calculate' do
    expression = request.body.read
    result = nil
    # ruleid: ruby-untrusted-eval
    result = eval(expression)
    "Result: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  require 'rack'
  
  class EvalApp
    def call(env)
      req = Rack::Request.new(env)
      user_input = req.params['command']
      
      # ruleid: ruby-untrusted-eval
      output = eval(user_input)
      
      [200, {"Content-Type" => "text/plain"}, [output.to_s]]
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  require 'sinatra'
  
  get '/dynamic-method' do
    method_name = params[:method]
    args = params[:args]
    
    # ruleid: ruby-untrusted-eval
    eval("#{method_name}(#{args})")
    
    "Method executed"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  require 'webrick'
  
  server = WEBrick::HTTPServer.new(Port: 8000)
  server.mount_proc '/eval' do |req, res|
    user_code = req.query['code']
    
    # ruleid: ruby-untrusted-eval
    result = eval(user_code)
    
    res.body = "Result: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  require 'sinatra'
  
  post '/template' do
    template = request.body.read
    data = { name: "User", age: 30 }
    
    # ruleid: ruby-untrusted-eval
    result = eval("\"#{template}\"")
    
    "Rendered: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  require 'sinatra'
  
  get '/config' do
    config_key = params[:key]
    config_value = params[:value]
    
    # ruleid: ruby-untrusted-eval
    eval("@#{config_key} = #{config_value}")
    
    "Configuration updated"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  require 'rack'
  
  class DynamicController
    def initialize(app)
      @app = app
    end
    
    def call(env)
      req = Rack::Request.new(env)
      if req.path.start_with?('/dynamic/')
        controller_action = req.path.sub('/dynamic/', '')
        # ruleid: ruby-untrusted-eval
        eval("process_#{controller_action}(req)")
      else
        @app.call(env)
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  require 'sinatra'
  
  helpers do
    def dynamic_helper
      code = params[:helper_code]
      # ruleid: ruby-untrusted-eval
      eval(code)
    end
  end
# {/fact}
  
  get '/helper' do
    dynamic_helper.to_s
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  require 'sinatra'
  
  get '/math' do
    expression = params[:expr]
    # Attempt to sanitize but still vulnerable
    if expression =~ /^[0-9\+\-\*\/\(\) ]+$/
      # ruleid: ruby-untrusted-eval
      result = eval(expression)
      "Result: #{result}"
    else
      "Invalid expression"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  require 'sinatra'
  
  post '/execute-with-context' do
    user_code = request.body.read
    context = { user: current_user, data: load_data }
    
    # ruleid: ruby-untrusted-eval
    result = eval(user_code, binding)
    
    "Executed with result: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  require 'rack'
  
  class CodeExecutor
    def call(env)
      req = Rack::Request.new(env)
      
      if req.post? && req.path == '/execute'
        code = req.params['code']
        output = StringIO.new
        original_stdout = $stdout
        $stdout = output
        
        begin
          # ruleid: ruby-untrusted-eval
          eval(code)
        ensure
          $stdout = original_stdout
        end
        
        [200, {"Content-Type" => "text/plain"}, [output.string]]
      else
        [404, {"Content-Type" => "text/plain"}, ["Not Found"]]
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  require 'sinatra'
  
  get '/dynamic-class' do
    class_name = params[:class]
    method_name = params[:method]
    args = params[:args]
    
    # ruleid: ruby-untrusted-eval
    eval("#{class_name}.new.#{method_name}(#{args})")
    
    "Method called"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  require 'sinatra'
  
  get '/indirect-eval' do
    user_input = params[:input]
    code_to_run = "result = #{user_input}"
    
    # ruleid: ruby-untrusted-eval
    eval(code_to_run)
    
    "Result: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  require 'webrick'
  
  class EvalHandler < WEBrick::HTTPServlet::AbstractServlet
    def do_GET(request, response)
      code = request.query['code']
      response.status = 200
      response.content_type = "text/plain"
      
      # ruleid: ruby-untrusted-eval
      result = eval(code)
      
      response.body = result.to_s
    end
  end
end
# {/fact}

# True Negatives (Safe Code)

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  require 'sinatra'
  
  get '/calculate' do
    expression = params[:expr]
    # ok: ruby-untrusted-eval
    result = calculate_safely(expression)
    "Result: #{result}"
  end
# {/fact}
  
  def calculate_safely(expr)
    # Parse and evaluate math expressions safely without eval
    allowed_operators = {'+' => ->(a,b) { a + b }, '-' => ->(a,b) { a - b }}
    parts = expr.split(/([+\-])/)
    # Simple implementation for demonstration
    parts[0].to_i + parts[2].to_i
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  require 'sinatra'
  
  post '/execute' do
    command = request.body.read
    # ok: ruby-untrusted-eval
    case command
    when "list_users"
      User.all.to_json
    when "system_status"
      { status: "online", uptime: 3600 }.to_json
    else
      { error: "Unknown command" }.to_json
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  require 'rack'
  
  class SafeApp
    def call(env)
      req = Rack::Request.new(env)
      user_input = req.params['command']
      
      # ok: ruby-untrusted-eval
      output = execute_safe_command(user_input)
      
      [200, {"Content-Type" => "text/plain"}, [output.to_s]]
    end
    
    def execute_safe_command(cmd)
      whitelist = {
        "hello" => "Hello, World!",
        "time" => Time.now.to_s
      }
      whitelist[cmd] || "Command not found"
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  require 'sinatra'
  
  get '/dynamic-method' do
    method_name = params[:method]
    args = params[:args].to_i
    
    # ok: ruby-untrusted-eval
    if method_name == "square"
      square(args)
    elsif method_name == "double"
      double(args)
    else
      "Method not allowed"
    end
  end
# {/fact}
  
  def square(n)
    n * n
  end
  
  def double(n)
    n * 2
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  require 'webrick'
  
  server = WEBrick::HTTPServer.new(Port: 8000)
  server.mount_proc '/calculate' do |req, res|
    expression = req.query['expr']
    
    # ok: ruby-untrusted-eval
    calculator = SafeCalculator.new
    result = calculator.evaluate(expression)
    
    res.body = "Result: #{result}"
  end
# {/fact}
  
  class SafeCalculator
    def evaluate(expr)
      # Simple safe calculator implementation
      if expr =~ /^[0-9+\-*\/() ]+$/
        # Use a safer approach than eval
        expr.gsub!(/[^0-9+\-*\/() ]/, '')  # Extra safety
        
        # Simple implementation for demonstration
        if expr.include?('+')
          parts = expr.split('+')
          parts[0].to_i + parts[1].to_i
        else
          0
        end
      else
        "Invalid expression"
      end
    end
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  require 'sinatra'
  
  post '/template' do
    template = request.body.read
    data = { name: "User", age: 30 }
    
    # ok: ruby-untrusted-eval
    # Using ERB instead of eval for templating
    require 'erb'
    renderer = ERB.new(template)
    result = renderer.result(binding)
    
    "Rendered: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  require 'sinatra'
  
  get '/config' do
    config_key = params[:key]
    config_value = params[:value]
    
    # ok: ruby-untrusted-eval
    # Using a whitelist for configuration keys
    allowed_keys = ["theme", "language", "timezone"]
    if allowed_keys.include?(config_key)
      settings[config_key.to_sym] = config_value
      "Configuration updated"
    else
      "Invalid configuration key"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  require 'rack'
  
  class SafeDynamicController
    def initialize(app)
      @app = app
    end
    
    def call(env)
      req = Rack::Request.new(env)
      if req.path.start_with?('/dynamic/')
        controller_action = req.path.sub('/dynamic/', '')
        
        # ok: ruby-untrusted-eval
        # Using a dispatch table instead of eval
        actions = {
          "users" => method(:process_users),
          "products" => method(:process_products)
        }
        
        if actions.key?(controller_action)
          actions[controller_action].call(req)
        else
          [404, {"Content-Type" => "text/plain"}, ["Not Found"]]
        end
      else
        @app.call(env)
      end
    end
    
    def process_users(req)
      [200, {"Content-Type" => "text/plain"}, ["Processing users"]]
    end
    
    def process_products(req)
      [200, {"Content-Type" => "text/plain"}, ["Processing products"]]
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  require 'sinatra'
  
  helpers do
    def safe_helper
      code = params[:helper_code]
      # ok: ruby-untrusted-eval
      # Using a whitelist of allowed helper functions
      helpers = {
        "format_date" => -> { Time.now.strftime("%Y-%m-%d") },
        "user_count" => -> { User.count }
      }
      
      if helpers.key?(code)
        helpers[code].call
      else
        "Unknown helper"
      end
    end
  end
# {/fact}
  
  get '/helper' do
    safe_helper.to_s
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  require 'sinatra'
  
  get '/math' do
    expression = params[:expr]
    
    # ok: ruby-untrusted-eval
    # Using a math parser gem instead of eval
    require 'dentaku'
    calculator = Dentaku::Calculator.new
    begin
      result = calculator.evaluate(expression)
      "Result: #{result}"
    rescue => e
      "Error: Invalid expression"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  require 'sinatra'
  
  post '/execute-with-context' do
    user_code = request.body.read
    
    # ok: ruby-untrusted-eval
    # Using a sandbox environment
    require 'sandbox'
    sandbox = Sandbox.safe
    result = sandbox.eval(user_code)
    
    "Executed with result: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  require 'rack'
  
  class SafeCodeExecutor
    def call(env)
      req = Rack::Request.new(env)
      
      if req.post? && req.path == '/execute'
        code_type = req.params['type']
        args = req.params['args']
        
        # ok: ruby-untrusted-eval
        # Using a command pattern instead of eval
        commands = {
          "list_files" => -> (dir) { Dir.entries(dir || ".").join(", ") },
          "word_count" => -> (text) { text.to_s.split.size }
        }
        
        if commands.key?(code_type)
          result = commands[code_type].call(args)
          [200, {"Content-Type" => "text/plain"}, [result.to_s]]
        else
          [400, {"Content-Type" => "text/plain"}, ["Unknown command"]]
        end
      else
        [404, {"Content-Type" => "text/plain"}, ["Not Found"]]
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  require 'sinatra'
  
  get '/dynamic-class' do
    class_name = params[:class]
    method_name = params[:method]
    args = params[:args].to_i
    
    # ok: ruby-untrusted-eval
    # Using a factory pattern with whitelist
    allowed_classes = {
      "calculator" => Calculator,
      "formatter" => Formatter
    }
    
    if allowed_classes.key?(class_name) && method_name == "process"
      allowed_classes[class_name].new.process(args)
    else
      "Invalid request"
    end
  end
# {/fact}
  
  class Calculator
    def process(n)
      n * n
    end
  end
  
  class Formatter
    def process(n)
      "Value: #{n}"
    end
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  require 'sinatra'
  
  get '/indirect-eval' do
    user_input = params[:input].to_i
    
    # ok: ruby-untrusted-eval
    # Using direct computation instead of eval
    result = user_input * 2
    
    "Result: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  require 'webrick'
  
  class SafeHandler < WEBrick::HTTPServlet::AbstractServlet
    def do_GET(request, response)
      code = request.query['code']
      response.status = 200
      response.content_type = "text/plain"
      
      # ok: ruby-untrusted-eval
      # Using a command registry instead of eval
      commands = {
        "time" => -> { Time.now.to_s },
        "rand" => -> { rand(100) },
        "hostname" => -> { `hostname`.strip }
      }
      
      if commands.key?(code)
        result = commands[code].call
      else
        result = "Unknown command"
      end
      
      response.body = result.to_s
    end
  end
end
# {/fact}