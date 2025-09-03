# True Positives (Vulnerable Code)

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  require 'sinatra'
  
  get '/execute' do
    method_name = params[:method]
    # ruleid: ruby-untrusted-send
    Object.send(method_name)
    "Method executed"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  require 'rails'
  
  class UserController < ApplicationController
    def process_action
      action = params[:action_name]
      # ruleid: ruby-untrusted-send
      self.send(action)
      render json: { success: true }
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  require 'sinatra'
  
  post '/user/update' do
    user = User.find(params[:id])
    field = params[:field]
    value = params[:value]
    # ruleid: ruby-untrusted-send
    user.send("#{field}=", value)
    user.save
    "User updated"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  require 'rack'
  
  class DynamicProcessor
    def call(env)
      request = Rack::Request.new(env)
      operation = request.params['operation']
      # ruleid: ruby-untrusted-send
      result = self.send(operation)
      [200, {"Content-Type" => "text/plain"}, [result.to_s]]
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  require 'sinatra'
  
  get '/api/v1/data' do
    format = params[:format] || 'json'
    data = { name: 'John', age: 30 }
    # ruleid: ruby-untrusted-send
    self.send("render_#{format}", data)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  require 'rails'
  
  class AdminController < ApplicationController
    def execute_command
      cmd = params[:command]
      args = params[:args]
      # ruleid: ruby-untrusted-send
      Object.send(cmd, *args)
      redirect_to admin_path, notice: 'Command executed'
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  require 'sinatra'
  
  post '/calculator' do
    num1 = params[:num1].to_i
    num2 = params[:num2].to_i
    operation = params[:operation]
    calculator = Calculator.new
    # ruleid: ruby-untrusted-send
    result = calculator.send(operation, num1, num2)
    "Result: #{result}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  require 'rails'
  
  class ReportController < ApplicationController
    def generate
      report_type = params[:type]
      data = collect_data()
      # ruleid: ruby-untrusted-send
      report = self.try(report_type, data)
      send_data report, filename: "report.pdf"
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  require 'sinatra'
  
  class ApiHandler
    def handle_request(request)
      action = request.params['action']
      data = request.params['data']
      # ruleid: ruby-untrusted-send
      public_send(action, data)
    end
  end
  
  post '/api' do
    handler = ApiHandler.new
    handler.handle_request(request)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  require 'rack'
  
  class DynamicRouter
    def route(env)
      request = Rack::Request.new(env)
      controller = request.params['controller']
      action = request.params['action']
      
      controller_obj = Object.const_get(controller).new
      # ruleid: ruby-untrusted-send
      result = controller_obj.send(action, request.params)
      [200, {"Content-Type" => "text/html"}, [result]]
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  require 'sinatra'
  
  helpers do
    def dynamic_helper
      method = params[:helper_method]
      # ruleid: ruby-untrusted-send
      send(method)
    end
  end
# {/fact}
  
  get '/helper' do
    dynamic_helper
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  require 'rails'
  
  class ConfigController < ApplicationController
    def update_setting
      setting = params[:setting]
      value = params[:value]
      config = AppConfig.instance
      # ruleid: ruby-untrusted-send
      config.send("#{setting}=", value)
      redirect_to config_path, notice: 'Setting updated'
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  require 'sinatra'
  
  class UserPreferences
    def update_from_request(request)
      preference = request.params['preference']
      value = request.params['value']
      # ruleid: ruby-untrusted-send
      send("update_#{preference}", value)
    end
  end
  
  post '/preferences' do
    prefs = UserPreferences.new
    prefs.update_from_request(request)
    "Preferences updated"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  require 'rack'
  
  class EventHandler
    def process(env)
      request = Rack::Request.new(env)
      event_type = request.params['event']
      data = request.params['data']
      # ruleid: ruby-untrusted-send
      self.send("handle_#{event_type}", data)
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  require 'sinatra'
  
  class DataFormatter
    def format_data(request)
      format = request.params['format']
      data = get_data()
      # ruleid: ruby-untrusted-send
      formatted_data = send("format_as_#{format}", data)
      return formatted_data
    end
  end
  
  get '/data' do
    formatter = DataFormatter.new
    formatter.format_data(request)
  end
# {/fact}
end

# True Negatives (Safe Code)

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  require 'sinatra'
  
  get '/execute' do
    method_name = params[:method]
    # ok: ruby-untrusted-send
    allowed_methods = ['get_public_data', 'format_output', 'calculate_total']
    if allowed_methods.include?(method_name)
      send(method_name)
    else
      "Method not allowed"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  require 'rails'
  
  class UserController < ApplicationController
    def process_action
      action = params[:action_name]
      # ok: ruby-untrusted-send
      allowed_actions = ['show', 'list', 'search']
      if allowed_actions.include?(action)
        self.send(action)
      else
        render json: { error: "Action not allowed" }, status: 403
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  require 'sinatra'
  
  post '/user/update' do
    user = User.find(params[:id])
    field = params[:field]
    value = params[:value]
    # ok: ruby-untrusted-send
    allowed_fields = ['name', 'email', 'preferences']
    if allowed_fields.include?(field)
      user.send("#{field}=", value)
      user.save
      "User updated"
    else
      status 403
      "Field update not allowed"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  require 'rack'
  
  class DynamicProcessor
    def call(env)
      request = Rack::Request.new(env)
      operation = request.params['operation']
      # ok: ruby-untrusted-send
      operations = {
        'add' => method(:add),
        'subtract' => method(:subtract),
        'multiply' => method(:multiply)
      }
      
      if operations.key?(operation)
        result = operations[operation].call
        [200, {"Content-Type" => "text/plain"}, [result.to_s]]
      else
        [403, {"Content-Type" => "text/plain"}, ["Operation not allowed"]]
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  require 'sinatra'
  
  get '/api/v1/data' do
    format = params[:format] || 'json'
    data = { name: 'John', age: 30 }
    # ok: ruby-untrusted-send
    allowed_formats = ['json', 'xml', 'csv']
    if allowed_formats.include?(format)
      send("render_#{format}", data)
    else
      status 400
      "Unsupported format"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  require 'rails'
  
  class AdminController < ApplicationController
    ALLOWED_COMMANDS = ['refresh_cache', 'update_index', 'generate_report']
    
    def execute_command
      cmd = params[:command]
      # ok: ruby-untrusted-send
      if ALLOWED_COMMANDS.include?(cmd)
        self.send(cmd)
        redirect_to admin_path, notice: 'Command executed'
      else
        redirect_to admin_path, alert: 'Command not allowed'
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  require 'sinatra'
  
  post '/calculator' do
    num1 = params[:num1].to_i
    num2 = params[:num2].to_i
    operation = params[:operation]
    calculator = Calculator.new
    # ok: ruby-untrusted-send
    valid_operations = ['add', 'subtract', 'multiply', 'divide']
    if valid_operations.include?(operation)
      result = calculator.send(operation, num1, num2)
      "Result: #{result}"
    else
      status 400
      "Invalid operation"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  require 'rails'
  
  class ReportController < ApplicationController
    VALID_REPORT_TYPES = ['pdf_report', 'csv_report', 'excel_report']
    
    def generate
      report_type = params[:type]
      data = collect_data()
      # ok: ruby-untrusted-send
      if VALID_REPORT_TYPES.include?(report_type)
        report = self.send(report_type, data)
        send_data report, filename: "report.pdf"
      else
        render json: { error: "Invalid report type" }, status: 400
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  require 'sinatra'
  
  class ApiHandler
    def handle_request(request)
      action = request.params['action']
      data = request.params['data']
      # ok: ruby-untrusted-send
      whitelist = {
        'get_users' => method(:get_users),
        'get_products' => method(:get_products),
        'search' => method(:search)
      }
      
      if whitelist.key?(action)
        whitelist[action].call(data)
      else
        { error: "Action not allowed" }
      end
    end
  end
  
  post '/api' do
    handler = ApiHandler.new
    handler.handle_request(request)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  require 'rack'
  
  class DynamicRouter
    def route(env)
      request = Rack::Request.new(env)
      controller = request.params['controller']
      action = request.params['action']
      
      # ok: ruby-untrusted-send
      valid_controllers = ['UsersController', 'ProductsController', 'OrdersController']
      valid_actions = ['index', 'show', 'search']
      
      if valid_controllers.include?(controller) && valid_actions.include?(action)
        controller_obj = Object.const_get(controller).new
        result = controller_obj.send(action, request.params)
        [200, {"Content-Type" => "text/html"}, [result]]
      else
        [403, {"Content-Type" => "text/html"}, ["Not allowed"]]
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  require 'sinatra'
  
  helpers do
    def dynamic_helper
      method = params[:helper_method]
      # ok: ruby-untrusted-send
      valid_helpers = ['format_date', 'format_currency', 'format_name']
      if valid_helpers.include?(method)
        send(method)
      else
        "Invalid helper method"
      end
    end
  end
# {/fact}
  
  get '/helper' do
    dynamic_helper
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  require 'rails'
  
  class ConfigController < ApplicationController
    ALLOWED_SETTINGS = ['theme', 'language', 'timezone']
    
    def update_setting
      setting = params[:setting]
      value = params[:value]
      config = AppConfig.instance
      # ok: ruby-untrusted-send
      if ALLOWED_SETTINGS.include?(setting)
        config.send("#{setting}=", value)
        redirect_to config_path, notice: 'Setting updated'
      else
        redirect_to config_path, alert: 'Setting update not allowed'
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  require 'sinatra'
  
  class UserPreferences
    VALID_PREFERENCES = ['notification', 'theme', 'privacy']
    
    def update_from_request(request)
      preference = request.params['preference']
      value = request.params['value']
      # ok: ruby-untrusted-send
      if VALID_PREFERENCES.include?(preference)
        send("update_#{preference}", value)
      else
        raise "Invalid preference"
      end
    end
  end
  
  post '/preferences' do
    begin
      prefs = UserPreferences.new
      prefs.update_from_request(request)
      "Preferences updated"
    rescue => e
      status 400
      e.message
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  require 'rack'
  
  class EventHandler
    def process(env)
      request = Rack::Request.new(env)
      event_type = request.params['event']
      data = request.params['data']
      # ok: ruby-untrusted-send
      valid_events = ['click', 'view', 'purchase']
      
      if valid_events.include?(event_type)
        self.send("handle_#{event_type}", data)
      else
        "Invalid event type"
      end
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  require 'sinatra'
  
  class DataFormatter
    def format_data(request)
      format = request.params['format']
      data = get_data()
      # ok: ruby-untrusted-send
      case format
      when 'json'
        format_as_json(data)
      when 'xml'
        format_as_xml(data)
      when 'csv'
        format_as_csv(data)
      else
        raise "Unsupported format"
      end
    end
  end
  
  get '/data' do
    begin
      formatter = DataFormatter.new
      formatter.format_data(request)
    rescue => e
      status 400
      e.message
    end
  end
# {/fact}
end