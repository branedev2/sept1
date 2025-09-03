# This file contains examples of safe and unsafe reflection in Ruby
# Unsafe reflection occurs when user-controlled input is used in reflection methods like
# Object.const_get, eval, send, etc., which can lead to code execution vulnerabilities.

require 'sinatra'
require 'json'

# True Positive Examples (Vulnerable Code)

# Example 1: Using const_get with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  get '/api/v1/resource' do
    resource_name = params[:resource]
    # ruleid: ruby-unsafe-reflection
    resource_class = Object.const_get(resource_name)
    resource_class.find(params[:id]).to_json
  end
# {/fact}
end

# Example 2: Using send with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  post '/api/v1/execute' do
    method_name = params[:method]
    args = params[:args]
    obj = MyClass.new
    # ruleid: ruby-unsafe-reflection
    result = obj.send(method_name, *args)
    { result: result }.to_json
  end
# {/fact}
end

# Example 3: Using eval with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  get '/calculate' do
    expression = params[:expr]
    # ruleid: ruby-unsafe-reflection
    result = eval(expression)
    "Result: #{result}"
  end
# {/fact}
end

# Example 4: Using class_eval with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  post '/update_model' do
    model_name = params[:model]
    code = params[:code]
    model = Object.const_get(model_name)
    # ruleid: ruby-unsafe-reflection
    model.class_eval(code)
    "Model updated"
  end
# {/fact}
end

# Example 5: Using instance_eval with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  put '/configure/:id' do
    obj = MyObject.find(params[:id])
    config_code = params[:config]
    # ruleid: ruby-unsafe-reflection
    obj.instance_eval(config_code)
    "Object configured"
  end
# {/fact}
end

# Example 6: Using define_method with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  post '/add_method' do
    method_name = params[:method_name]
    method_body = params[:method_body]
    
    MyClass.class_eval do
      # ruleid: ruby-unsafe-reflection
      define_method(method_name) do |*args|
        eval(method_body)
      end
# {/fact}
    end
    
    "Method added"
  end
end

# Example 7: Using public_send with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  get '/api/call' do
    method = params[:method]
    args = JSON.parse(params[:args] || '[]')
    service = ApiService.new
    # ruleid: ruby-unsafe-reflection
    result = service.public_send(method, *args)
    result.to_json
  end
# {/fact}
end

# Example 8: Using constantize (Rails method) with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  get '/models/:model_name' do
    model_name = params[:model_name]
    # ruleid: ruby-unsafe-reflection
    model = model_name.constantize
    model.all.to_json
  end
# {/fact}
end

# Example 9: Using Module.const_get with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  get '/module/class' do
    module_name = params[:module]
    class_name = params[:class]
    # ruleid: ruby-unsafe-reflection
    mod = Module.const_get(module_name)
    # ruleid: ruby-unsafe-reflection
    klass = mod.const_get(class_name)
    klass.new.to_json
  end
# {/fact}
end

# Example 10: Using instance_variable_get with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  get '/object/attribute' do
    obj = SomeObject.new
    var_name = params[:var_name]
    # ruleid: ruby-unsafe-reflection
    value = obj.instance_variable_get("@#{var_name}")
    { value: value }.to_json
  end
# {/fact}
end

# Example 11: Using method with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  get '/call_method' do
    obj = MyObject.new
    method_name = params[:method]
    # ruleid: ruby-unsafe-reflection
    method_obj = obj.method(method_name)
    result = method_obj.call
    "Result: #{result}"
  end
# {/fact}
end

# Example 12: Using class_exec with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  post '/extend_class' do
    class_name = params[:class]
    code_block = params[:code]
    klass = Object.const_get(class_name)
    # ruleid: ruby-unsafe-reflection
    klass.class_exec { eval(code_block) }
    "Class extended"
  end
# {/fact}
end

# Example 13: Using instance_exec with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  put '/execute_on_instance/:id' do
    obj = SomeClass.find(params[:id])
    code = params[:code]
    # ruleid: ruby-unsafe-reflection
    obj.instance_exec { eval(code) }
    "Executed code on instance"
  end
# {/fact}
end

# Example 14: Using Object.const_set with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  post '/define_constant' do
    const_name = params[:name]
    const_value = params[:value]
    # ruleid: ruby-unsafe-reflection
    Object.const_set(const_name, eval(const_value))
    "Constant defined"
  end
# {/fact}
end

# Example 15: Using Module#module_eval with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  post '/modify_module' do
    module_name = params[:module]
    code = params[:code]
    mod = Object.const_get(module_name)
    # ruleid: ruby-unsafe-reflection
    mod.module_eval(code)
    "Module modified"
  end
# {/fact}
end

# True Negative Examples (Safe Code)

# Example 1: Using const_get with hardcoded value
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  get '/api/v1/users' do
    # ok: ruby-unsafe-reflection
    resource_class = Object.const_get("User")
    resource_class.find(params[:id]).to_json
  end
# {/fact}
end

# Example 2: Using send with hardcoded method name
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  post '/api/v1/users/activate' do
    user = User.find(params[:id])
    # ok: ruby-unsafe-reflection
    result = user.send(:activate, params[:reason])
    { success: result }.to_json
  end
# {/fact}
end

# Example 3: Using a whitelist for reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  get '/api/resource' do
    resource_name = params[:resource]
    allowed_resources = ["User", "Post", "Comment"]
    
    if allowed_resources.include?(resource_name)
      # ok: ruby-unsafe-reflection
      resource_class = Object.const_get(resource_name)
      resource_class.all.to_json
    else
      halt 403, "Unauthorized resource"
    end
  end
# {/fact}
end

# Example 4: Using a case statement instead of reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  get '/api/data' do
    type = params[:type]
    
    # ok: ruby-unsafe-reflection
    data = case type
    when "users"
      User.all
    when "posts"
      Post.all
    when "comments"
      Comment.all
    else
      halt 400, "Invalid type"
    end
# {/fact}
    
    data.to_json
  end
end

# Example 5: Using a hash map instead of reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  get '/api/service' do
    service_name = params[:service]
    
    services = {
      "email" => EmailService.new,
      "sms" => SmsService.new,
      "push" => PushNotificationService.new
    }
    
    # ok: ruby-unsafe-reflection
    service = services[service_name]
    
    if service.nil?
      halt 400, "Invalid service"
    else
      service.process(params[:data]).to_json
    end
  end
# {/fact}
end

# Example 6: Using a factory pattern instead of reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  post '/create_object' do
    type = params[:type]
    
    # ok: ruby-unsafe-reflection
    object = ObjectFactory.create(type, params[:data])
    
    if object.nil?
      halt 400, "Invalid object type"
    else
      object.to_json
    end
  end
# {/fact}
end

# Example 7: Using a registry pattern instead of reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  get '/component/:name' do
    name = params[:name]
    
    # ok: ruby-unsafe-reflection
    component = ComponentRegistry.get(name)
    
    if component.nil?
      halt 404, "Component not found"
    else
      component.render.to_json
    end
  end
# {/fact}
end

# Example 8: Using a method lookup table
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  post '/api/action' do
    action = params[:action]
    data = params[:data]
    
    actions = {
      "create" => method(:create_resource),
      "update" => method(:update_resource),
      "delete" => method(:delete_resource)
    }
    
    # ok: ruby-unsafe-reflection
    handler = actions[action]
    
    if handler.nil?
      halt 400, "Invalid action"
    else
      result = handler.call(data)
      { success: true, result: result }.to_json
    end
  end
# {/fact}
end

# Example 9: Using a strategy pattern instead of reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  get '/process' do
    strategy_name = params[:strategy]
    
    strategies = {
      "fast" => FastProcessingStrategy.new,
      "detailed" => DetailedProcessingStrategy.new,
      "batch" => BatchProcessingStrategy.new
    }
    
    # ok: ruby-unsafe-reflection
    strategy = strategies[strategy_name]
    
    if strategy.nil?
      halt 400, "Invalid strategy"
    else
      result = strategy.process(params[:data])
      result.to_json
    end
  end
# {/fact}
end

# Example 10: Using a command pattern instead of reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  post '/execute_command' do
    command_name = params[:command]
    
    commands = {
      "send_email" => SendEmailCommand.new,
      "generate_report" => GenerateReportCommand.new,
      "backup_data" => BackupDataCommand.new
    }
    
    # ok: ruby-unsafe-reflection
    command = commands[command_name]
    
    if command.nil?
      halt 400, "Invalid command"
    else
      result = command.execute(params[:params])
      { status: "success", result: result }.to_json
    end
  end
# {/fact}
end

# Example 11: Using a validator before reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  get '/api/model' do
    model_name = params[:model]
    
    validator = ModelValidator.new
    if validator.valid_model?(model_name)
      # ok: ruby-unsafe-reflection
      model = Object.const_get(model_name)
      model.all.to_json
    else
      halt 403, "Invalid model name"
    end
  end
# {/fact}
end

# Example 12: Using a custom DSL instead of direct reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  post '/configure' do
    config_name = params[:config]
    settings = params[:settings]
    
    # ok: ruby-unsafe-reflection
    configurator = Configurator.new
    configurator.load_config(config_name)
    configurator.apply_settings(settings)
    
    "Configuration applied"
  end
# {/fact}
end

# Example 13: Using a service locator pattern
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  get '/service/:name/action/:action' do
    service_name = params[:name]
    action_name = params[:action]
    
    # ok: ruby-unsafe-reflection
    service = ServiceLocator.get_service(service_name)
    
    if service.nil?
      halt 404, "Service not found"
    elsif !service.respond_to?(action_name)
      halt 400, "Invalid action"
    else
      result = service.public_send(action_name, params[:data])
      result.to_json
    end
  end
# {/fact}
end

# Example 14: Using a plugin system with registered handlers
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  post '/plugin/execute' do
    plugin_name = params[:plugin]
    
    # ok: ruby-unsafe-reflection
    plugin = PluginRegistry.get(plugin_name)
    
    if plugin.nil?
      halt 404, "Plugin not found"
    else
      result = plugin.execute(params[:data])
      { success: true, data: result }.to_json
    end
  end
# {/fact}
end

# Example 15: Using dependency injection instead of reflection
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  get '/report/:type' do
    report_type = params[:type]
    
    # ok: ruby-unsafe-reflection
    report_generator = ReportGeneratorFactory.create(report_type)
    
    if report_generator.nil?
      halt 400, "Invalid report type"
    else
      data = report_generator.generate(params[:filters])
      data.to_json
    end
  end
# {/fact}
end