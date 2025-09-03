# Test cases for ruby-json-entity-escape rule
require 'json'
require 'sinatra'
require 'rails'
require 'active_support'
require 'action_controller'

# True Positive Cases (Vulnerable Code)

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  # Disabling HTML escaping in Rails JSON encoder
  # ruleid: ruby-json-entity-escape
  ActiveSupport.escape_html_entities_in_json = false
  
  user_input = params[:user_input]
  render json: { data: user_input }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  # Explicitly disabling HTML escaping in Rails configuration
  # ruleid: ruby-json-entity-escape
  Rails.application.config.active_support.escape_html_entities_in_json = false
  
  data = { message: request.params[:message] }
  render json: data
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  # Disabling HTML escaping in a Rails initializer
  # ruleid: ruby-json-entity-escape
  config = Rails.application.config
  config.active_support.escape_html_entities_in_json = false
  
  user_data = request.params[:data]
  render json: { content: user_data }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  # Using JSON.generate with HTML escaping disabled
  # ruleid: ruby-json-entity-escape
  ActiveSupport::JSON::Encoding.escape_html_entities_in_json = false
  
  user_content = request.params[:content]
  response.body = JSON.generate({ html: user_content })
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  # Setting escape_html_entities_in_json to false in a controller
  # ruleid: ruby-json-entity-escape
  ActionController::Base.config.active_support.escape_html_entities_in_json = false
  
  data = { user_input: params[:input] }
  render json: data
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  # Disabling HTML escaping in a custom JSON encoder
  # ruleid: ruby-json-entity-escape
  class CustomJSONEncoder
    def initialize
      ActiveSupport.escape_html_entities_in_json = false
    end
    
    def encode(data)
      ActiveSupport::JSON.encode(data)
    end
  end
  
  encoder = CustomJSONEncoder.new
  render json: encoder.encode({ message: request.params[:message] })
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  # Disabling HTML escaping in a Rails engine
  # ruleid: ruby-json-entity-escape
  module MyEngine
    class Engine < ::Rails::Engine
      config.active_support.escape_html_entities_in_json = false
    end
  end
  
  data = { content: params[:content] }
  render json: data
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  # Disabling HTML escaping in a Rails application class
  # ruleid: ruby-json-entity-escape
  class Application < Rails::Application
    config.active_support.escape_html_entities_in_json = false
  end
  
  user_data = request.params[:data]
  render json: { html: user_data }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  # Disabling HTML escaping in a Sinatra application
  # ruleid: ruby-json-entity-escape
  configure do
    ActiveSupport::JSON::Encoding.escape_html_entities_in_json = false
  end
# {/fact}
  
  get '/api' do
    content_type :json
    { message: params[:message] }.to_json
  end
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  # Disabling HTML escaping in a Rails initializer with conditional
  # ruleid: ruby-json-entity-escape
  if Rails.env.development?
    Rails.application.config.active_support.escape_html_entities_in_json = false
  end
  
  data = { user_input: request.params[:input] }
  render json: data
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  # Disabling HTML escaping with a variable
  # ruleid: ruby-json-entity-escape
  escape_html = false
  ActiveSupport.escape_html_entities_in_json = escape_html
  
  user_content = params[:content]
  render json: { data: user_content }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  # Disabling HTML escaping in a method
  # ruleid: ruby-json-entity-escape
  def configure_json
    ActiveSupport.escape_html_entities_in_json = false
  end
  
  configure_json
  user_data = request.params[:data]
  render json: { content: user_data }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  # Disabling HTML escaping with environment variable check
  # ruleid: ruby-json-entity-escape
  if ENV['DISABLE_HTML_ESCAPING'] == 'true'
    ActiveSupport.escape_html_entities_in_json = false
  end
  
  user_input = params[:input]
  render json: { message: user_input }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  # Disabling HTML escaping in a Rails module
  # ruleid: ruby-json-entity-escape
  module JSONConfig
    def self.setup
      ActiveSupport.escape_html_entities_in_json = false
    end
  end
  
  JSONConfig.setup
  data = { content: request.params[:content] }
  render json: data
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  # Disabling HTML escaping in a custom configuration method
  # ruleid: ruby-json-entity-escape
  def disable_html_escaping
    Rails.application.config.active_support.escape_html_entities_in_json = false
  end
  
  disable_html_escaping
  user_data = params[:data]
  render json: { html: user_data }
end
# {/fact}

# True Negative Cases (Secure Code)

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  # Enabling HTML escaping in Rails JSON encoder
  # ok: ruby-json-entity-escape
  ActiveSupport.escape_html_entities_in_json = true
  
  user_input = params[:user_input]
  render json: { data: user_input }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  # Explicitly enabling HTML escaping in Rails configuration
  # ok: ruby-json-entity-escape
  Rails.application.config.active_support.escape_html_entities_in_json = true
  
  data = { message: request.params[:message] }
  render json: data
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  # Using default HTML escaping (which is enabled by default)
  # ok: ruby-json-entity-escape
  # Not modifying escape_html_entities_in_json at all
  
  user_data = request.params[:data]
  render json: { content: user_data }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  # Using JSON.generate with HTML escaping enabled
  # ok: ruby-json-entity-escape
  ActiveSupport::JSON::Encoding.escape_html_entities_in_json = true
  
  user_content = request.params[:content]
  response.body = JSON.generate({ html: user_content })
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  # Setting escape_html_entities_in_json to true in a controller
  # ok: ruby-json-entity-escape
  ActionController::Base.config.active_support.escape_html_entities_in_json = true
  
  data = { user_input: params[:input] }
  render json: data
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  # Enabling HTML escaping in a custom JSON encoder
  # ok: ruby-json-entity-escape
  class SecureJSONEncoder
    def initialize
      ActiveSupport.escape_html_entities_in_json = true
    end
    
    def encode(data)
      ActiveSupport::JSON.encode(data)
    end
  end
  
  encoder = SecureJSONEncoder.new
  render json: encoder.encode({ message: request.params[:message] })
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  # Using ERB::Util.html_escape for manual escaping
  # ok: ruby-json-entity-escape
  require 'erb'
  
  user_input = params[:input]
  escaped_input = ERB::Util.html_escape(user_input)
  render json: { content: escaped_input }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  # Using sanitize helper for HTML content
  # ok: ruby-json-entity-escape
  include ActionView::Helpers::SanitizeHelper
  
  user_content = params[:content]
  sanitized_content = sanitize(user_content)
  render json: { html: sanitized_content }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  # Using Rails sanitize_helper
  # ok: ruby-json-entity-escape
  include ActionView::Helpers::SanitizeHelper
  
  user_input = request.params[:input]
  safe_html = sanitize(user_input, tags: %w(b i p br))
  render json: { content: safe_html }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  # Using HTML::Pipeline for sanitization
  # ok: ruby-json-entity-escape
  require 'html/pipeline'
  
  pipeline = HTML::Pipeline.new([
    HTML::Pipeline::SanitizationFilter
  ])
  
  user_content = params[:content]
  result = pipeline.call(user_content)
  render json: { html: result[:output].to_s }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  # Using Rails html_safe only after sanitization
  # ok: ruby-json-entity-escape
  include ActionView::Helpers::SanitizeHelper
  
  user_input = params[:input]
  sanitized = sanitize(user_input)
  render json: { content: sanitized }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  # Using a custom sanitizer before JSON rendering
  # ok: ruby-json-entity-escape
  def sanitize_html(text)
    text.gsub(/<\/?[^>]*>/, "")
  end
  
  user_content = params[:content]
  safe_content = sanitize_html(user_content)
  render json: { html: safe_content }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  # Using Rails configuration with explicit true value
  # ok: ruby-json-entity-escape
  Rails.application.configure do
    config.active_support.escape_html_entities_in_json = true
  end
# {/fact}
  
  user_data = request.params[:data]
  render json: { content: user_data }
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  # Using CGI.escapeHTML for manual escaping
  # ok: ruby-json-entity-escape
  require 'cgi'
  
  user_input = params[:input]
  escaped_input = CGI.escapeHTML(user_input)
  render json: { message: escaped_input }
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  # Using a secure JSON renderer with HTML escaping
  # ok: ruby-json-entity-escape
  class SecureJSONRenderer
    def render(data)
      # Ensure HTML escaping is enabled
      original_setting = ActiveSupport.escape_html_entities_in_json
      ActiveSupport.escape_html_entities_in_json = true
      
      result = ActiveSupport::JSON.encode(data)
      
      # Restore original setting
      ActiveSupport.escape_html_entities_in_json = original_setting
      
      result
    end
  end
  
  renderer = SecureJSONRenderer.new
  user_data = params[:data]
  response.body = renderer.render({ content: user_data })
end
# {/fact}