# This file contains examples of secure and insecure uses of render inline in Ruby applications
# Rule ID: ruby-avoid-render-inline

require 'rails'
require 'sinatra'
require 'erb'

# BAD EXAMPLES - These demonstrate vulnerable code that should be detected

# Example 1: Basic render inline with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  user_input = params[:template]
  
  # ruleid: ruby-avoid-render-inline
  render inline: "<%= #{user_input} %>"
end
# {/fact}

# Example 2: Using render inline with string interpolation
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  user_template = params[:user_template]
  
  # ruleid: ruby-avoid-render-inline
  render inline: "Hello <%= #{user_template} %>, welcome to our site!"
end
# {/fact}

# Example 3: Using render_to_string with inline option
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  template_content = request.headers["X-Template-Content"]
  
  # ruleid: ruby-avoid-render-inline
  result = render_to_string inline: template_content
  render plain: result
end
# {/fact}

# Example 4: Using render inline in a controller action with complex ERB
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  user_data = params[:data]
  
  # ruleid: ruby-avoid-render-inline
  render inline: "<% if #{user_data}.present? %><p><%= #{user_data} %></p><% end %>"
end
# {/fact}

# Example 5: Using render inline with a variable from session
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  template = session[:saved_template]
  
  # ruleid: ruby-avoid-render-inline
  render inline: template
end
# {/fact}

# Example 6: Using render inline with a variable from cookies
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  stored_template = cookies[:template]
  
  # ruleid: ruby-avoid-render-inline
  render inline: "<h1>Custom View</h1><div><%= #{stored_template} %></div>"
end
# {/fact}

# Example 7: Using render_to_string inline in a helper method
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  template_string = params[:template_string]
  
  # ruleid: ruby-avoid-render-inline
  content = render_to_string inline: template_string, locals: { user: current_user }
  send_email(content)
end
# {/fact}

# Example 8: Using render inline with request parameters in a conditional
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  if params[:admin]
    admin_template = params[:admin_template]
    
    # ruleid: ruby-avoid-render-inline
    render inline: admin_template
  else
    render plain: "Access denied"
  end
end
# {/fact}

# Example 9: Using render inline with JSON data converted to string
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  json_data = request.body.read
  template_data = JSON.parse(json_data)["template"]
  
  # ruleid: ruby-avoid-render-inline
  render inline: template_data
end
# {/fact}

# Example 10: Using render inline with form data
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  form_template = params[:form][:template]
  
  # ruleid: ruby-avoid-render-inline
  render inline: form_template, layout: 'application'
end
# {/fact}

# Example 11: Using render inline with a database-stored template
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  user_id = params[:user_id]
  user = User.find(user_id)
  stored_template = user.custom_template
  
  # ruleid: ruby-avoid-render-inline
  render inline: stored_template
end
# {/fact}

# Example 12: Using render_to_string inline with complex options
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  template_content = params[:content]
  
  # ruleid: ruby-avoid-render-inline
  result = render_to_string(
    inline: template_content,
    locals: { current_time: Time.now }
  )
  render json: { rendered_content: result }
end
# {/fact}

# Example 13: Using render inline in a Sinatra application
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  template = params[:template]
  
  # ruleid: ruby-avoid-render-inline
  erb inline: template
end
# {/fact}

# Example 14: Using render inline with multiple template parts
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  header = params[:header_template]
  body = params[:body_template]
  footer = params[:footer_template]
  
  # ruleid: ruby-avoid-render-inline
  render inline: "<div class='header'><%= #{header} %></div><div class='body'><%= #{body} %></div><div class='footer'><%= #{footer} %></div>"
end
# {/fact}

# Example 15: Using render inline with a template from an API
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  response = HTTParty.get("https://api.example.com/templates/#{params[:template_id]}")
  template_content = response.body
  
  # ruleid: ruby-avoid-render-inline
  render inline: template_content
end
# {/fact}

# GOOD EXAMPLES - These demonstrate secure code that should not be detected

# Example 1: Using render with a template file instead of inline
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  user_input = params[:template]
  
  # ok: ruby-avoid-render-inline
  render template: "users/profile", locals: { user_data: user_input }
end
# {/fact}

# Example 2: Using render partial instead of inline
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  user_template = params[:user_template]
  
  # ok: ruby-avoid-render-inline
  render partial: "shared/user_content", locals: { content: user_template }
end
# {/fact}

# Example 3: Using render_to_string with template option
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  template_name = request.headers["X-Template-Name"]
  
  # ok: ruby-avoid-render-inline
  result = render_to_string template: template_name
  render plain: result
end
# {/fact}

# Example 4: Using render json instead of inline
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  user_data = params[:data]
  
  # ok: ruby-avoid-render-inline
  render json: { data: user_data }
end
# {/fact}

# Example 5: Using render with a specific template and layout
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  template = params[:template_name]
  
  # ok: ruby-avoid-render-inline
  render template: template, layout: 'application'
end
# {/fact}

# Example 6: Using render with html option
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  html_content = "<p>Static HTML content</p>"
  
  # ok: ruby-avoid-render-inline
  render html: html_content.html_safe
end
# {/fact}

# Example 7: Using render_to_string with a partial
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  template_name = params[:template_name]
  
  # ok: ruby-avoid-render-inline
  content = render_to_string partial: template_name, locals: { user: current_user }
  send_email(content)
end
# {/fact}

# Example 8: Using render with different formats based on request
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  respond_to do |format|
    # ok: ruby-avoid-render-inline
    format.html { render template: 'users/show' }
    format.json { render json: @user }
    format.xml { render xml: @user }
  end
# {/fact}
end

# Example 9: Using render with a specific action
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  # ok: ruby-avoid-render-inline
  render action: 'show'
end
# {/fact}

# Example 10: Using render with a file path
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  # ok: ruby-avoid-render-inline
  render file: "#{Rails.root}/public/404.html", layout: false
end
# {/fact}

# Example 11: Using render with a specific controller and action
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  # ok: ruby-avoid-render-inline
  render controller: 'users', action: 'profile'
end
# {/fact}

# Example 12: Using render nothing
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  # ok: ruby-avoid-render-inline
  render nothing: true, status: 204
end
# {/fact}

# Example 13: Using render text with sanitized content
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  user_input = params[:message]
  sanitized_input = ActionController::Base.helpers.sanitize(user_input)
  
  # ok: ruby-avoid-render-inline
  render plain: sanitized_input
end
# {/fact}

# Example 14: Using render with a specific template and status
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  # ok: ruby-avoid-render-inline
  render template: 'shared/error', status: 500
end
# {/fact}

# Example 15: Using ERB in a controlled way without render inline
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  user_input = params[:name]
  template = ERB.new("<p>Hello, <%= name %>!</p>")
  
  # ok: ruby-avoid-render-inline
  result = template.result_with_hash(name: ERB::Util.html_escape(user_input))
  render plain: result
end
# {/fact}