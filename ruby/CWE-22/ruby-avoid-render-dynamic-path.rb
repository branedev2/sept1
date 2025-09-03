# Examples for ruby-avoid-render-dynamic-path (CWE-22)
# This file contains examples of secure and insecure uses of the render method in Ruby applications

require 'sinatra'
require 'rails'

# True Positive Examples (Vulnerable Code)

# Example 1: Directly using user input in render
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_1
  get '/view' do
    template = params[:template]
    # ruleid: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 2: Using request parameter in render with string interpolation
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_2
  get '/document' do
    doc_type = params[:type]
    # ruleid: ruby-avoid-render-dynamic-path
    render "documents/#{doc_type}"
  end
# {/fact}
end

# Example 3: Using POST data in render
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_3
  post '/render_template' do
    template_path = request.body.read
    # ruleid: ruby-avoid-render-dynamic-path
    render template_path
  end
# {/fact}
end

# Example 4: Using header value in render
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_4
  get '/view_with_header' do
    template = request.env['HTTP_X_TEMPLATE']
    # ruleid: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 5: Using URL parameter with minimal processing
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_5
  get '/view/:template' do
    template = params[:template].strip
    # ruleid: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 6: Using cookie value in render
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_6
  get '/themed_view' do
    theme = request.cookies['user_theme']
    # ruleid: ruby-avoid-render-dynamic-path
    render "themes/#{theme}/index"
  end
# {/fact}
end

# Example 7: Using form data in render with Rails
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_7
  def show
    template = params[:template_name]
    # ruleid: ruby-avoid-render-dynamic-path
    render template
  end
end
# {/fact}

# Example 8: Using JSON body parameter in render
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_8
  post '/api/render' do
    data = JSON.parse(request.body.read)
    template = data['template']
    # ruleid: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 9: Using user input with conditional logic
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_9
  get '/conditional_view' do
    template = params[:view]
    if template.include?('admin')
      template = 'unauthorized'
    end
    # ruleid: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 10: Using request parameter with string concatenation
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_10
  get '/profile' do
    section = params[:section]
    # ruleid: ruby-avoid-render-dynamic-path
    render 'profiles/' + section
  end
# {/fact}
end

# Example 11: Using multiple parameters to construct template path
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_11
  get '/multi_param' do
    category = params[:category]
    page = params[:page]
    # ruleid: ruby-avoid-render-dynamic-path
    render "#{category}/#{page}"
  end
# {/fact}
end

# Example 12: Using user input with format specification
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_12
  get '/formatted_view' do
    template = params[:template]
    format = params[:format] || 'html'
    # ruleid: ruby-avoid-render-dynamic-path
    render template, formats: [format.to_sym]
  end
# {/fact}
end

# Example 13: Using session data in render
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_13
  get '/session_view' do
    template = session[:preferred_template]
    # ruleid: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 14: Using query parameter with default value
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_14
  get '/default_view' do
    template = params[:template] || 'default'
    # ruleid: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 15: Using user input with complex path construction
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_15
  get '/complex_path' do
    base = params[:base_dir]
    sub = params[:sub_dir]
    file = params[:file]
    # ruleid: ruby-avoid-render-dynamic-path
    render "#{base}/#{sub}/#{file}"
  end
# {/fact}
end

# True Negative Examples (Secure Code)

# Example 1: Using hardcoded template path
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_1
  get '/about' do
    # ok: ruby-avoid-render-dynamic-path
    render 'about'
  end
# {/fact}
end

# Example 2: Using File.basename to sanitize user input
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_2
  get '/view' do
    template = params[:template]
    safe_template = File.basename(template)
    # ok: ruby-avoid-render-dynamic-path
    render safe_template
  end
# {/fact}
end

# Example 3: Using a whitelist of allowed templates
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_3
  get '/document' do
    doc_type = params[:type]
    allowed_templates = ['invoice', 'receipt', 'report']
    
    if allowed_templates.include?(doc_type)
      # ok: ruby-avoid-render-dynamic-path
      render "documents/#{doc_type}"
    else
      render 'error'
    end
  end
# {/fact}
end

# Example 4: Using a mapping to translate user input to safe templates
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_4
  get '/view_mapped' do
    template_key = params[:template]
    template_map = {
      'profile' => 'users/profile',
      'settings' => 'users/settings',
      'dashboard' => 'users/dashboard'
    }
    
    template = template_map[template_key] || 'default'
    # ok: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 5: Using a case statement to select templates
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_5
  get '/section' do
    section = params[:section]
    
    template = case section
               when 'about'
                 'about'
               when 'contact'
                 'contact'
               when 'faq'
                 'faq'
               else
                 'home'
               end
# {/fact}
    
    # ok: ruby-avoid-render-dynamic-path
    render template
  end
end

# Example 6: Using regex validation before rendering
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_6
  get '/validated_view' do
    template = params[:template]
    
    if template =~ /\A[a-zA-Z0-9_]+\z/
      # ok: ruby-avoid-render-dynamic-path
      render "safe/#{template}"
    else
      render 'error'
    end
  end
# {/fact}
end

# Example 7: Using a constant for template paths
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_7
  ALLOWED_TEMPLATES = ['home', 'about', 'contact', 'products', 'services'].freeze
  
  get '/page' do
    page = params[:page]
    
    if ALLOWED_TEMPLATES.include?(page)
      # ok: ruby-avoid-render-dynamic-path
      render page
    else
      render 'not_found'
    end
  end
# {/fact}
end

# Example 8: Using a helper method to validate template paths
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_8
  def safe_template_path(user_input)
    allowed_paths = ['users', 'products', 'orders']
    return 'default' unless allowed_paths.include?(user_input)
    user_input
  end
  
  get '/safe_view' do
    section = params[:section]
    template_path = safe_template_path(section)
    # ok: ruby-avoid-render-dynamic-path
    render template_path
  end
# {/fact}
end

# Example 9: Using File.basename with explicit directory
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_9
  get '/user_template' do
    template_name = params[:template]
    safe_name = File.basename(template_name, '.html.erb')
    # ok: ruby-avoid-render-dynamic-path
    render "users/#{safe_name}"
  end
# {/fact}
end

# Example 10: Using integer ID to select template
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_10
  get '/product/:id' do
    product_id = params[:id].to_i
    # ok: ruby-avoid-render-dynamic-path
    render "product_#{product_id}"
  end
# {/fact}
end

# Example 11: Using a secure lookup function
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_11
  def get_template_for_category(category)
    templates = {
      'electronics' => 'categories/electronics',
      'clothing' => 'categories/clothing',
      'books' => 'categories/books'
    }
    templates[category] || 'categories/default'
  end
  
  get '/category' do
    category = params[:cat]
    template = get_template_for_category(category)
    # ok: ruby-avoid-render-dynamic-path
    render template
  end
# {/fact}
end

# Example 12: Using hardcoded template with dynamic locals
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_12
  get '/user_profile' do
    user_id = params[:id]
    # ok: ruby-avoid-render-dynamic-path
    render 'user_profile', locals: { user_id: user_id }
  end
# {/fact}
end

# Example 13: Using a secure template selection with validation
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_13
  get '/report' do
    report_type = params[:type]
    
    # Validate and transform input
    valid_types = ['sales', 'inventory', 'customers']
    if valid_types.include?(report_type)
      # ok: ruby-avoid-render-dynamic-path
      render "reports/#{report_type}_report"
    else
      render 'reports/invalid_report'
    end
  end
# {/fact}
end

# Example 14: Using a secure template with dynamic partial
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_14
  get '/dashboard' do
    widget = params[:widget]
    allowed_widgets = ['stats', 'charts', 'notifications']
    
    # ok: ruby-avoid-render-dynamic-path
    render 'dashboard', locals: { 
      partial_name: allowed_widgets.include?(widget) ? widget : 'default'
    }
  end
# {/fact}
end

# Example 15: Using hardcoded template with dynamic format
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_15
  get '/document' do
    format = params[:format]
    allowed_formats = ['html', 'pdf', 'csv']
    
    format = 'html' unless allowed_formats.include?(format)
    
    # ok: ruby-avoid-render-dynamic-path
    render 'document', formats: [format.to_sym]
  end
# {/fact}
end