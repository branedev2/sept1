# This file contains examples of safe and unsafe uses of the `raw` method in Ruby
# The rule detects potential XSS vulnerabilities from unescaped HTML content

require 'rails'
require 'sinatra'
require 'erb'

# True Positive Examples (Vulnerable Code)

# Example 1: Basic use of raw with user input from params
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  get '/profile' do
    user_bio = params[:bio]
    # ruleid: ruby-avoid-raw
    @content = raw(user_bio)
    erb :profile
  end
# {/fact}
end

# Example 2: Raw used with concatenated user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  get '/article' do
    title = params[:title]
    # ruleid: ruby-avoid-raw
    @header = raw("<h1>" + title + "</h1>")
    erb :article
  end
# {/fact}
end

# Example 3: Raw used with interpolated user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  get '/comment' do
    comment = params[:comment]
    username = params[:username]
    # ruleid: ruby-avoid-raw
    @comment_html = raw("Comment by #{username}: #{comment}")
    erb :comments
  end
# {/fact}
end

# Example 4: Raw used with request headers
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  get '/custom_header' do
    custom_header = request.env['HTTP_X_CUSTOM_HEADER']
    # ruleid: ruby-avoid-raw
    @header_display = raw("Custom header: #{custom_header}")
    erb :headers
  end
# {/fact}
end

# Example 5: Raw used with cookie data
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  get '/preferences' do
    theme_preference = request.cookies['theme']
    # ruleid: ruby-avoid-raw
    @theme_html = raw("<div class='theme-#{theme_preference}'>Theme applied</div>")
    erb :preferences
  end
# {/fact}
end

# Example 6: Raw used with form data in POST request
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  post '/submit_form' do
    form_content = request.body.read
    # ruleid: ruby-avoid-raw
    @form_display = raw("Submitted content: #{form_content}")
    erb :form_result
  end
# {/fact}
end

# Example 7: Raw used with JSON data
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  post '/api/data' do
    data = JSON.parse(request.body.read)
    # ruleid: ruby-avoid-raw
    @json_display = raw("Data received: #{data['message']}")
    erb :api_response
  end
# {/fact}
end

# Example 8: Raw used with URL parameters in complex structure
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  get '/search' do
    query = params[:q]
    category = params[:category]
    # ruleid: ruby-avoid-raw
    @search_html = raw("<div class='search-result'>Results for: #{query} in #{category}</div>")
    erb :search
  end
# {/fact}
end

# Example 9: Raw used with session data
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  get '/dashboard' do
    user_notes = session[:notes]
    # ruleid: ruby-avoid-raw
    @notes_display = raw("Your notes: #{user_notes}")
    erb :dashboard
  end
# {/fact}
end

# Example 10: Raw used with multiple concatenated user inputs
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  get '/user_profile' do
    name = params[:name]
    bio = params[:bio]
    location = params[:location]
    # ruleid: ruby-avoid-raw
    @profile_html = raw("<div>Name: #{name}</div><div>Bio: #{bio}</div><div>Location: #{location}</div>")
    erb :user_profile
  end
# {/fact}
end

# Example 11: Raw used with user input after minimal processing
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  get '/format_text' do
    text = params[:text]
    formatted_text = text.gsub("\n", "<br>")
    # ruleid: ruby-avoid-raw
    @formatted_content = raw(formatted_text)
    erb :formatted
  end
# {/fact}
end

# Example 12: Raw used with user input in a helper method
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  helpers do
    def format_user_content(content)
      # ruleid: ruby-avoid-raw
      raw(content)
    end
  end
# {/fact}
  
  get '/helper_example' do
    user_content = params[:content]
    @formatted = format_user_content(user_content)
    erb :helper_example
  end
end

# Example 13: Raw used with user input in a conditional
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  get '/conditional_content' do
    content = params[:content]
    if content.length > 10
      # ruleid: ruby-avoid-raw
      @display = raw(content)
    else
      @display = content
    end
    erb :conditional
  end
# {/fact}
end

# Example 14: Raw used with user input in a loop
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  get '/list_items' do
    items = params[:items].split(',')
    @item_list = ""
    items.each do |item|
      # ruleid: ruby-avoid-raw
      @item_list += raw("<li>#{item}</li>")
    end
# {/fact}
    erb :list
  end
end

# Example 15: Raw used with user input in a complex template
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  get '/template' do
    title = params[:title]
    content = params[:content]
    footer = params[:footer]
    
    template = <<-HTML
      <div class="page">
        <header>#{title}</header>
        <main>#{content}</main>
        <footer>#{footer}</footer>
      </div>
    HTML
    
    # ruleid: ruby-avoid-raw
    @page_content = raw(template)
    erb :template
  end
# {/fact}
end

# True Negative Examples (Safe Code)

# Example 1: Using h helper for proper HTML escaping
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  get '/profile_safe' do
    user_bio = params[:bio]
    # ok: ruby-avoid-raw
    @content = h(user_bio)
    erb :profile
  end
# {/fact}
end

# Example 2: Using sanitize helper for safe HTML rendering
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  get '/article_safe' do
    title = params[:title]
    # ok: ruby-avoid-raw
    @header = sanitize("<h1>#{title}</h1>", tags: ['h1'])
    erb :article
  end
# {/fact}
end

# Example 3: Using html_escape for safe interpolation
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  get '/comment_safe' do
    comment = params[:comment]
    username = params[:username]
    # ok: ruby-avoid-raw
    @comment_html = "Comment by #{ERB::Util.html_escape(username)}: #{ERB::Util.html_escape(comment)}"
    erb :comments
  end
# {/fact}
end

# Example 4: Using content_tag for safe HTML generation
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  get '/custom_header_safe' do
    custom_header = request.env['HTTP_X_CUSTOM_HEADER']
    # ok: ruby-avoid-raw
    @header_display = content_tag(:div, "Custom header: #{custom_header}", class: 'header')
    erb :headers
  end
# {/fact}
end

# Example 5: Using safe string interpolation with ERB
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  get '/preferences_safe' do
    theme_preference = request.cookies['theme']
    # ok: ruby-avoid-raw
    @theme_html = "<div class='theme-#{ERB::Util.html_escape(theme_preference)}'>Theme applied</div>".html_safe
    erb :preferences
  end
# {/fact}
end

# Example 6: Using strip_tags to remove HTML before display
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  post '/submit_form_safe' do
    form_content = request.body.read
    # ok: ruby-avoid-raw
    @form_display = "Submitted content: #{strip_tags(form_content)}"
    erb :form_result
  end
# {/fact}
end

# Example 7: Using safe JSON rendering
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  post '/api/data_safe' do
    data = JSON.parse(request.body.read)
    # ok: ruby-avoid-raw
    @json_display = "Data received: #{ERB::Util.html_escape(data['message'])}"
    erb :api_response
  end
# {/fact}
end

# Example 8: Using Rails' tag helpers for safe HTML
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  get '/search_safe' do
    query = params[:q]
    category = params[:category]
    # ok: ruby-avoid-raw
    @search_html = tag.div("Results for: #{h(query)} in #{h(category)}", class: 'search-result')
    erb :search
  end
# {/fact}
end

# Example 9: Using safe string concatenation with escaping
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  get '/dashboard_safe' do
    user_notes = session[:notes]
    # ok: ruby-avoid-raw
    @notes_display = "Your notes: " + h(user_notes)
    erb :dashboard
  end
# {/fact}
end

# Example 10: Using safe HTML construction with multiple inputs
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  get '/user_profile_safe' do
    name = params[:name]
    bio = params[:bio]
    location = params[:location]
    
    # ok: ruby-avoid-raw
    @profile_html = tag.div do
      concat tag.div("Name: #{h(name)}")
      concat tag.div("Bio: #{h(bio)}")
      concat tag.div("Location: #{h(location)}")
    end
# {/fact}
    
    erb :user_profile
  end
end

# Example 11: Using markdown renderer with HTML escaping
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  get '/format_text_safe' do
    text = params[:text]
    require 'redcarpet'
    markdown = Redcarpet::Markdown.new(Redcarpet::Render::HTML.new(escape_html: true))
    # ok: ruby-avoid-raw
    @formatted_content = markdown.render(text)
    erb :formatted
  end
# {/fact}
end

# Example 12: Using a safe helper method
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  helpers do
    def format_user_content_safe(content)
      # ok: ruby-avoid-raw
      h(content).gsub("\n", "<br>").html_safe
    end
  end
# {/fact}
  
  get '/helper_example_safe' do
    user_content = params[:content]
    @formatted = format_user_content_safe(user_content)
    erb :helper_example
  end
end

# Example 13: Using conditional with safe HTML handling
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  get '/conditional_content_safe' do
    content = params[:content]
    if content.length > 10
      # ok: ruby-avoid-raw
      @display = h(content)
    else
      @display = content.to_s
    end
    erb :conditional
  end
# {/fact}
end

# Example 14: Using safe HTML in a loop
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  get '/list_items_safe' do
    items = params[:items].split(',')
    @item_list = ""
    items.each do |item|
      # ok: ruby-avoid-raw
      @item_list += content_tag(:li, item)
    end
# {/fact}
    erb :list
  end
end

# Example 15: Using safe template construction
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  get '/template_safe' do
    title = params[:title]
    content = params[:content]
    footer = params[:footer]
    
    # ok: ruby-avoid-raw
    @page_content = tag.div(class: 'page') do
      concat tag.header(h(title))
      concat tag.main(h(content))
      concat tag.footer(h(footer))
    end
# {/fact}
    
    erb :template
  end
end