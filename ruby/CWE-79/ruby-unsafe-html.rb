# Examples for ruby-unsafe-html rule detection
# This file contains examples of both vulnerable and safe usage of html_safe in Ruby

require 'sinatra'
require 'rails'
require 'erb'
require 'action_view'
require 'sanitize'

# True Positive Examples (Vulnerable Code)

# Example 1: Direct use of html_safe with user input from params
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  get '/profile' do
    user_input = params[:name]
    # ruleid: ruby-unsafe-html
    unsafe_html = user_input.html_safe
    erb :profile, locals: { user_html: unsafe_html }
  end
# {/fact}
end

# Example 2: Using html_safe with concatenated user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  get '/welcome' do
    username = params[:username]
    # ruleid: ruby-unsafe-html
    greeting = "<div>Welcome, #{username}</div>".html_safe
    erb :welcome, locals: { greeting: greeting }
  end
# {/fact}
end

# Example 3: Using html_safe with request headers
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  get '/header_display' do
    user_agent = request.env['HTTP_USER_AGENT']
    # ruleid: ruby-unsafe-html
    agent_display = "Your browser: #{user_agent}".html_safe
    erb :header, locals: { agent: agent_display }
  end
# {/fact}
end

# Example 4: Using html_safe with form data in POST request
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  post '/comment' do
    comment = request.body.read
    # ruleid: ruby-unsafe-html
    formatted_comment = "<blockquote>#{comment}</blockquote>".html_safe
    erb :comment, locals: { comment: formatted_comment }
  end
# {/fact}
end

# Example 5: Using html_safe with cookie data
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  get '/preferences' do
    theme = request.cookies['theme']
    # ruleid: ruby-unsafe-html
    theme_html = "<div class='theme-#{theme}'>Theme applied</div>".html_safe
    erb :preferences, locals: { theme_html: theme_html }
  end
# {/fact}
end

# Example 6: Using html_safe with URL parameters in complex HTML
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  get '/article' do
    article_id = params[:id]
    title = params[:title]
    # ruleid: ruby-unsafe-html
    article_html = "<article data-id='#{article_id}'><h1>#{title}</h1></article>".html_safe
    erb :article, locals: { content: article_html }
  end
# {/fact}
end

# Example 7: Using html_safe with JSON data parsed from request
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  post '/api/widget' do
    data = JSON.parse(request.body.read)
    widget_name = data['name']
    # ruleid: ruby-unsafe-html
    widget_html = "<div class='widget'>#{widget_name}</div>".html_safe
    erb :widget, locals: { widget: widget_html }
  end
# {/fact}
end

# Example 8: Using html_safe with multiple user inputs
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  get '/search' do
    query = params[:q]
    category = params[:category]
    # ruleid: ruby-unsafe-html
    search_html = "<div>Results for <strong>#{query}</strong> in #{category}</div>".html_safe
    erb :search, locals: { search_info: search_html }
  end
# {/fact}
end

# Example 9: Using html_safe with input after minimal processing
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  get '/message' do
    message = params[:msg]
    processed_message = message.gsub(/\s+/, ' ').strip
    # ruleid: ruby-unsafe-html
    message_html = "<p class='message'>#{processed_message}</p>".html_safe
    erb :message, locals: { message: message_html }
  end
# {/fact}
end

# Example 10: Using html_safe with user input in a loop
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  get '/tags' do
    tags = params[:tags].split(',')
    tag_list = ""
    tags.each do |tag|
      tag_list += "<li>#{tag}</li>"
    end
# {/fact}
    # ruleid: ruby-unsafe-html
    final_html = "<ul>#{tag_list}</ul>".html_safe
    erb :tags, locals: { tags_html: final_html }
  end
end

# Example 11: Using html_safe with user input in conditional logic
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  get '/status' do
    status = params[:status]
    status_html = ""
    if status == "active"
      status_html = "<span class='active'>#{status}</span>"
    else
      status_html = "<span class='inactive'>#{status}</span>"
    end
    # ruleid: ruby-unsafe-html
    final_status = status_html.html_safe
    erb :status, locals: { status: final_status }
  end
# {/fact}
end

# Example 12: Using html_safe with user input in a hash
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  get '/user_info' do
    user_data = {
      name: params[:name],
      email: params[:email],
      bio: params[:bio]
    }
    
    user_html = "<div class='user-card'>"
    user_html += "<h2>#{user_data[:name]}</h2>"
    user_html += "<p>#{user_data[:email]}</p>"
    user_html += "<div>#{user_data[:bio]}</div>"
    user_html += "</div>"
    
    # ruleid: ruby-unsafe-html
    final_html = user_html.html_safe
    erb :user, locals: { user_content: final_html }
  end
# {/fact}
end

# Example 13: Using html_safe with URL fragment
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  get '/link' do
    url = params[:url]
    fragment = params[:fragment]
    # ruleid: ruby-unsafe-html
    link_html = "<a href='#{url}##{fragment}'>Click here</a>".html_safe
    erb :link, locals: { link: link_html }
  end
# {/fact}
end

# Example 14: Using html_safe with user input in attributes
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  get '/image' do
    src = params[:src]
    alt = params[:alt]
    # ruleid: ruby-unsafe-html
    img_html = "<img src='#{src}' alt='#{alt}' class='user-image'>".html_safe
    erb :image, locals: { image: img_html }
  end
# {/fact}
end

# Example 15: Using html_safe with user input in data attributes
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  get '/element' do
    data_value = params[:value]
    element_id = params[:id]
    # ruleid: ruby-unsafe-html
    element_html = "<div id='#{element_id}' data-custom='#{data_value}'>Element</div>".html_safe
    erb :element, locals: { element: element_html }
  end
# {/fact}
end

# True Negative Examples (Safe Code)

# Example 1: Using ERB::Util.html_escape instead of html_safe
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  get '/profile' do
    user_input = params[:name]
    # ok: ruby-unsafe-html
    safe_html = ERB::Util.html_escape(user_input)
    erb :profile, locals: { user_html: safe_html }
  end
# {/fact}
end

# Example 2: Using h helper method for HTML escaping
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  get '/welcome' do
    username = params[:username]
    # ok: ruby-unsafe-html
    greeting = "<div>Welcome, #{h(username)}</div>"
    erb :welcome, locals: { greeting: greeting }
  end
# {/fact}
  
  def h(text)
    ERB::Util.html_escape(text)
  end
end

# Example 3: Using sanitize gem for user input
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  get '/header_display' do
    user_agent = request.env['HTTP_USER_AGENT']
    # ok: ruby-unsafe-html
    agent_display = Sanitize.fragment(user_agent)
    erb :header, locals: { agent: agent_display }
  end
# {/fact}
end

# Example 4: Using Rails sanitize helper
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  post '/comment' do
    comment = request.body.read
    # ok: ruby-unsafe-html
    formatted_comment = ActionView::Base.new.sanitize(comment)
    erb :comment, locals: { comment: formatted_comment }
  end
# {/fact}
end

# Example 5: Using html_safe only with hardcoded content
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  get '/static_content' do
    # ok: ruby-unsafe-html
    static_html = "<div class='static'>This is static content</div>".html_safe
    erb :static, locals: { content: static_html }
  end
# {/fact}
end

# Example 6: Using Rails::Html::FullSanitizer
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  get '/article' do
    title = params[:title]
    sanitizer = Rails::Html::FullSanitizer.new
    # ok: ruby-unsafe-html
    safe_title = sanitizer.sanitize(title)
    erb :article, locals: { title: safe_title }
  end
# {/fact}
end

# Example 7: Proper escaping before using html_safe
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  post '/api/widget' do
    data = JSON.parse(request.body.read)
    widget_name = data['name']
    escaped_name = ERB::Util.html_escape(widget_name)
    # ok: ruby-unsafe-html
    widget_html = "<div class='widget'>#{escaped_name}</div>".html_safe
    erb :widget, locals: { widget: widget_html }
  end
# {/fact}
end

# Example 8: Using Rails safe_join for combining HTML elements
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  get '/search' do
    query = params[:q]
    category = params[:category]
    escaped_query = ERB::Util.html_escape(query)
    escaped_category = ERB::Util.html_escape(category)
    # ok: ruby-unsafe-html
    search_html = ActionView::Base.new.safe_join([
      "<div>Results for ".html_safe,
      "<strong>#{escaped_query}</strong>".html_safe,
      " in #{escaped_category}</div>".html_safe
    ])
    erb :search, locals: { search_info: search_html }
  end
# {/fact}
end

# Example 9: Using content_tag helper from ActionView
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  get '/message' do
    message = params[:msg]
    # ok: ruby-unsafe-html
    message_html = ActionView::Base.new.content_tag(:p, message, class: 'message')
    erb :message, locals: { message: message_html }
  end
# {/fact}
end

# Example 10: Using raw only with validated input
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  get '/tags' do
    tags = params[:tags].split(',')
    tag_list = ""
    tags.each do |tag|
      # Validate that tag contains only alphanumeric characters
      if tag =~ /\A[a-zA-Z0-9]+\z/
        tag_list += "<li>#{tag}</li>"
      else
        tag_list += "<li>#{ERB::Util.html_escape(tag)}</li>"
      end
    end
# {/fact}
    # ok: ruby-unsafe-html
    final_html = "<ul>#{tag_list}</ul>".html_safe
    erb :tags, locals: { tags_html: final_html }
  end
end

# Example 11: Using strip_tags to remove all HTML
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  get '/status' do
    status = params[:status]
    # ok: ruby-unsafe-html
    safe_status = ActionView::Base.new.strip_tags(status)
    erb :status, locals: { status: safe_status }
  end
# {/fact}
end

# Example 12: Using Rails::Html::WhiteListSanitizer
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  get '/user_info' do
    bio = params[:bio]
    sanitizer = Rails::Html::WhiteListSanitizer.new
    # ok: ruby-unsafe-html
    safe_bio = sanitizer.sanitize(bio, tags: %w(p b i u))
    erb :user, locals: { bio: safe_bio }
  end
# {/fact}
end

# Example 13: Using link_to helper from ActionView
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  get '/link' do
    url = params[:url]
    text = params[:text]
    # ok: ruby-unsafe-html
    link_html = ActionView::Base.new.link_to(text, url)
    erb :link, locals: { link: link_html }
  end
# {/fact}
end

# Example 14: Using image_tag helper from ActionView
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  get '/image' do
    src = params[:src]
    alt = params[:alt]
    # ok: ruby-unsafe-html
    img_html = ActionView::Base.new.image_tag(src, alt: alt, class: 'user-image')
    erb :image, locals: { image: img_html }
  end
# {/fact}
end

# Example 15: Using content_tag with nested elements
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  get '/element' do
    data_value = params[:value]
    element_id = params[:id]
    view = ActionView::Base.new
    # ok: ruby-unsafe-html
    element_html = view.content_tag(:div, "Element", id: element_id, data: { custom: data_value })
    erb :element, locals: { element: element_html }
  end
# {/fact}
end