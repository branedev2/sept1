require 'sinatra'
require 'erb'
require 'rails'
require 'action_view'
require 'sanitize'

# True Positives (Vulnerable Code)

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  # Direct user input in HTML response
  get '/profile' do
    username = params[:username]
    # ruleid: ruby-cross-site-scripting
    "<div>Welcome, #{username}!</div>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  # User input in URL construction
  get '/redirect' do
    destination = params[:url]
    # ruleid: ruby-cross-site-scripting
    redirect "https://example.com/forward?url=#{destination}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  # User input in JavaScript
  get '/script' do
    user_data = params[:data]
    # ruleid: ruby-cross-site-scripting
    "<script>const userData = '#{user_data}';</script>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  # User input in HTML attribute
  get '/button' do
    action = params[:action]
    # ruleid: ruby-cross-site-scripting
    "<button onclick=\"#{action}\">Click me</button>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  # User input in iframe src
  get '/iframe' do
    source = params[:src]
    # ruleid: ruby-cross-site-scripting
    "<iframe src=\"#{source}\"></iframe>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  # User input in style attribute
  get '/style' do
    color = params[:color]
    # ruleid: ruby-cross-site-scripting
    "<div style=\"color: #{color}\">Colored text</div>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  # User input in meta tag
  get '/meta' do
    content = params[:content]
    # ruleid: ruby-cross-site-scripting
    "<meta name=\"description\" content=\"#{content}\">"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  # User input in anchor href
  get '/link' do
    url = params[:url]
    # ruleid: ruby-cross-site-scripting
    "<a href=\"#{url}\">Click here</a>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  # User input in HTML with string interpolation
  get '/welcome' do
    name = request.cookies["name"]
    # ruleid: ruby-cross-site-scripting
    html = "<h1>Welcome back, #{name}!</h1>"
    html
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  # User input in HTML with concatenation
  get '/search' do
    query = request.env["HTTP_REFERER"]
    # ruleid: ruby-cross-site-scripting
    html = "<p>Results for: " + query + "</p>"
    html
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  # User input in HTML with ERB without escaping
  get '/template' do
    user_comment = params[:comment]
    template = ERB.new("<div><%= user_comment %></div>")
    # ruleid: ruby-cross-site-scripting
    template.result(binding)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  # User input in HTML with string formatting
  get '/format' do
    username = request.params["user"]
    # ruleid: ruby-cross-site-scripting
    "<div>%s's Profile</div>" % username
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  # User input in HTML with multiple interpolations
  get '/multi' do
    first_name = params[:first]
    last_name = params[:last]
    # ruleid: ruby-cross-site-scripting
    "<div>Name: #{first_name} #{last_name}</div>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  # User input in HTML with conditional
  get '/conditional' do
    role = params[:role]
    # ruleid: ruby-cross-site-scripting
    html = role == "admin" ? "<div>Admin: #{role}</div>" : "<div>User: #{role}</div>"
    html
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  # User input in HTML with processing
  get '/processed' do
    message = params[:message]
    processed = message.upcase
    # ruleid: ruby-cross-site-scripting
    "<div>Your message: #{processed}</div>"
  end
# {/fact}
end

# True Negatives (Safe Code)

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  # Using HTML escaping with ERB::Util
  get '/profile' do
    username = params[:username]
    # ok: ruby-cross-site-scripting
    "<div>Welcome, #{ERB::Util.html_escape(username)}!</div>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  # Using Rails sanitize helper
  get '/comment' do
    comment = params[:comment]
    # ok: ruby-cross-site-scripting
    ActionView::Base.new.sanitize(comment)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  # Using Rails h helper
  get '/username' do
    username = params[:username]
    helper = ActionView::Base.new
    # ok: ruby-cross-site-scripting
    "<div>#{helper.h(username)}</div>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  # Using template rendering with automatic escaping
  get '/template' do
    @name = params[:name]
    # ok: ruby-cross-site-scripting
    erb :user_template
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  # Using URL encoding for query parameters
  get '/redirect' do
    destination = params[:url]
    # ok: ruby-cross-site-scripting
    redirect "https://example.com/forward?url=#{URI.encode_www_form_component(destination)}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  # Using allowlist for URLs
  get '/link' do
    url = params[:url]
    allowed_domains = ["example.com", "trusted-site.org"]
    
    begin
      uri = URI.parse(url)
      # ok: ruby-cross-site-scripting
      if allowed_domains.include?(uri.host)
        "<a href=\"#{url}\">Click here</a>"
      else
        "<a href=\"#\">Invalid URL</a>"
      end
    rescue URI::InvalidURIError
      "<a href=\"#\">Invalid URL</a>"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  # Using Sanitize gem
  get '/html_content' do
    content = params[:content]
    # ok: ruby-cross-site-scripting
    Sanitize.fragment(content, Sanitize::Config::BASIC)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  # Using JSON for data passing instead of HTML
  get '/api/user' do
    username = params[:username]
    # ok: ruby-cross-site-scripting
    content_type :json
    { user: username }.to_json
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  # Using content_tag helper from Rails
  get '/tag' do
    user_text = params[:text]
    helper = ActionView::Base.new
    # ok: ruby-cross-site-scripting
    helper.content_tag(:div, user_text)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  # Using explicit escaping with CGI
  get '/search' do
    query = params[:q]
    # ok: ruby-cross-site-scripting
    "<p>Results for: #{CGI.escapeHTML(query)}</p>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  # Using safe string concatenation with escaping
  get '/welcome' do
    name = request.cookies["name"]
    escaped_name = ERB::Util.html_escape(name)
    # ok: ruby-cross-site-scripting
    html = "<h1>Welcome back, " + escaped_name + "!</h1>"
    html
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  # Using Rails safe_join for HTML elements
  get '/items' do
    items = params[:items].split(',')
    escaped_items = items.map { |item| ERB::Util.html_escape(item) }
    # ok: ruby-cross-site-scripting
    ActionView::Base.new.safe_join(escaped_items.map { |item| "<li>#{item}</li>" })
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  # Using numeric or boolean parameters directly (safe by type)
  get '/count' do
    count = params[:count].to_i
    # ok: ruby-cross-site-scripting
    "<div>Count: #{count}</div>"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  # Using Rails raw helper only for trusted content
  get '/static_content' do
    static_content = "<strong>Welcome to our site!</strong>"  # Hardcoded, trusted content
    # ok: ruby-cross-site-scripting
    ActionView::Base.new.raw(static_content)
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  # Using input validation before output
  get '/color' do
    color = params[:color]
    valid_colors = ["red", "green", "blue", "yellow"]
    
    if valid_colors.include?(color.downcase)
      # ok: ruby-cross-site-scripting
      "<div style=\"color: #{color}\">Colored text</div>"
    else
      "<div>Invalid color selected</div>"
    end
  end
# {/fact}
end