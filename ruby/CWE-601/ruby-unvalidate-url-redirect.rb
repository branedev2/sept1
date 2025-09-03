# Necessary imports for the examples
require 'sinatra'
require 'rails'
require 'uri'
require 'net/http'
require 'rack'

# True Positive Examples (Vulnerable Code)

# Example 1: Basic redirect with user-controlled URL
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_1
  get '/redirect' do
    redirect_url = params[:url]
    # ruleid: ruby-unvalidate-url-redirect
    redirect redirect_url
  end
# {/fact}
end

# Example 2: Using user input in Rails redirect_to
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_2
  class UsersController < ApplicationController
    def profile
      target = params[:target_url]
      # ruleid: ruby-unvalidate-url-redirect
      redirect_to target
    end
  end
end
# {/fact}

# Example 3: Concatenating user input with base URL
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_3
  get '/go' do
    destination = "//" + params[:subdomain] + ".example.com"
    # ruleid: ruby-unvalidate-url-redirect
    redirect destination
  end
# {/fact}
end

# Example 4: Using header value for redirect
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_4
  get '/continue' do
    next_page = request.env['HTTP_REFERER']
    # ruleid: ruby-unvalidate-url-redirect
    redirect next_page
  end
# {/fact}
end

# Example 5: Using a cookie value for redirect
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_5
  get '/return' do
    return_url = request.cookies['return_to']
    # ruleid: ruby-unvalidate-url-redirect
    redirect return_url
  end
# {/fact}
end

# Example 6: Using POST data for redirect
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_6
  post '/process' do
    redirect_after = request.POST['redirect_after']
    # ruleid: ruby-unvalidate-url-redirect
    redirect redirect_after
  end
# {/fact}
end

# Example 7: Using JSON body parameter for redirect in Rails
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_7
  class ApiController < ApplicationController
    def process_action
      data = JSON.parse(request.body.read)
      callback_url = data['callback']
      # ruleid: ruby-unvalidate-url-redirect
      redirect_to callback_url
    end
  end
end
# {/fact}

# Example 8: Using path parameters for redirect
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_8
  get '/go/:destination' do
    target = params[:destination]
    # ruleid: ruby-unvalidate-url-redirect
    redirect "https://#{target}"
  end
# {/fact}
end

# Example 9: Using string interpolation with user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_9
  get '/visit' do
    site = params[:site]
    # ruleid: ruby-unvalidate-url-redirect
    redirect "#{site}/welcome"
  end
# {/fact}
end

# Example 10: Using multiple parameters to construct URL
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_10
  get '/navigate' do
    protocol = params[:protocol] || "https"
    domain = params[:domain]
    path = params[:path]
    # ruleid: ruby-unvalidate-url-redirect
    redirect "#{protocol}://#{domain}/#{path}"
  end
# {/fact}
end

# Example 11: Using request parameters in a complex URL construction
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_11
  get '/complex-redirect' do
    base = params[:base_url]
    query = params[:query] ? "?#{params[:query]}" : ""
    fragment = params[:fragment] ? "##{params[:fragment]}" : ""
    # ruleid: ruby-unvalidate-url-redirect
    redirect "#{base}#{query}#{fragment}"
  end
# {/fact}
end

# Example 12: Conditional redirect based on user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_12
  get '/conditional' do
    if params[:admin] == 'true'
      destination = params[:admin_url]
    else
      destination = params[:user_url]
    end
    # ruleid: ruby-unvalidate-url-redirect
    redirect destination
  end
# {/fact}
end

# Example 13: Using form data in Rails for redirect
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_13
  class FormController < ApplicationController
    def submit
      form_data = params.require(:form).permit(:redirect_url)
      # ruleid: ruby-unvalidate-url-redirect
      redirect_to form_data[:redirect_url]
    end
  end
end
# {/fact}

# Example 14: Using session data that could be controlled by user
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_14
  get '/return-to-saved' do
    # Session could be manipulated in some scenarios
    saved_url = session[:last_url]
    # ruleid: ruby-unvalidate-url-redirect
    redirect saved_url
  end
# {/fact}
end

# Example 15: Using a variable that indirectly contains user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_15
  get '/indirect' do
    temp_var = params[:destination]
    final_destination = temp_var
    # ruleid: ruby-unvalidate-url-redirect
    redirect final_destination
  end
# {/fact}
end

# True Negative Examples (Safe Code)

# Example 1: Using a whitelist of allowed redirect URLs
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_1
  get '/safe-redirect' do
    redirect_url = params[:url]
    allowed_urls = ['https://example.com', 'https://example.org']
    # ok: ruby-unvalidate-url-redirect
    redirect allowed_urls.include?(redirect_url) ? redirect_url : '/'
  end
# {/fact}
end

# Example 2: Using a relative URL (same-site redirect)
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_2
  get '/internal' do
    path = params[:path]
    # ok: ruby-unvalidate-url-redirect
    redirect "/#{path}"
  end
# {/fact}
end

# Example 3: Validating URL against allowed domains
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_3
  get '/validated-redirect' do
    url = params[:url]
    begin
      uri = URI.parse(url)
      # ok: ruby-unvalidate-url-redirect
      redirect url if uri.host == 'example.com'
    rescue URI::InvalidURIError
      redirect '/'
    end
  end
# {/fact}
end

# Example 4: Using a fixed URL with no user input
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_4
  get '/fixed' do
    # ok: ruby-unvalidate-url-redirect
    redirect 'https://example.com/welcome'
  end
# {/fact}
end

# Example 5: Validating URL format and domain
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_5
  get '/secure-redirect' do
    url = params[:url]
    if url =~ /\Ahttps:\/\/trusted\.example\.com\/[a-zA-Z0-9\/-]*\z/
      # ok: ruby-unvalidate-url-redirect
      redirect url
    else
      redirect '/'
    end
  end
# {/fact}
end

# Example 6: Using a path-only redirect with validation
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_6
  get '/path-only' do
    path = params[:path]
    if path =~ /\A[a-zA-Z0-9\/-]+\z/
      # ok: ruby-unvalidate-url-redirect
      redirect "/app/#{path}"
    else
      redirect '/app'
    end
  end
# {/fact}
end

# Example 7: Using Rails path helpers instead of raw URLs
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_7
  class ProfileController < ApplicationController
    def show
      user = User.find(params[:id])
      # ok: ruby-unvalidate-url-redirect
      redirect_to user_path(user)
    end
  end
end
# {/fact}

# Example 8: Using a URL builder with validation
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_8
  get '/builder' do
    page = params[:page]
    allowed_pages = ['home', 'about', 'contact']
    if allowed_pages.include?(page)
      # ok: ruby-unvalidate-url-redirect
      redirect "/pages/#{page}"
    else
      redirect '/pages/home'
    end
  end
# {/fact}
end

# Example 9: Using a URL mapping dictionary
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_9
  get '/map' do
    key = params[:page]
    url_map = {
      'home' => 'https://example.com/home',
      'about' => 'https://example.com/about',
      'contact' => 'https://example.com/contact'
    }
    # ok: ruby-unvalidate-url-redirect
    redirect url_map[key] || '/'
  end
# {/fact}
end

# Example 10: Validating URL protocol
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_10
  get '/protocol-check' do
    url = params[:url]
    if url.start_with?('https://example.com/')
      # ok: ruby-unvalidate-url-redirect
      redirect url
    else
      redirect 'https://example.com/'
    end
  end
# {/fact}
end

# Example 11: Using a signed URL to prevent tampering
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_11
  get '/signed-redirect' do
    url = params[:url]
    signature = params[:signature]
    expected_signature = Digest::SHA256.hexdigest(url + ENV['SECRET_KEY'])
    
    if Rack::Utils.secure_compare(signature, expected_signature)
      # ok: ruby-unvalidate-url-redirect
      redirect url
    else
      redirect '/'
    end
  end
# {/fact}
end

# Example 12: Using a safe default with optional validated redirect
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_12
  get '/optional-redirect' do
    default_url = 'https://example.com/dashboard'
    custom_url = params[:url]
    
    if custom_url && custom_url.start_with?('https://example.com/')
      # ok: ruby-unvalidate-url-redirect
      redirect custom_url
    else
      redirect default_url
    end
  end
# {/fact}
end

# Example 13: Using Rails routes for redirection
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_13
  class AppController < ApplicationController
    def navigate
      section = params[:section]
      allowed_sections = ['dashboard', 'profile', 'settings']
      
      if allowed_sections.include?(section)
        # ok: ruby-unvalidate-url-redirect
        redirect_to send("#{section}_path")
      else
        redirect_to root_path
      end
    end
  end
end
# {/fact}

# Example 14: Using a URL builder with domain validation
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_14
  get '/domain-check' do
    subdomain = params[:subdomain]
    allowed_subdomains = ['app', 'blog', 'shop']
    
    if allowed_subdomains.include?(subdomain)
      # ok: ruby-unvalidate-url-redirect
      redirect "https://#{subdomain}.example.com"
    else
      redirect 'https://example.com'
    end
  end
# {/fact}
end

# Example 15: Using strict validation with URI parsing
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_15
  get '/strict-validation' do
    url = params[:url]
    begin
      uri = URI.parse(url)
      allowed_hosts = ['example.com', 'api.example.com', 'cdn.example.com']
      
      if uri.scheme == 'https' && allowed_hosts.include?(uri.host)
        # ok: ruby-unvalidate-url-redirect
        redirect url
      else
        redirect 'https://example.com'
      end
    rescue URI::InvalidURIError
      redirect 'https://example.com'
    end
  end
# {/fact}
end