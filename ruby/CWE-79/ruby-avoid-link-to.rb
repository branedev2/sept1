# This file contains test cases for the ruby-avoid-link-to rule
# which detects potential XSS vulnerabilities in Rails' link_to helper

require 'rails'
require 'action_controller'
require 'action_view'

class LinkToController < ActionController::Base
  include ActionView::Helpers::UrlHelper
  
  # True Positives (Vulnerable Code)
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_1
    # User input directly used in link_to href
    user_url = params[:url]
    
    # ruleid: ruby-avoid-link-to
    link_to "Click here", user_url
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_2
    # User input directly used in link_to with block
    user_url = params[:redirect]
    
    # ruleid: ruby-avoid-link-to
    link_to user_url do
      "Click this link"
    end
  # {/fact}
  end
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_3
    # User input in link_to with minimal processing
    user_url = params[:next_page].strip
    
    # ruleid: ruby-avoid-link-to
    link_to "Continue", user_url
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_4
    # User input from request headers
    referer = request.headers["Referer"]
    
    # ruleid: ruby-avoid-link-to
    link_to "Back to referring page", referer
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_5
    # User input with string interpolation
    profile = params[:username]
    
    # ruleid: ruby-avoid-link-to
    link_to "View Profile", "/users/#{profile}"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_6
    # User input from cookies
    last_visited = cookies[:last_page]
    
    # ruleid: ruby-avoid-link-to
    link_to "Return to last page", last_visited
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_7
    # User input with concatenation
    category = params[:category]
    
    # ruleid: ruby-avoid-link-to
    link_to "Browse category", "/products/category/" + category
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_8
    # User input in query parameters
    search_term = params[:q]
    
    # ruleid: ruby-avoid-link-to
    link_to "Search results", "/search?term=#{search_term}"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_9
    # User input in link text
    username = params[:name]
    
    # ruleid: ruby-avoid-link-to
    link_to username, "/profile"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_10
    # User input in both link text and URL
    product = params[:product]
    
    # ruleid: ruby-avoid-link-to
    link_to "View #{product}", "/products/#{product}"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_11
    # User input in HTML options hash
    user_id = params[:id]
    
    # ruleid: ruby-avoid-link-to
    link_to "User profile", "/users/profile", id: "user-#{user_id}"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_12
    # User input in data attributes
    action = params[:action_type]
    
    # ruleid: ruby-avoid-link-to
    link_to "Perform action", "/action", data: { type: action }
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_13
    # User input in onclick attribute
    callback = params[:callback]
    
    # ruleid: ruby-avoid-link-to
    link_to "Click me", "#", onclick: callback
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_14
    # User input from session
    return_url = session[:return_to]
    
    # ruleid: ruby-avoid-link-to
    link_to "Return", return_url
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=1}
  def bad_case_15
    # User input with conditional
    target = params[:external] == "true" ? params[:url] : "/internal"
    
    # ruleid: ruby-avoid-link-to
    link_to "Visit site", target
  end
  # {/fact}
  
  # True Negatives (Safe Code)
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_1
    # Static URL, no user input
    # ok: ruby-avoid-link-to
    link_to "Home", "/home"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_2
    # URL from routes helper
    # ok: ruby-avoid-link-to
    link_to "Products", products_path
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_3
    # User input properly validated with whitelist
    allowed_pages = ["home", "about", "contact"]
    page = params[:page]
    
    if allowed_pages.include?(page)
      # ok: ruby-avoid-link-to
      link_to "Go to #{page}", "/#{page}"
    else
      # ok: ruby-avoid-link-to
      link_to "Home", "/home"
    end
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_4
    # User input properly sanitized
    user_id = params[:id].to_i
    
    # ok: ruby-avoid-link-to
    link_to "User Profile", "/users/#{user_id}"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_5
    # URL generated from ActiveRecord object
    @product = Product.find(params[:id])
    
    # ok: ruby-avoid-link-to
    link_to @product.name, product_path(@product)
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_6
    # URL with properly escaped query parameters
    search = params[:q]
    
    # ok: ruby-avoid-link-to
    link_to "Search", search_path(query: search)
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_7
    # Using URL helpers with user input
    category = params[:category]
    
    # ok: ruby-avoid-link-to
    link_to "View category", category_path(id: category)
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_8
    # Using content_tag instead of link_to for dynamic content
    user_content = params[:content]
    
    # ok: ruby-avoid-link-to
    content_tag(:span, user_content)
    link_to "Static link", "/static"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_9
    # Using sanitize for user content in link text
    username = sanitize(params[:username])
    
    # ok: ruby-avoid-link-to
    link_to "Profile for #{username}", "/profiles"
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_10
    # Using html_safe only on known safe content
    static_url = "/about"
    
    # ok: ruby-avoid-link-to
    link_to "About Us".html_safe, static_url
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_11
    # Using routes with properly validated parameters
    id = params[:id].to_i
    
    if id > 0
      # ok: ruby-avoid-link-to
      link_to "View item #{id}", item_path(id)
    end
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_12
    # Using URI.parse to validate URLs
    require 'uri'
    
    begin
      url = params[:url]
      uri = URI.parse(url)
      if uri.scheme == "http" || uri.scheme == "https"
        # ok: ruby-avoid-link-to
        link_to "External site", url_for(host: uri.host, path: uri.path)
      end
    rescue URI::InvalidURIError
      # ok: ruby-avoid-link-to
      link_to "Home", root_path
    end
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_13
    # Using Rails' polymorphic_path for generating URLs
    @article = Article.find(params[:article_id])
    @comment = @article.comments.find(params[:id])
    
    # ok: ruby-avoid-link-to
    link_to "View comment", polymorphic_path([@article, @comment])
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_14
    # Using URL helpers with proper escaping
    tag = CGI.escape(params[:tag])
    
    # ok: ruby-avoid-link-to
    link_to "Tagged items", tagged_items_path(tag: tag)
  end
  # {/fact}
  
  # {fact rule=autoescape-disabled@v1.0 defects=0}
  def good_case_15
    # Using built-in Rails helper for safe URLs
    external_url = params[:url]
    
    if external_url.present?
      # ok: ruby-avoid-link-to
      link_to "External link", Rails.application.routes.url_helpers.safe_redirect_path(url: external_url)
    else
      # ok: ruby-avoid-link-to
      link_to "Home", root_path
    end
  end
  # {/fact}
end