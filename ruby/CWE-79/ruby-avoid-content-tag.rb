# Example cases for ruby-avoid-content-tag rule
require 'action_view'
require 'sinatra'

class ContentTagExamples
  include ActionView::Helpers::TagHelper

  # True Positive Examples (Vulnerable Code)

  # Example 1: Directly using user input in content_tag
  get '/bad_case_1' do
    user_input = params[:user_input]
    # ruleid: ruby-avoid-content-tag
    content_tag(:div, user_input)
  end

  # Example 2: Using user input in content_tag with attributes
  get '/bad_case_2' do
    user_title = params[:title]
    # ruleid: ruby-avoid-content-tag
    content_tag(:h1, user_title, class: "header")
  end

  # Example 3: Using user input for tag name
  get '/bad_case_3' do
    tag_name = params[:tag]
    # ruleid: ruby-avoid-content-tag
    content_tag(tag_name.to_sym, "Content")
  end

  # Example 4: Using user input in nested content_tag
  get '/bad_case_4' do
    user_content = request.cookies["user_content"]
    # ruleid: ruby-avoid-content-tag
    content_tag(:div, content_tag(:p, user_content))
  end

  # Example 5: Using user input in content_tag with block
  get '/bad_case_5' do
    user_data = params[:data]
    # ruleid: ruby-avoid-content-tag
    content_tag(:div) do
      user_data
    end
  end

  # Example 6: Using user input from headers in content_tag
  get '/bad_case_6' do
    header_content = request.env["HTTP_X_CUSTOM_HEADER"]
    # ruleid: ruby-avoid-content-tag
    content_tag(:span, header_content, id: "header-content")
  end

  # Example 7: Using user input in content_tag with minimal processing
  get '/bad_case_7' do
    user_message = params[:message].strip
    # ruleid: ruby-avoid-content-tag
    content_tag(:p, user_message, class: "message")
  end

  # Example 8: Using user input in content_tag with string interpolation
  get '/bad_case_8' do
    username = params[:username]
    # ruleid: ruby-avoid-content-tag
    content_tag(:div, "Welcome, #{username}!")
  end

  # Example 9: Using user input in content_tag with concatenation
  get '/bad_case_9' do
    user_input = params[:input]
    # ruleid: ruby-avoid-content-tag
    content_tag(:div, "Your input: " + user_input)
  end

  # Example 10: Using user input in content_tag with attributes from user
  get '/bad_case_10' do
    user_content = params[:content]
    user_class = params[:class]
    # ruleid: ruby-avoid-content-tag
    content_tag(:div, user_content, class: user_class)
  end

  # Example 11: Using user input in content_tag within a loop
  get '/bad_case_11' do
    items = params[:items].split(',')
    result = ""
    items.each do |item|
      # ruleid: ruby-avoid-content-tag
      result += content_tag(:li, item)
    end
    result
  end

  # Example 12: Using user input in content_tag with conditional
  get '/bad_case_12' do
    user_input = params[:input]
    if user_input.length > 10
      # ruleid: ruby-avoid-content-tag
      content_tag(:div, user_input, class: "long")
    else
      # ruleid: ruby-avoid-content-tag
      content_tag(:div, user_input, class: "short")
    end
  end

  # Example 13: Using user input in content_tag with multiple arguments
  get '/bad_case_13' do
    title = params[:title]
    content = params[:content]
    # ruleid: ruby-avoid-content-tag
    content_tag(:div, content_tag(:h2, title) + content_tag(:p, content))
  end

  # Example 14: Using user input in content_tag with complex processing
  get '/bad_case_14' do
    user_data = params[:data]
    processed_data = user_data.gsub(/\s+/, " ").capitalize
    # ruleid: ruby-avoid-content-tag
    content_tag(:div, processed_data, class: "processed")
  end

  # Example 15: Using user input in content_tag with JSON data
  get '/bad_case_15' do
    require 'json'
    json_data = JSON.parse(request.body.read)
    user_message = json_data["message"]
    # ruleid: ruby-avoid-content-tag
    content_tag(:div, user_message, id: "json-message")
  end

  # True Negative Examples (Safe Code)

  # Example 1: Using static content in content_tag
  get '/good_case_1' do
    # ok: ruby-avoid-content-tag
    content_tag(:div, "Static content")
  end

  # Example 2: Using sanitized user input in content_tag
  get '/good_case_2' do
    require 'action_view'
    include ActionView::Helpers::SanitizeHelper
    user_input = params[:input]
    sanitized_input = sanitize(user_input)
    # ok: ruby-avoid-content-tag
    content_tag(:div, sanitized_input)
  end

  # Example 3: Using html_escape for user input
  get '/good_case_3' do
    include ERB::Util
    user_input = params[:input]
    safe_input = html_escape(user_input)
    # ok: ruby-avoid-content-tag
    content_tag(:div, safe_input)
  end

  # Example 4: Using content_tag with safe interpolation
  get '/good_case_4' do
    include ERB::Util
    username = html_escape(params[:username])
    # ok: ruby-avoid-content-tag
    content_tag(:div, "Welcome, #{username}!")
  end

  # Example 5: Using content_tag with manually escaped content
  get '/good_case_5' do
    user_input = params[:input].gsub('<', '&lt;').gsub('>', '&gt;')
    # ok: ruby-avoid-content-tag
    content_tag(:div, user_input)
  end

  # Example 6: Using content_tag with static content and dynamic attributes
  get '/good_case_6' do
    user_class = params[:class]
    # ok: ruby-avoid-content-tag
    content_tag(:div, "Static content", class: user_class)
  end

  # Example 7: Using alternative safe approach with html_safe
  get '/good_case_7' do
    include ERB::Util
    user_input = params[:input]
    safe_html = "<div>#{h(user_input)}</div>".html_safe
    # ok: ruby-avoid-content-tag
    safe_html
  end

  # Example 8: Using content_tag with safe dynamic content
  get '/good_case_8' do
    items = ["Item 1", "Item 2", "Item 3"] # Static list, not from user input
    result = ""
    items.each do |item|
      # ok: ruby-avoid-content-tag
      result += content_tag(:li, item)
    end
    result
  end

  # Example 9: Using content_tag with safe conditional content
  get '/good_case_9' do
    is_admin = current_user.admin? # Assuming this is determined server-side
    # ok: ruby-avoid-content-tag
    content_tag(:div, is_admin ? "Admin Panel" : "User Panel")
  end

  # Example 10: Using content_tag with safe processed content
  get '/good_case_10' do
    include ERB::Util
    user_input = params[:input]
    processed_input = h(user_input.upcase)
    # ok: ruby-avoid-content-tag
    content_tag(:div, processed_input)
  end

  # Example 11: Using content_tag with safe block content
  get '/good_case_11' do
    # ok: ruby-avoid-content-tag
    content_tag(:div, class: "container") do
      "Static content in a block"
    end
  end

  # Example 12: Using content_tag with safe nested tags
  get '/good_case_12' do
    # ok: ruby-avoid-content-tag
    content_tag(:div, content_tag(:p, "Static paragraph"))
  end

  # Example 13: Using content_tag with safe data from database
  get '/good_case_13' do
    product = Product.find(params[:id]) # Assuming this is a trusted database record
    # ok: ruby-avoid-content-tag
    content_tag(:h1, product.name) # Product name is trusted data from our database
  end

  # Example 14: Using content_tag with safe complex structure
  get '/good_case_14' do
    # ok: ruby-avoid-content-tag
    content_tag(:div, class: "profile") do
      content_tag(:h2, "User Profile") +
      content_tag(:p, "Static information")
    end
  end

  # Example 15: Using content_tag with safe JSON rendering
  get '/good_case_15' do
    require 'json'
    data = { name: "John", role: "Admin" } # Static data, not from user
    # ok: ruby-avoid-content-tag
    content_tag(:div, data.to_json, class: "json-data")
  end
end