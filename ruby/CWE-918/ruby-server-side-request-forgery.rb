# Ruby SSRF Vulnerability Examples
require 'net/http'
require 'uri'
require 'open-uri'
require 'rest-client'
require 'httparty'
require 'faraday'
require 'sinatra'
require 'rails'

# True Positive Examples (Vulnerable Code)

# Example 1: Basic SSRF with Net::HTTP
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_1
  # User-controlled URL from request parameter
  url = params[:url]
  
  # ruleid: ruby-server-side-request-forgery
  uri = URI(url)
  response = Net::HTTP.get_response(uri)
  
  return response.body
end
# {/fact}

# Example 2: SSRF with open-uri
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_2
  # User-controlled URL from request parameter
  url = params[:image_url]
  
  # ruleid: ruby-server-side-request-forgery
  content = open(url).read
  
  return content
end
# {/fact}

# Example 3: SSRF with RestClient
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_3
  # User-controlled URL from request parameter
  target = params[:api_endpoint]
  
  # ruleid: ruby-server-side-request-forgery
  response = RestClient.get(target)
  
  return response.body
end
# {/fact}

# Example 4: SSRF with HTTParty
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_4
  # User-controlled URL from request header
  callback_url = request.headers["X-Callback-URL"]
  
  # ruleid: ruby-server-side-request-forgery
  response = HTTParty.get(callback_url)
  
  return response.body
end
# {/fact}

# Example 5: SSRF with Faraday
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_5
  # User-controlled URL from request parameter
  endpoint = params[:endpoint]
  
  conn = Faraday.new
  # ruleid: ruby-server-side-request-forgery
  response = conn.get(endpoint)
  
  return response.body
end
# {/fact}

# Example 6: SSRF with URI.open (alias for open-uri)
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_6
  # User-controlled URL from request parameter
  file_url = params[:document_url]
  
  # ruleid: ruby-server-side-request-forgery
  content = URI.open(file_url).read
  
  return content
end
# {/fact}

# Example 7: SSRF with Net::HTTP.post
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_7
  # User-controlled URL from request parameter
  webhook = params[:webhook_url]
  
  uri = URI(webhook)
  # ruleid: ruby-server-side-request-forgery
  response = Net::HTTP.post(uri, "data=test")
  
  return response.body
end
# {/fact}

# Example 8: SSRF with RestClient.post
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_8
  # User-controlled URL from request parameter
  target = params[:target]
  data = { message: "Hello" }
  
  # ruleid: ruby-server-side-request-forgery
  response = RestClient.post(target, data)
  
  return response.code
end
# {/fact}

# Example 9: SSRF with string interpolation in URL
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_9
  # User-controlled subdomain from request parameter
  subdomain = params[:subdomain]
  
  # ruleid: ruby-server-side-request-forgery
  response = Net::HTTP.get(URI("https://#{subdomain}.example.com/api/data"))
  
  return response
end
# {/fact}

# Example 10: SSRF with Net::HTTP.start
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_10
  # User-controlled host and path from request parameters
  host = params[:host]
  path = params[:path]
  
  # ruleid: ruby-server-side-request-forgery
  Net::HTTP.start(host) do |http|
    response = http.get(path)
    return response.body
  end
# {/fact}
end

# Example 11: SSRF with Faraday and complex request
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_11
  # User-controlled URL from request parameter
  service_url = params[:service_url]
  
  conn = Faraday.new
  # ruleid: ruby-server-side-request-forgery
  response = conn.post do |req|
    req.url service_url
    req.headers['Content-Type'] = 'application/json'
    req.body = '{"query": "data"}'
  end
# {/fact}
  
  return response.body
end

# Example 12: SSRF with HTTParty and user-controlled path
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_12
  # User-controlled path from request parameter
  api_path = params[:api_path]
  base_url = "https://api.example.com"
  
  # ruleid: ruby-server-side-request-forgery
  response = HTTParty.get("#{base_url}#{api_path}")
  
  return response.parsed_response
end
# {/fact}

# Example 13: SSRF with RestClient and user-controlled headers
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_13
  # User-controlled URL from request parameter
  proxy_url = params[:proxy_url]
  
  # ruleid: ruby-server-side-request-forgery
  response = RestClient::Request.execute(
    method: :get,
    url: proxy_url,
    headers: { content_type: 'application/json' }
  )
  
  return response.body
end
# {/fact}

# Example 14: SSRF with open-uri and request cookies
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_14
  # User-controlled URL from cookie
  feed_url = request.cookies["feed_url"]
  
  # ruleid: ruby-server-side-request-forgery
  content = open(feed_url).read
  
  return content
end
# {/fact}

# Example 15: SSRF with Net::HTTP and JSON body
# {fact rule=server-side-request-forgery@v1.0 defects=1}
def bad_case_15
  # User-controlled URL from request JSON body
  callback = JSON.parse(request.body.read)["callback_url"]
  
  # ruleid: ruby-server-side-request-forgery
  uri = URI(callback)
  response = Net::HTTP.get_response(uri)
  
  return response.body
end
# {/fact}

# True Negative Examples (Safe Code)

# Example 1: Safe usage with whitelist validation
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_1
  # User-controlled URL from request parameter
  url = params[:url]
  
  # Whitelist of allowed domains
  allowed_domains = ['api.example.com', 'cdn.example.com']
  
  begin
    uri = URI(url)
    # ok: ruby-server-side-request-forgery
    if allowed_domains.include?(uri.host)
      response = Net::HTTP.get_response(uri)
      return response.body
    else
      return "Domain not allowed"
    end
  rescue URI::InvalidURIError
    return "Invalid URL"
  end
end
# {/fact}

# Example 2: Safe usage with regex validation
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_2
  # User-controlled URL from request parameter
  url = params[:image_url]
  
  # Validate URL format and domain
  # ok: ruby-server-side-request-forgery
  if url =~ /\A(https?:\/\/)?(www\.)?example\.com\/images\/[a-zA-Z0-9_\-\.]+\.(jpg|png|gif)\z/
    content = open(url).read
    return content
  else
    return "Invalid image URL"
  end
end
# {/fact}

# Example 3: Safe usage with hardcoded base URL
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_3
  # User-controlled path parameter
  resource_id = params[:id]
  
  # ok: ruby-server-side-request-forgery
  base_url = "https://api.example.com/resources/"
  response = RestClient.get("#{base_url}#{resource_id}")
  
  return response.body
end
# {/fact}

# Example 4: Safe usage with URL parsing and validation
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_4
  # User-controlled URL from request parameter
  target = params[:url]
  
  begin
    uri = URI(target)
    # ok: ruby-server-side-request-forgery
    if uri.host == "api.trusted-service.com" && uri.scheme == "https"
      response = HTTParty.get(target)
      return response.body
    else
      return "Invalid target URL"
    end
  rescue URI::InvalidURIError
    return "Invalid URL format"
  end
end
# {/fact}

# Example 5: Safe usage with predefined options
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_5
  # User selects from predefined options
  service_id = params[:service_id].to_i
  
  # Map of allowed services
  services = {
    1 => "https://api1.example.com/data",
    2 => "https://api2.example.com/data",
    3 => "https://api3.example.com/data"
  }
  
  # ok: ruby-server-side-request-forgery
  if services.key?(service_id)
    response = Faraday.get(services[service_id])
    return response.body
  else
    return "Invalid service ID"
  end
end
# {/fact}

# Example 6: Safe usage with URL builder function
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_6
  # User-controlled resource ID
  resource_id = params[:id]
  
  # ok: ruby-server-side-request-forgery
  def build_api_url(id)
    "https://api.example.com/resources/#{id}"
  end
  
  url = build_api_url(resource_id)
  content = URI.open(url).read
  
  return content
end
# {/fact}

# Example 7: Safe usage with domain validation
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_7
  # User-controlled URL from request parameter
  webhook = params[:webhook_url]
  
  begin
    uri = URI(webhook)
    # ok: ruby-server-side-request-forgery
    if uri.host.end_with?('.example.com') && uri.scheme == 'https'
      response = Net::HTTP.post(uri, "data=test")
      return response.body
    else
      return "Invalid webhook URL"
    end
  rescue URI::InvalidURIError
    return "Invalid URL format"
  end
end
# {/fact}

# Example 8: Safe usage with IP address validation
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_8
  # User-controlled host from request parameter
  host = params[:host]
  
  require 'ipaddr'
  
  begin
    # Check if it's an IP address
    ip = IPAddr.new(host)
    
    # ok: ruby-server-side-request-forgery
    # Reject private/internal IPs
    if ip.private? || ip.loopback?
      return "Access to internal IP addresses is not allowed"
    else
      response = RestClient.get("https://#{host}/api/public")
      return response.body
    end
  rescue IPAddr::InvalidAddressError
    # It's a hostname, validate domain
    if host =~ /\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i && !host.end_with?('.local', '.internal')
      response = RestClient.get("https://#{host}/api/public")
      return response.body
    else
      return "Invalid hostname"
    end
  end
end
# {/fact}

# Example 9: Safe usage with fixed URL and user parameters
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_9
  # User-controlled query parameter
  query = params[:search]
  
  # ok: ruby-server-side-request-forgery
  url = URI("https://api.example.com/search")
  url.query = URI.encode_www_form({ q: query })
  
  response = Net::HTTP.get_response(url)
  return response.body
end
# {/fact}

# Example 10: Safe usage with URL signing
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_10
  # User-controlled resource ID
  resource_id = params[:id]
  
  # ok: ruby-server-side-request-forgery
  def generate_signed_url(resource_id)
    base_url = "https://api.example.com/resources/#{resource_id}"
    secret_key = ENV['API_SECRET_KEY']
    timestamp = Time.now.to_i
    signature = Digest::SHA256.hexdigest("#{base_url}#{timestamp}#{secret_key}")
    "#{base_url}?timestamp=#{timestamp}&signature=#{signature}"
  end
  
  signed_url = generate_signed_url(resource_id)
  response = Net::HTTP.get_response(URI(signed_url))
  
  return response.body
end
# {/fact}

# Example 11: Safe usage with proxy service
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_11
  # User-controlled URL from request parameter
  external_url = params[:url]
  
  # ok: ruby-server-side-request-forgery
  # Use internal proxy service that validates URLs
  proxy_service_url = "https://internal-proxy.example.com/fetch"
  response = RestClient.post(proxy_service_url, { external_url: external_url })
  
  return response.body
end
# {/fact}

# Example 12: Safe usage with URL components
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_12
  # User-controlled path components
  category = params[:category]
  item_id = params[:item_id]
  
  # Validate components
  valid_categories = ['products', 'services', 'locations']
  
  # ok: ruby-server-side-request-forgery
  if valid_categories.include?(category) && item_id =~ /\A\d+\z/
    url = "https://api.example.com/#{category}/#{item_id}"
    response = HTTParty.get(url)
    return response.parsed_response
  else
    return "Invalid parameters"
  end
end
# {/fact}

# Example 13: Safe usage with URL pattern matching
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_13
  # User-controlled URL from request parameter
  image_url = params[:image_url]
  
  # ok: ruby-server-side-request-forgery
  # Validate URL against specific patterns
  valid_patterns = [
    /\Ahttps:\/\/cdn\.example\.com\/images\/[a-zA-Z0-9\-_]+\.(jpg|png|gif)\z/i,
    /\Ahttps:\/\/assets\.partner\.com\/public\/[a-zA-Z0-9\-_\/]+\.(jpg|png|gif)\z/i
  ]
  
  is_valid = valid_patterns.any? { |pattern| image_url =~ pattern }
  
  if is_valid
    content = open(image_url).read
    return content
  else
    return "Invalid image URL"
  end
end
# {/fact}

# Example 14: Safe usage with URL construction
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_14
  # User-controlled parameters
  user_id = params[:user_id]
  report_type = params[:report_type]
  
  # Validate parameters
  valid_report_types = ['summary', 'detailed', 'metrics']
  
  # ok: ruby-server-side-request-forgery
  if user_id =~ /\A\d+\z/ && valid_report_types.include?(report_type)
    api_url = "https://reports.example.com/users/#{user_id}/reports/#{report_type}"
    response = Faraday.get(api_url)
    return response.body
  else
    return "Invalid parameters"
  end
end
# {/fact}

# Example 15: Safe usage with environment-based URLs
# {fact rule=server-side-request-forgery@v1.0 defects=0}
def good_case_15
  # User-controlled resource identifier
  resource_id = params[:id]
  
  # ok: ruby-server-side-request-forgery
  # Get base URL from environment configuration
  api_base_url = ENV['API_BASE_URL'] || "https://api.example.com"
  
  if resource_id =~ /\A[a-zA-Z0-9\-_]+\z/
    url = "#{api_base_url}/resources/#{resource_id}"
    response = Net::HTTP.get_response(URI(url))
    return response.body
  else
    return "Invalid resource ID"
  end
end
# {/fact}