require 'net/http'
require 'net/https'
require 'openssl'
require 'uri'
require 'rest-client'
require 'faraday'
require 'httparty'
require 'typhoeus'

# True Positive Cases (Vulnerable Code)

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_1
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-request-without-validation
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_2
  uri = URI('https://api.example.com/data')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-request-without-validation
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  request = Net::HTTP::Post.new(uri.path, {'Content-Type' => 'application/json'})
  request.body = {data: 'example'}.to_json
  response = http.request(request)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_3
  # Using a variable to store the insecure verification mode
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  verify_mode_value = OpenSSL::SSL::VERIFY_NONE
  # ruleid: ruby-request-without-validation
  http.verify_mode = verify_mode_value
  response = http.get('/api/users')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_4
  # Using RestClient with SSL verification disabled
  # ruleid: ruby-request-without-validation
  RestClient::Resource.new(
    'https://api.example.com',
    :verify_ssl => OpenSSL::SSL::VERIFY_NONE
  ).get
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_5
  # Using Faraday with SSL verification disabled
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-request-without-validation
    faraday.ssl.verify = false
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/users')
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_6
  # Using HTTParty with SSL verification disabled
  # ruleid: ruby-request-without-validation
  HTTParty.get('https://api.example.com', verify: false)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_7
  # Using Typhoeus with SSL verification disabled
  request = Typhoeus::Request.new(
    'https://api.example.com',
    method: :get,
    # ruleid: ruby-request-without-validation
    ssl_verifypeer: false
  )
  response = request.run
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_8
  # Using Net::HTTP.start with SSL verification disabled
  uri = URI('https://api.example.com')
  Net::HTTP.start(uri.host, uri.port, 
    :use_ssl => true, 
    # ruleid: ruby-request-without-validation
    :verify_mode => OpenSSL::SSL::VERIFY_NONE
  ) do |http|
    request = Net::HTTP::Get.new(uri)
    response = http.request(request)
  end
# {/fact}
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_9
  # Using OpenSSL::SSL::SSLContext with verification disabled
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  ssl_context = OpenSSL::SSL::SSLContext.new
  # ruleid: ruby-request-without-validation
  ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.ssl_context = ssl_context
  
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_10
  # Using a method that returns VERIFY_NONE
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  def get_verify_mode
    OpenSSL::SSL::VERIFY_NONE
  end
  
  # ruleid: ruby-request-without-validation
  http.verify_mode = get_verify_mode
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_11
  # Using conditional to set verify_mode to VERIFY_NONE
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  dev_mode = true
  if dev_mode
    # ruleid: ruby-request-without-validation
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end
  
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_12
  # Using RestClient with verify_ssl: false
  # ruleid: ruby-request-without-validation
  RestClient::Resource.new(
    'https://api.example.com',
    :verify_ssl => false
  ).get
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_13
  # Using Net::HTTP with multiple SSL options including disabled verification
  uri = URI('https://api.example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.ssl_timeout = 5
  # ruleid: ruby-request-without-validation
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.ciphers = ['TLS_AES_256_GCM_SHA384']
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_14
  # Using HTTParty with multiple options including disabled verification
  options = {
    headers: { 'Content-Type' => 'application/json' },
    timeout: 10,
    # ruleid: ruby-request-without-validation
    verify: false,
    body: { data: 'example' }.to_json
  }
  HTTParty.post('https://api.example.com', options)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_15
  # Using Faraday with complex configuration including disabled verification
  conn = Faraday.new do |faraday|
    faraday.url_prefix = 'https://api.example.com'
    faraday.request :json
    faraday.response :json, content_type: /\bjson$/
    # ruleid: ruby-request-without-validation
    faraday.ssl.verify = false
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/data')
end

# True Negative Cases (Secure Code)

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_1
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ok: ruby-request-without-validation
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_2
  uri = URI('https://api.example.com/data')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # Default is VERIFY_PEER, no need to set explicitly
  # ok: ruby-request-without-validation
  request = Net::HTTP::Post.new(uri.path, {'Content-Type' => 'application/json'})
  request.body = {data: 'example'}.to_json
  response = http.request(request)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_3
  # Using a variable to store the secure verification mode
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  verify_mode_value = OpenSSL::SSL::VERIFY_PEER
  # ok: ruby-request-without-validation
  http.verify_mode = verify_mode_value
  response = http.get('/api/users')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_4
  # Using RestClient with SSL verification enabled (default)
  # ok: ruby-request-without-validation
  RestClient::Resource.new(
    'https://api.example.com',
    :verify_ssl => true
  ).get
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_5
  # Using Faraday with SSL verification enabled (default)
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-request-without-validation
    faraday.ssl.verify = true
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/users')
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_6
  # Using HTTParty with SSL verification enabled (default)
  # ok: ruby-request-without-validation
  HTTParty.get('https://api.example.com', verify: true)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_7
  # Using Typhoeus with SSL verification enabled
  request = Typhoeus::Request.new(
    'https://api.example.com',
    method: :get,
    # ok: ruby-request-without-validation
    ssl_verifypeer: true
  )
  response = request.run
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_8
  # Using Net::HTTP.start with SSL verification enabled
  uri = URI('https://api.example.com')
  Net::HTTP.start(uri.host, uri.port, 
    :use_ssl => true, 
    # ok: ruby-request-without-validation
    :verify_mode => OpenSSL::SSL::VERIFY_PEER
  ) do |http|
    request = Net::HTTP::Get.new(uri)
    response = http.request(request)
  end
# {/fact}
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_9
  # Using OpenSSL::SSL::SSLContext with verification enabled
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  ssl_context = OpenSSL::SSL::SSLContext.new
  # ok: ruby-request-without-validation
  ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.ssl_context = ssl_context
  
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_10
  # Using a method that returns VERIFY_PEER
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  def get_verify_mode
    OpenSSL::SSL::VERIFY_PEER
  end
  
  # ok: ruby-request-without-validation
  http.verify_mode = get_verify_mode
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_11
  # Using conditional but still maintaining secure verification
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  dev_mode = true
  # ok: ruby-request-without-validation
  http.verify_mode = dev_mode ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_PEER
  
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_12
  # Using RestClient with explicit certificate path
  # ok: ruby-request-without-validation
  RestClient::Resource.new(
    'https://api.example.com',
    :ssl_ca_file => '/path/to/ca_cert.pem'
  ).get
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_13
  # Using Net::HTTP with certificate store
  uri = URI('https://api.example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  cert_store = OpenSSL::X509::Store.new
  cert_store.set_default_paths
  # ok: ruby-request-without-validation
  http.cert_store = cert_store
  
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_14
  # Using HTTParty with custom certificate
  options = {
    headers: { 'Content-Type' => 'application/json' },
    # ok: ruby-request-without-validation
    ssl_ca_file: '/path/to/ca_cert.pem',
    body: { data: 'example' }.to_json
  }
  HTTParty.post('https://api.example.com', options)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_15
  # Using Faraday with complex configuration including proper verification
  conn = Faraday.new do |faraday|
    faraday.url_prefix = 'https://api.example.com'
    faraday.request :json
    faraday.response :json, content_type: /\bjson$/
    # ok: ruby-request-without-validation
    faraday.ssl.ca_file = '/path/to/ca_cert.pem'
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/data')
end