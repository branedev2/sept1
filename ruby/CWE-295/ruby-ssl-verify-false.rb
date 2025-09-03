require 'net/http'
require 'uri'
require 'openssl'
require 'httparty'
require 'rest-client'
require 'faraday'
require 'typhoeus'
require 'excon'
require 'aws-sdk-s3'
require 'mysql2'

# True Positives (Vulnerable Code)

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_1
  uri = URI('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-ssl-verify-false
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  response = http.get('/')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_2
  uri = URI('https://api.example.com/data')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-ssl-verify-false
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
  request.body = { data: 'test' }.to_json
  response = http.request(request)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_3
  # ruleid: ruby-ssl-verify-false
  RestClient::Resource.new('https://api.example.com', verify_ssl: false).get
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_4
  # ruleid: ruby-ssl-verify-false
  HTTParty.get('https://api.example.com', verify: false)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_5
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-ssl-verify-false
    faraday.ssl.verify = false
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/endpoint')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_6
  # ruleid: ruby-ssl-verify-false
  request = Typhoeus::Request.new("https://api.example.com", ssl_verifypeer: false)
  response = request.run
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_7
  # ruleid: ruby-ssl-verify-false
  response = Excon.get('https://api.example.com', ssl_verify_peer: false)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_8
  uri = URI('https://example.com')
  Net::HTTP.start(uri.host, uri.port, 
                  use_ssl: true, 
                  # ruleid: ruby-ssl-verify-false
                  verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
    request = Net::HTTP::Get.new uri
    response = http.request request
    puts response.body
  end
# {/fact}
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_9
  # ruleid: ruby-ssl-verify-false
  s3_client = Aws::S3::Client.new(
    region: 'us-west-2',
    ssl_verify_peer: false
  )
  s3_client.list_buckets
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_10
  # ruleid: ruby-ssl-verify-false
  client = Mysql2::Client.new(
    host: "db.example.com",
    username: "user",
    password: "password",
    database: "mydb",
    sslverify: false
  )
  results = client.query("SELECT * FROM users")
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_11
  uri = URI('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-ssl-verify-false
  http.verify_mode = 0 # OpenSSL::SSL::VERIFY_NONE
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_12
  options = {
    use_ssl: true,
    # ruleid: ruby-ssl-verify-false
    verify_mode: OpenSSL::SSL::VERIFY_NONE
  }
  
  Net::HTTP.start('example.com', 443, options) do |http|
    response = http.get('/')
    puts response.body
  end
# {/fact}
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_13
  # Dynamic but still insecure
  verify_setting = false
  # ruleid: ruby-ssl-verify-false
  HTTParty.get('https://api.example.com', verify: verify_setting)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_14
  uri = URI('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-ssl-verify-false
  http.instance_variable_set(:@verify_mode, OpenSSL::SSL::VERIFY_NONE)
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_15
  # ruleid: ruby-ssl-verify-false
  conn = Faraday.new('https://api.example.com', ssl: {verify: false}) do |f|
    f.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/endpoint')
end

# True Negatives (Secure Code)

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_1
  uri = URI('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ok: ruby-ssl-verify-false
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  response = http.get('/')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_2
  uri = URI('https://api.example.com/data')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # Default is VERIFY_PEER, so no need to set it explicitly
  # ok: ruby-ssl-verify-false
  request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
  request.body = { data: 'test' }.to_json
  response = http.request(request)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_3
  # ok: ruby-ssl-verify-false
  RestClient::Resource.new('https://api.example.com', verify_ssl: true).get
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_4
  # ok: ruby-ssl-verify-false
  HTTParty.get('https://api.example.com', verify: true)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_5
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-ssl-verify-false
    faraday.ssl.verify = true
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/endpoint')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_6
  # ok: ruby-ssl-verify-false
  request = Typhoeus::Request.new("https://api.example.com", ssl_verifypeer: true)
  response = request.run
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_7
  # ok: ruby-ssl-verify-false
  response = Excon.get('https://api.example.com', ssl_verify_peer: true)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_8
  uri = URI('https://example.com')
  Net::HTTP.start(uri.host, uri.port, 
                  use_ssl: true, 
                  # ok: ruby-ssl-verify-false
                  verify_mode: OpenSSL::SSL::VERIFY_PEER) do |http|
    request = Net::HTTP::Get.new uri
    response = http.request request
    puts response.body
  end
# {/fact}
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_9
  # ok: ruby-ssl-verify-false
  s3_client = Aws::S3::Client.new(
    region: 'us-west-2',
    ssl_verify_peer: true
  )
  s3_client.list_buckets
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_10
  # ok: ruby-ssl-verify-false
  client = Mysql2::Client.new(
    host: "db.example.com",
    username: "user",
    password: "password",
    database: "mydb",
    sslverify: true
  )
  results = client.query("SELECT * FROM users")
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_11
  uri = URI('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ok: ruby-ssl-verify-false
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.ca_file = '/path/to/ca_cert.pem'
  response = http.get('/')
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_12
  # ok: ruby-ssl-verify-false
  conn = Faraday.new('https://api.example.com') do |f|
    f.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/endpoint')
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_13
  # ok: ruby-ssl-verify-false
  options = {
    use_ssl: true,
    # VERIFY_PEER is default, so not setting verify_mode is secure
  }
  
  Net::HTTP.start('example.com', 443, options) do |http|
    response = http.get('/')
    puts response.body
  end
# {/fact}
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_14
  # Dynamic but secure
  verify_setting = true
  # ok: ruby-ssl-verify-false
  HTTParty.get('https://api.example.com', verify: verify_setting)
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_15
  # ok: ruby-ssl-verify-false
  conn = Faraday.new('https://api.example.com', ssl: {verify: true}) do |f|
    f.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/endpoint')
end