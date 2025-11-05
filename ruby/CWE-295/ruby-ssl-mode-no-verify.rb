require 'openssl'
require 'net/https'
require 'uri'
require 'aws-sdk-s3'
require 'mysql2'
require 'pg'
require 'mongo'
require 'faraday'
require 'rest-client'
require 'httparty'

# True Positive Examples (Vulnerable Code)

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_1
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-ssl-mode-no-verify
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  response = http.get('/')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_2
  uri = URI('https://api.example.org/data')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-ssl-mode-no-verify
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
  request.body = {data: 'sensitive information'}.to_json
  response = http.request(request)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_3
  # Creating a custom SSL context with verification disabled
  ssl_context = OpenSSL::SSL::SSLContext.new
  # ruleid: ruby-ssl-mode-no-verify
  ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
  
  uri = URI.parse('https://payment.example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.ssl_context = ssl_context
  response = http.get('/process_payment')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_4
  # Disabling verification in a banking API client
  def create_ssl_client
    client = Net::HTTP.new('banking-api.example.com', 443)
    client.use_ssl = true
    # ruleid: ruby-ssl-mode-no-verify
    client.verify_mode = OpenSSL::SSL::VERIFY_NONE
    return client
  end
  
  client = create_ssl_client
  response = client.get('/account/balance')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_5
  # Conditional but still vulnerable
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  if ENV['ENVIRONMENT'] == 'development'
    # ruleid: ruby-ssl-mode-no-verify
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  else
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  end
  
  response = http.get('/')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_6
  # Using RestClient with SSL verification disabled
  # ruleid: ruby-ssl-mode-no-verify
  response = RestClient::Request.execute(
    method: :get,
    url: 'https://api.example.com/data',
    verify_ssl: OpenSSL::SSL::VERIFY_NONE
  )
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_7
  # Using Faraday with SSL verification disabled
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-ssl-mode-no-verify
    faraday.ssl.verify = false
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/endpoint')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_8
  # Using HTTParty with SSL verification disabled
  # ruleid: ruby-ssl-mode-no-verify
  response = HTTParty.get('https://api.example.com/data', verify: false)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_9
  # Using AWS SDK with SSL verification disabled
  # ruleid: ruby-ssl-mode-no-verify
  s3_client = Aws::S3::Client.new(
    region: 'us-west-2',
    ssl_verify_peer: false
  )
  response = s3_client.get_object(bucket: 'my-bucket', key: 'my-object')
  puts response.body.read
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_10
  # Using MongoDB with SSL verification disabled
  # ruleid: ruby-ssl-mode-no-verify
  client = Mongo::Client.new(['mongodb.example.com:27017'], 
    database: 'my_database',
    ssl: true,
    ssl_verify: false
  )
  collection = client[:users]
  document = collection.find(name: 'John').first
  puts document
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_11
  # Using MySQL with SSL verification disabled
  # ruleid: ruby-ssl-mode-no-verify
  client = Mysql2::Client.new(
    host: 'mysql.example.com',
    username: 'user',
    password: 'password',
    database: 'my_db',
    sslca: '/path/to/ca.pem',
    sslverify: false
  )
  results = client.query("SELECT * FROM users")
  puts results.first
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_12
  # Using PostgreSQL with SSL verification disabled
  # ruleid: ruby-ssl-mode-no-verify
  conn = PG.connect(
    host: 'postgres.example.com',
    user: 'postgres',
    password: 'password',
    dbname: 'my_database',
    sslmode: 'require',
    sslrootcert: '/path/to/server-ca.pem',
    sslverifyfull: false
  )
  result = conn.exec("SELECT * FROM users")
  puts result.first
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_13
  # Using a wrapper function that disables verification
  def fetch_data(url)
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    # ruleid: ruby-ssl-mode-no-verify
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    response = http.get(uri.path)
    return response.body
  end
  
  data = fetch_data('https://api.example.com/data')
  puts data
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_14
  # Using a constant for the verify mode
  VERIFY_MODE = OpenSSL::SSL::VERIFY_NONE
  
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-ssl-mode-no-verify
  http.verify_mode = VERIFY_MODE
  response = http.get('/')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_15
  # Using a method to determine verify mode but returning VERIFY_NONE
  def get_verify_mode
    # Some logic that ultimately returns VERIFY_NONE
    return OpenSSL::SSL::VERIFY_NONE
  end
  
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ruleid: ruby-ssl-mode-no-verify
  http.verify_mode = get_verify_mode
  response = http.get('/')
  puts response.body
end
# {/fact}

# True Negative Examples (Secure Code)

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_1
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ok: ruby-ssl-mode-no-verify
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  response = http.get('/')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_2
  uri = URI('https://api.example.org/data')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # Default is VERIFY_PEER, so no need to set it explicitly
  # ok: ruby-ssl-mode-no-verify
  request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
  request.body = {data: 'sensitive information'}.to_json
  response = http.request(request)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_3
  # Creating a custom SSL context with verification enabled
  ssl_context = OpenSSL::SSL::SSLContext.new
  # ok: ruby-ssl-mode-no-verify
  ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  
  uri = URI.parse('https://payment.example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.ssl_context = ssl_context
  response = http.get('/process_payment')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_4
  # Setting up a secure banking API client
  def create_ssl_client
    client = Net::HTTP.new('banking-api.example.com', 443)
    client.use_ssl = true
    # ok: ruby-ssl-mode-no-verify
    client.verify_mode = OpenSSL::SSL::VERIFY_PEER
    client.ca_file = '/path/to/ca_certificates.pem'
    return client
  end
  
  client = create_ssl_client
  response = client.get('/account/balance')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_5
  # Always using VERIFY_PEER regardless of environment
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  # ok: ruby-ssl-mode-no-verify
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  
  # Additional security settings
  if ENV['ENVIRONMENT'] == 'production'
    http.ca_file = '/path/to/ca_certificates.pem'
  end
  
  response = http.get('/')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_6
  # Using RestClient with SSL verification enabled
  # ok: ruby-ssl-mode-no-verify
  response = RestClient::Request.execute(
    method: :get,
    url: 'https://api.example.com/data',
    verify_ssl: OpenSSL::SSL::VERIFY_PEER
  )
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_7
  # Using Faraday with SSL verification enabled
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-ssl-mode-no-verify
    faraday.ssl.verify = true
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/endpoint')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_8
  # Using HTTParty with SSL verification enabled
  # ok: ruby-ssl-mode-no-verify
  response = HTTParty.get('https://api.example.com/data', verify: true)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_9
  # Using AWS SDK with SSL verification enabled
  # ok: ruby-ssl-mode-no-verify
  s3_client = Aws::S3::Client.new(
    region: 'us-west-2',
    ssl_verify_peer: true
  )
  response = s3_client.get_object(bucket: 'my-bucket', key: 'my-object')
  puts response.body.read
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_10
  # Using MongoDB with SSL verification enabled
  # ok: ruby-ssl-mode-no-verify
  client = Mongo::Client.new(['mongodb.example.com:27017'], 
    database: 'my_database',
    ssl: true,
    ssl_verify: true,
    ssl_ca_cert: '/path/to/ca.pem'
  )
  collection = client[:users]
  document = collection.find(name: 'John').first
  puts document
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_11
  # Using MySQL with SSL verification enabled
  # ok: ruby-ssl-mode-no-verify
  client = Mysql2::Client.new(
    host: 'mysql.example.com',
    username: 'user',
    password: 'password',
    database: 'my_db',
    sslca: '/path/to/ca.pem',
    sslverify: true
  )
  results = client.query("SELECT * FROM users")
  puts results.first
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_12
  # Using PostgreSQL with SSL verification enabled
  # ok: ruby-ssl-mode-no-verify
  conn = PG.connect(
    host: 'postgres.example.com',
    user: 'postgres',
    password: 'password',
    dbname: 'my_database',
    sslmode: 'verify-full',
    sslrootcert: '/path/to/server-ca.pem'
  )
  result = conn.exec("SELECT * FROM users")
  puts result.first
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_13
  # Using a wrapper function that enables verification
  def fetch_data_securely(url)
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    # ok: ruby-ssl-mode-no-verify
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.ca_file = '/path/to/ca_certificates.pem'
    response = http.get(uri.path)
    return response.body
  end
  
  data = fetch_data_securely('https://api.example.com/data')
  puts data
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_14
  # Using a constant for the verify mode
  VERIFY_MODE = OpenSSL::SSL::VERIFY_PEER
  
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ok: ruby-ssl-mode-no-verify
  http.verify_mode = VERIFY_MODE
  response = http.get('/')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_15
  # Using a method to determine verify mode and returning VERIFY_PEER
  def get_secure_verify_mode
    # Some logic that ultimately returns VERIFY_PEER
    return OpenSSL::SSL::VERIFY_PEER
  end
  
  uri = URI.parse('https://example.com')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # ok: ruby-ssl-mode-no-verify
  http.verify_mode = get_secure_verify_mode
  response = http.get('/')
  puts response.body
end
# {/fact}