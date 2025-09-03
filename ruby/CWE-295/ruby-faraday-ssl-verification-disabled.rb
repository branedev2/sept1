# frozen_string_literal: true

require 'faraday'
require 'net/http'
require 'openssl'
require 'uri'

# TRUE POSITIVES - Vulnerable cases where SSL verification is disabled

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_1
  # Basic case - SSL verification explicitly disabled with verify: false
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = false
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/users')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_2
  # Using ssl_verify option set to false
  # ruleid: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new(url: 'https://api.example.com', ssl: { verify: false })
  response = conn.post('/data', { name: 'test' })
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_3
  # Using ssl_verify option directly in the constructor
  # ruleid: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new('https://api.example.com', ssl_verify: false)
  response = conn.get('/users/1')
  puts response.status
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_4
  # Disabling verification in a variable first
  verify_ssl = false
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = verify_ssl
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/products')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_5
  # Setting SSL verification through options hash
  options = { ssl: { verify: false } }
  # ruleid: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new('https://api.example.com', options)
  response = conn.put('/update', { status: 'completed' })
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_6
  # Disabling verification after connection creation
  conn = Faraday.new(url: 'https://api.example.com')
  # ruleid: ruby-faraday-ssl-verification-disabled
  conn.ssl[:verify] = false
  response = conn.get('/status')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_7
  # Using a method to determine verification status
  def should_verify_ssl?
    return false # Always returns false for this example
  end
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = should_verify_ssl?
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/health')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_8
  # Using a constant for SSL verification
  SSL_VERIFY = false
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = SSL_VERIFY
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/metrics')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_9
  # Using a ternary operator that always results in false
  is_development = true
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = is_development ? false : true
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/data')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_10
  # Using string key instead of symbol
  # ruleid: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new(url: 'https://api.example.com', ssl: { 'verify' => false })
  response = conn.get('/users')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_11
  # Using SSL options with multiple settings
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    faraday.ssl = {
      # ruleid: ruby-faraday-ssl-verification-disabled
      verify: false,
      ca_file: '/path/to/ca_cert.pem',
      version: 'TLSv1_2'
    }
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/secure_endpoint')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_12
  # Using environment-based configuration that defaults to insecure
  verify_ssl = ENV['VERIFY_SSL'] == 'true'
  # Assuming ENV['VERIFY_SSL'] is not set or not 'true'
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = verify_ssl
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/api/v1/data')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_13
  # Using a complex condition that evaluates to false
  production = false
  testing = true
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ruleid: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = production && !testing
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.post('/submit', { data: 'test' })
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_14
  # Using a hash with indifferent access
  options = {}
  options[:ssl] = { verify: false }
  
  # ruleid: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new('https://api.example.com', options)
  response = conn.get('/resources')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_15
  # Using a method to configure the connection with SSL verification disabled
  def configure_connection(conn)
    conn.ssl[:verify] = false
  end
  
  conn = Faraday.new(url: 'https://api.example.com')
  # ruleid: ruby-faraday-ssl-verification-disabled
  configure_connection(conn)
  response = conn.get('/endpoint')
  puts response.body
end
# {/fact}

# TRUE NEGATIVES - Secure cases where SSL verification is properly enabled

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_1
  # Basic case - SSL verification explicitly enabled
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = true
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/users')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_2
  # Using ssl_verify option set to true
  # ok: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new(url: 'https://api.example.com', ssl: { verify: true })
  response = conn.post('/data', { name: 'test' })
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_3
  # Default behavior without specifying SSL verification (defaults to true)
  # ok: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new('https://api.example.com')
  response = conn.get('/users/1')
  puts response.status
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_4
  # Using a variable set to true
  verify_ssl = true
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = verify_ssl
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/products')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_5
  # Setting SSL verification through options hash to true
  options = { ssl: { verify: true } }
  # ok: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new('https://api.example.com', options)
  response = conn.put('/update', { status: 'completed' })
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_6
  # Setting verification after connection creation to true
  conn = Faraday.new(url: 'https://api.example.com')
  # ok: ruby-faraday-ssl-verification-disabled
  conn.ssl[:verify] = true
  response = conn.get('/status')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_7
  # Using a method that returns true for verification
  def should_verify_ssl?
    return true # Always returns true for this example
  end
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = should_verify_ssl?
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/health')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_8
  # Using a constant for SSL verification set to true
  SSL_VERIFY = true
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = SSL_VERIFY
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/metrics')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_9
  # Using a ternary operator that results in true
  is_development = false
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = is_development ? false : true
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/data')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_10
  # Using string key with true value
  # ok: ruby-faraday-ssl-verification-disabled
  conn = Faraday.new(url: 'https://api.example.com', ssl: { 'verify' => true })
  response = conn.get('/users')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_11
  # Using SSL options with multiple settings including verify: true
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    faraday.ssl = {
      # ok: ruby-faraday-ssl-verification-disabled
      verify: true,
      ca_file: '/path/to/ca_cert.pem',
      version: 'TLSv1_2'
    }
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/secure_endpoint')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_12
  # Using environment-based configuration that defaults to secure
  verify_ssl = ENV.fetch('VERIFY_SSL', 'true') == 'true'
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = verify_ssl
    faraday.adapter Faraday.default_adapter
  end
# {/fact}
  response = conn.get('/api/v1/data')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_13
  # Using a complex condition that evaluates to true
  production = true
  testing = false
  
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-faraday-ssl-verification-disabled
    faraday.ssl[:verify] = production || !testing
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.post('/submit', { data: 'test' })
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_14
  # Using custom CA certificate path with verification enabled
  conn = Faraday.new(url: 'https://api.example.com') do |faraday|
    # ok: ruby-faraday-ssl-verification-disabled
    faraday.ssl = {
      verify: true,
      ca_file: '/path/to/custom/ca_bundle.pem'
    }
    faraday.adapter :net_http
  end
# {/fact}
  response = conn.get('/resources')
  puts response.body
end

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_15
  # Using a method to configure the connection with SSL verification enabled
  def configure_secure_connection(conn)
    conn.ssl[:verify] = true
    conn.ssl[:version] = :TLSv1_2
  end
  
  conn = Faraday.new(url: 'https://api.example.com')
  # ok: ruby-faraday-ssl-verification-disabled
  configure_secure_connection(conn)
  response = conn.get('/endpoint')
  puts response.body
end
# {/fact}