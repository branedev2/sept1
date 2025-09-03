# Excon SSL Verification Test Cases
require 'excon'

# True Positive Cases (Vulnerable)

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_1
  # Basic case with ssl_verify_peer explicitly set to false
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: false)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_2
  # Using a variable to set ssl_verify_peer to false
  verify = false
  # ruleid: ruby-excon-ssl-verify
  conn = Excon.new('https://api.example.com', ssl_verify_peer: verify)
  response = conn.post(
    path: '/data',
    body: 'example data'
  )
  puts response.status
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_3
  # Using a hash of options with ssl_verify_peer set to false
  options = {
    connect_timeout: 30,
    ssl_verify_peer: false,
    read_timeout: 60
  }
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', options)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_4
  # Using Excon::Connection with ssl_verify_peer set to false
  # ruleid: ruby-excon-ssl-verify
  connection = Excon::Connection.new(
    scheme: 'https',
    host: 'api.example.com',
    ssl_verify_peer: false
  )
  response = connection.request(method: :get, path: '/users')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_5
  # Using a method that returns false for ssl_verify_peer
  def get_verification_setting
    return false
  end
  
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: get_verification_setting)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_6
  # Using a ternary operator that evaluates to false
  env = 'development'
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: (env == 'production' ? true : false))
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_7
  # Setting ssl_verify_peer to false in a conditional block
  options = {}
  if ENV['ENVIRONMENT'] == 'development'
    options[:ssl_verify_peer] = false
  end
  
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', options)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_8
  # Using a constant for ssl_verify_peer set to false
  VERIFY_SSL = false
  
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: VERIFY_SSL)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_9
  # Using a more complex hash with nested options
  options = {
    headers: { 'Content-Type' => 'application/json' },
    connect_options: {
      ssl_verify_peer: false
    }
  }
  
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', options[:connect_options])
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_10
  # Using ssl_verify_peer: false with other SSL options
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', 
    ssl_verify_peer: false,
    ssl_ca_file: '/path/to/ca.crt',
    ssl_ca_path: '/path/to/certs/'
  )
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_11
  # Using a method call with multiple parameters including ssl_verify_peer: false
  def create_connection(url, verify_ssl)
    # ruleid: ruby-excon-ssl-verify
    Excon.new(url, ssl_verify_peer: verify_ssl)
  end
  
  connection = create_connection('https://api.example.com', false)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_12
  # Using a hash with string keys instead of symbols
  options = {
    'ssl_verify_peer' => false
  }
  
  # ruleid: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', options)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_13
  # Using ssl_verify_peer: false with request method directly
  # ruleid: ruby-excon-ssl-verify
  response = Excon.get('https://api.example.com', ssl_verify_peer: false)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_14
  # Using ssl_verify_peer: false with a POST request
  data = { name: 'John', email: 'john@example.com' }
  
  # ruleid: ruby-excon-ssl-verify
  response = Excon.post(
    'https://api.example.com/users',
    body: data.to_json,
    headers: { 'Content-Type' => 'application/json' },
    ssl_verify_peer: false
  )
  puts response.status
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=1}
def bad_case_15
  # Using ssl_verify_peer: false with a block
  # ruleid: ruby-excon-ssl-verify
  Excon.get('https://api.example.com', ssl_verify_peer: false) do |chunk, remaining_bytes, total_bytes|
    puts "Read #{chunk.size} bytes, #{remaining_bytes} bytes remaining"
  end
# {/fact}
end

# True Negative Cases (Secure)

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_1
  # Basic case with ssl_verify_peer explicitly set to true
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: true)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_2
  # Using default settings (ssl_verify_peer defaults to true)
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com')
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_3
  # Using a variable to set ssl_verify_peer to true
  verify = true
  # ok: ruby-excon-ssl-verify
  conn = Excon.new('https://api.example.com', ssl_verify_peer: verify)
  response = conn.post(
    path: '/data',
    body: 'example data'
  )
  puts response.status
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_4
  # Using a hash of options with ssl_verify_peer set to true
  options = {
    connect_timeout: 30,
    ssl_verify_peer: true,
    read_timeout: 60
  }
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', options)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_5
  # Using Excon::Connection with ssl_verify_peer set to true
  # ok: ruby-excon-ssl-verify
  connection = Excon::Connection.new(
    scheme: 'https',
    host: 'api.example.com',
    ssl_verify_peer: true
  )
  response = connection.request(method: :get, path: '/users')
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_6
  # Using a method that returns true for ssl_verify_peer
  def get_verification_setting
    return true
  end
  
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: get_verification_setting)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_7
  # Using a ternary operator that evaluates to true
  env = 'production'
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: (env == 'production' ? true : false))
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_8
  # Setting custom CA file with ssl_verify_peer defaulting to true
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', 
    ssl_ca_file: '/path/to/ca.crt'
  )
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_9
  # Using a constant for ssl_verify_peer set to true
  VERIFY_SSL = true
  
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: VERIFY_SSL)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_10
  # Using ssl_verify_peer: true with other SSL options
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', 
    ssl_verify_peer: true,
    ssl_ca_file: '/path/to/ca.crt',
    ssl_ca_path: '/path/to/certs/'
  )
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_11
  # Using HTTP instead of HTTPS (ssl_verify_peer not relevant)
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('http://api.example.com')
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_12
  # Using a method call with multiple parameters including ssl_verify_peer: true
  def create_connection(url, verify_ssl)
    # ok: ruby-excon-ssl-verify
    Excon.new(url, ssl_verify_peer: verify_ssl)
  end
  
  connection = create_connection('https://api.example.com', true)
  response = connection.get
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_13
  # Using ssl_verify_peer: true with request method directly
  # ok: ruby-excon-ssl-verify
  response = Excon.get('https://api.example.com', ssl_verify_peer: true)
  puts response.body
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_14
  # Using ssl_verify_peer: true with a POST request
  data = { name: 'John', email: 'john@example.com' }
  
  # ok: ruby-excon-ssl-verify
  response = Excon.post(
    'https://api.example.com/users',
    body: data.to_json,
    headers: { 'Content-Type' => 'application/json' },
    ssl_verify_peer: true
  )
  puts response.status
end
# {/fact}

# {fact rule=improper-certificate-validation@v1.0 defects=0}
def good_case_15
  # Using environment variable to set ssl_verify_peer to true
  verify_ssl = ENV['VERIFY_SSL'] != 'false'
  
  # ok: ruby-excon-ssl-verify
  connection = Excon.new('https://api.example.com', ssl_verify_peer: verify_ssl)
  response = connection.get
  puts response.body
end
# {/fact}