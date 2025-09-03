# frozen_string_literal: true
require 'jwt'
require 'sinatra'

# True Positives (Vulnerable Code)

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_1
  payload = { 'user_id' => 123, 'admin' => true }
  # ruleid: ruby-jwt-none-algorithm
  token = JWT.encode(payload, nil, 'none')
  return token
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_2
  user_data = { 'username' => 'alice', 'role' => 'admin' }
  secret = 'super_secret_key'
  # ruleid: ruby-jwt-none-algorithm
  JWT.encode(user_data, secret, 'none')
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_3
  claims = { 'sub' => '1234567890', 'name' => 'John Doe' }
  # ruleid: ruby-jwt-none-algorithm
  token = JWT.encode(claims, 'any-key-will-be-ignored', 'none')
  puts "Generated token: #{token}"
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_4
  get '/generate_token' do
    user_id = params[:user_id]
    # ruleid: ruby-jwt-none-algorithm
    token = JWT.encode({ 'user_id' => user_id }, nil, 'none')
    { token: token }.to_json
  end
# {/fact}
end

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_5
  def create_session(user)
    payload = { user_id: user.id, exp: Time.now.to_i + 3600 }
    # ruleid: ruby-jwt-none-algorithm
    JWT.encode(payload, 'unused-secret', 'none')
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_6
  class AuthService
    def self.generate_token(user_id)
      payload = { 'uid' => user_id, 'iat' => Time.now.to_i }
      # ruleid: ruby-jwt-none-algorithm
      JWT.encode(payload, 'dummy-key', 'none')
    end
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_7
  post '/login' do
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      payload = { user_id: user.id }
      # ruleid: ruby-jwt-none-algorithm
      token = JWT.encode(payload, 'any-key', 'none')
      { token: token }.to_json
    else
      status 401
      { error: 'Invalid credentials' }.to_json
    end
  end
# {/fact}
end

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_8
  def generate_public_token
    data = { 'public_data' => 'viewable by anyone' }
    # ruleid: ruby-jwt-none-algorithm
    JWT.encode(data, '', 'none')
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_9
  class JWTHelper
    ALGORITHMS = {
      secure: 'HS256',
      public: 'none'
    }
    
    def self.create_token(data, type = :secure)
      secret = ENV['JWT_SECRET'] || 'fallback-secret'
      # ruleid: ruby-jwt-none-algorithm
      JWT.encode(data, secret, ALGORITHMS[type])
    end
  end
  
  # Creating a public token with none algorithm
  JWTHelper.create_token({ 'data' => 'test' }, :public)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_10
  def create_temporary_token(data)
    # ruleid: ruby-jwt-none-algorithm
    JWT.encode(data.merge(exp: Time.now.to_i + 300), 'not-used', 'none')
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_11
  module TokenGenerator
    def self.unsigned_token(payload)
      # ruleid: ruby-jwt-none-algorithm
      JWT.encode(payload, nil, 'none')
    end
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_12
  get '/api/public-data' do
    payload = { data: 'public', timestamp: Time.now.to_i }
    alg = request.params['debug'] == 'true' ? 'none' : 'HS256'
    secret = ENV['JWT_SECRET'] || 'default-secret'
    # ruleid: ruby-jwt-none-algorithm
    token = JWT.encode(payload, secret, alg)
    { token: token }.to_json
  end
# {/fact}
end

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_13
  class AuthToken
    ALGORITHMS = ['HS256', 'HS384', 'HS512', 'none']
    
    def self.generate(payload, algorithm_index)
      secret = ENV['JWT_SECRET'] || 'fallback'
      # ruleid: ruby-jwt-none-algorithm
      JWT.encode(payload, secret, ALGORITHMS[algorithm_index])
    end
  end
  
  # Using none algorithm (index 3)
  AuthToken.generate({ user_id: 42 }, 3)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_14
  def create_token_with_algorithm(payload, algorithm)
    secret = algorithm == 'none' ? nil : 'my-secret'
    # ruleid: ruby-jwt-none-algorithm
    JWT.encode(payload, secret, algorithm)
  end
  
  create_token_with_algorithm({ 'data' => 'test' }, 'none')
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_15
  config = {
    algorithm: 'none',
    secret: 'not-needed-for-none'
  }
  
  def generate_token_from_config(user_data, config)
    # ruleid: ruby-jwt-none-algorithm
    JWT.encode(user_data, config[:secret], config[:algorithm])
  end
  
  generate_token_from_config({ user_id: 123 }, config)
end
# {/fact}

# True Negatives (Secure Code)

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_1
  payload = { 'user_id' => 123, 'admin' => true }
  secret = 'super_secret_key'
  # ok: ruby-jwt-none-algorithm
  token = JWT.encode(payload, secret, 'HS256')
  return token
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_2
  user_data = { 'username' => 'alice', 'role' => 'admin' }
  secret = ENV['JWT_SECRET']
  # ok: ruby-jwt-none-algorithm
  JWT.encode(user_data, secret, 'HS512')
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_3
  claims = { 'sub' => '1234567890', 'name' => 'John Doe' }
  private_key = OpenSSL::PKey::RSA.generate(2048)
  # ok: ruby-jwt-none-algorithm
  token = JWT.encode(claims, private_key, 'RS256')
  puts "Generated token: #{token}"
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_4
  get '/generate_token' do
    user_id = params[:user_id]
    secret = ENV['JWT_SECRET']
    # ok: ruby-jwt-none-algorithm
    token = JWT.encode({ 'user_id' => user_id }, secret, 'HS384')
    { token: token }.to_json
  end
# {/fact}
end

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_5
  def create_session(user)
    payload = { user_id: user.id, exp: Time.now.to_i + 3600 }
    secret = Rails.application.credentials.secret_key_base
    # ok: ruby-jwt-none-algorithm
    JWT.encode(payload, secret, 'HS256')
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_6
  class AuthService
    def self.generate_token(user_id)
      payload = { 'uid' => user_id, 'iat' => Time.now.to_i }
      secret = ENV.fetch('JWT_SECRET')
      # ok: ruby-jwt-none-algorithm
      JWT.encode(payload, secret, 'HS256')
    end
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_7
  post '/login' do
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      payload = { user_id: user.id }
      secret = ENV['JWT_SECRET']
      # ok: ruby-jwt-none-algorithm
      token = JWT.encode(payload, secret, 'HS256')
      { token: token }.to_json
    else
      status 401
      { error: 'Invalid credentials' }.to_json
    end
  end
# {/fact}
end

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_8
  def generate_secure_token
    data = { 'data' => 'sensitive information' }
    secret = Rails.application.credentials.secret_key_base
    # ok: ruby-jwt-none-algorithm
    JWT.encode(data, secret, 'HS512')
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_9
  class JWTHelper
    ALGORITHMS = {
      default: 'HS256',
      high_security: 'HS512'
    }
    
    def self.create_token(data, type = :default)
      secret = ENV['JWT_SECRET'] || raise('JWT_SECRET not configured')
      # ok: ruby-jwt-none-algorithm
      JWT.encode(data, secret, ALGORITHMS[type])
    end
  end
  
  # Creating a token with HS256 algorithm
  JWTHelper.create_token({ 'data' => 'test' })
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_10
  def create_token_with_expiry(data)
    secret = ENV.fetch('JWT_SECRET')
    # ok: ruby-jwt-none-algorithm
    JWT.encode(data.merge(exp: Time.now.to_i + 3600), secret, 'HS256')
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_11
  module TokenGenerator
    def self.signed_token(payload)
      secret = ENV['JWT_SECRET'] || raise('Missing JWT_SECRET')
      # ok: ruby-jwt-none-algorithm
      JWT.encode(payload, secret, 'HS384')
    end
  end
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_12
  get '/api/secure-data' do
    payload = { data: 'secure', timestamp: Time.now.to_i }
    secret = ENV['JWT_SECRET'] || raise('JWT_SECRET not configured')
    # ok: ruby-jwt-none-algorithm
    token = JWT.encode(payload, secret, 'HS256')
    { token: token }.to_json
  end
# {/fact}
end

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_13
  class AuthToken
    ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256']
    
    def self.generate(payload, algorithm_index)
      secret = ENV['JWT_SECRET'] || raise('JWT_SECRET not configured')
      # ok: ruby-jwt-none-algorithm
      JWT.encode(payload, secret, ALGORITHMS[algorithm_index])
    end
  end
  
  # Using HS256 algorithm (index 0)
  AuthToken.generate({ user_id: 42 }, 0)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_14
  def create_token_with_algorithm(payload, algorithm = 'HS256')
    raise "Insecure algorithm: #{algorithm}" if algorithm == 'none'
    secret = ENV['JWT_SECRET'] || raise('JWT_SECRET not configured')
    # ok: ruby-jwt-none-algorithm
    JWT.encode(payload, secret, algorithm)
  end
  
  create_token_with_algorithm({ 'data' => 'test' })
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_15
  config = {
    algorithm: 'HS256',
    secret: ENV['JWT_SECRET'] || raise('JWT_SECRET not configured')
  }
  
  def generate_token_from_config(user_data, config)
    # ok: ruby-jwt-none-algorithm
    JWT.encode(user_data, config[:secret], config[:algorithm])
  end
  
  generate_token_from_config({ user_id: 123 }, config)
end
# {/fact}