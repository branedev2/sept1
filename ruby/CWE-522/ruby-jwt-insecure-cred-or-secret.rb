require 'jwt'

# True Positive Examples (Vulnerable Code)

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_1
  # Using a hardcoded string as JWT secret
  # ruleid: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode({user_id: 123, exp: Time.now.to_i + 3600}, "my_hardcoded_secret", 'HS256')
  
  # Use the token for authentication
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_2
  payload = {data: 'test'}
  
  # Hardcoded secret in a variable
  secret = "super_secret_key_123"
  # ruleid: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode(payload, secret, 'HS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_3
  # Hardcoded secret in a constant
  SECRET_KEY = "jwt_secret_dont_share"
  
  # ruleid: ruby-jwt-insecure-cred-or-secret
  decoded_token = JWT.decode(request.headers['Authorization'], SECRET_KEY, true, { algorithm: 'HS256' })
  
  user_id = decoded_token[0]['user_id']
  return user_id
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_4
  # Hardcoded secret in a class constant
  class JwtHandler
    SECRET = "static_jwt_secret_key"
    
    def self.create_token(payload)
      # ruleid: ruby-jwt-insecure-cred-or-secret
      JWT.encode(payload, SECRET, 'HS256')
    end
  end
  
  token = JwtHandler.create_token({user: 'admin'})
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_5
  # Hardcoded RSA private key as string
  private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAuV9ht9J7k4NBs38jOXvvTKY9gW8nLICSno5AAUP3pjJo/1D\nSGkSVrAHHRZiTRuiD2dnDZrn1kQK45cN1PFfC3j++8QpAXZqLlDUDFV4IXSxXqr\n...truncated for brevity...\nXDE5MzAtNDI0MC05ZjJlLTRlZGUtOGVi\nOC0xMjc1NDU5NDAxMjEiLCJhbGciOiJSUzI1NiJ9\n-----END RSA PRIVATE KEY-----"
  
  # ruleid: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode({admin: true}, private_key, 'RS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_6
  # Hardcoded secret in a hash
  jwt_config = {
    secret: "hardcoded_jwt_secret_in_hash",
    algorithm: 'HS256'
  }
  
  # ruleid: ruby-jwt-insecure-cred-or-secret
  JWT.encode({user_role: 'admin'}, jwt_config[:secret], jwt_config[:algorithm])
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_7
  # Multiple hardcoded secrets for different environments
  secrets = {
    development: "dev_secret_key",
    test: "test_secret_key",
    production: "prod_secret_key"
  }
  
  env = ENV['RAILS_ENV'] || 'development'
  # ruleid: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode({data: 'sensitive'}, secrets[env.to_sym], 'HS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_8
  # Hardcoded secret with string interpolation
  app_name = "my_app"
  # ruleid: ruby-jwt-insecure-cred-or-secret
  secret = "#{app_name}_secret_key_123"
  
  token = JWT.encode({user: 'john'}, secret, 'HS256')
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_9
  # Hardcoded secret in a method
  def get_secret
    "static_method_secret_key"
  end
  
  payload = {exp: Time.now.to_i + 3600, data: 'important'}
  # ruleid: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode(payload, get_secret, 'HS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_10
  # Hardcoded HMAC key
  hmac_key = "abcdef1234567890"
  payload = {user_id: 42}
  
  # ruleid: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode(payload, hmac_key, 'HS512')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_11
  # Hardcoded secret in JWT verification
  token = request.headers['Authorization'].split(' ').last
  
  begin
    # ruleid: ruby-jwt-insecure-cred-or-secret
    decoded = JWT.decode(token, "verification_secret_123", true, { algorithm: 'HS256' })
    return {success: true, data: decoded[0]}
  rescue JWT::DecodeError
    return {success: false, error: "Invalid token"}
  end
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_12
  # Hardcoded secret with base64 encoding (still hardcoded)
  require 'base64'
  
  encoded_secret = Base64.encode64("my_secret_key")
  # ruleid: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode({admin: true}, encoded_secret, 'HS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_13
  # Hardcoded secret in a more complex scenario with options
  payload = {
    iss: "https://myapp.com",
    exp: Time.now.to_i + 3600,
    user_id: 123
  }
  
  # ruleid: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode(payload, "complex_scenario_secret", 'HS384')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_14
  # Hardcoded secret in a class with multiple methods
  class TokenService
    def initialize
      @secret = "service_class_secret"
    end
    
    def encode(payload)
      # ruleid: ruby-jwt-insecure-cred-or-secret
      JWT.encode(payload, @secret, 'HS256')
    end
    
    def decode(token)
      JWT.decode(token, @secret, true, { algorithm: 'HS256' })
    end
  end
  
  service = TokenService.new
  token = service.encode({user: 'admin'})
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_15
  # Hardcoded secret with conditional logic
  use_strong_algo = true
  
  if use_strong_algo
    algo = 'HS512'
    # ruleid: ruby-jwt-insecure-cred-or-secret
    secret = "strong_algo_secret_key"
  else
    algo = 'HS256'
    # ruleid: ruby-jwt-insecure-cred-or-secret
    secret = "standard_algo_secret_key"
  end
  
  token = JWT.encode({data: 'protected'}, secret, algo)
  return token
end
# {/fact}

# True Negative Examples (Secure Code)

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_1
  # Using environment variable for JWT secret
  # ok: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode({user_id: 123, exp: Time.now.to_i + 3600}, ENV['JWT_SECRET'], 'HS256')
  
  # Use the token for authentication
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_2
  payload = {data: 'test'}
  
  # Secret from environment variable
  # ok: ruby-jwt-insecure-cred-or-secret
  secret = ENV.fetch('JWT_SECRET_KEY')
  token = JWT.encode(payload, secret, 'HS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_3
  # Secret from a secure credential store
  require 'aws-sdk-secretsmanager'
  
  client = Aws::SecretsManager::Client.new(region: 'us-west-2')
  secret = client.get_secret_value(secret_id: 'jwt/secret').secret_string
  
  # ok: ruby-jwt-insecure-cred-or-secret
  decoded_token = JWT.decode(request.headers['Authorization'], secret, true, { algorithm: 'HS256' })
  
  user_id = decoded_token[0]['user_id']
  return user_id
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_4
  # Secret from a configuration service
  class JwtHandler
    def self.secret
      Rails.application.credentials.jwt_secret
    end
    
    def self.create_token(payload)
      # ok: ruby-jwt-insecure-cred-or-secret
      JWT.encode(payload, secret, 'HS256')
    end
  end
  
  token = JwtHandler.create_token({user: 'admin'})
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_5
  # RSA private key from file
  require 'openssl'
  
  private_key = OpenSSL.pkey.read(File.read('private_key.pem'))
  
  # ok: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode({admin: true}, private_key, 'RS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_6
  # Secret from configuration service
  require 'vault'
  
  Vault.address = ENV['VAULT_ADDR']
  Vault.token = ENV['VAULT_TOKEN']
  
  jwt_config = {
    secret: Vault.logical.read('secret/jwt').data[:secret],
    algorithm: 'HS256'
  }
  
  # ok: ruby-jwt-insecure-cred-or-secret
  JWT.encode({user_role: 'admin'}, jwt_config[:secret], jwt_config[:algorithm])
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_7
  # Secret from database
  require 'active_record'
  
  class AppSecret < ActiveRecord::Base
  end
  
  jwt_secret = AppSecret.find_by(name: 'jwt_secret').value
  
  # ok: ruby-jwt-insecure-cred-or-secret
  token = JWT.encode({data: 'sensitive'}, jwt_secret, 'HS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_8
  # Secret from a method that fetches from secure source
  def get_secret_from_keystore
    # Implementation that fetches from a secure key store
    KeyStore.get('jwt_signing_key')
  end
  
  # ok: ruby-jwt-insecure-cred-or-secret
  secret = get_secret_from_keystore
  
  token = JWT.encode({user: 'john'}, secret, 'HS256')
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_9
  # Secret generated at runtime (not hardcoded)
  require 'securerandom'
  
  # This is just an example - in practice, you'd want to store and reuse this secret
  # ok: ruby-jwt-insecure-cred-or-secret
  runtime_secret = SecureRandom.hex(32)
  
  payload = {exp: Time.now.to_i + 3600, data: 'important'}
  token = JWT.encode(payload, runtime_secret, 'HS256')
  
  # Store the secret securely for verification
  Rails.cache.write('jwt_secret', runtime_secret)
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_10
  # Secret from encrypted credentials in Rails
  # ok: ruby-jwt-insecure-cred-or-secret
  hmac_key = Rails.application.credentials.jwt[:hmac_key]
  
  payload = {user_id: 42}
  token = JWT.encode(payload, hmac_key, 'HS512')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_11
  # Secret from environment with fallback mechanism
  token = request.headers['Authorization'].split(' ').last
  
  begin
    # ok: ruby-jwt-insecure-cred-or-secret
    secret = ENV['JWT_SECRET'] || Rails.application.credentials.jwt_secret
    
    decoded = JWT.decode(token, secret, true, { algorithm: 'HS256' })
    return {success: true, data: decoded[0]}
  rescue JWT::DecodeError
    return {success: false, error: "Invalid token"}
  end
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_12
  # Secret from a secure key rotation service
  require 'key_rotation_service'
  
  key_service = KeyRotationService.new
  # ok: ruby-jwt-insecure-cred-or-secret
  current_key = key_service.get_current_key('jwt_signing')
  
  token = JWT.encode({admin: true}, current_key, 'HS256')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_13
  # Secret from a configuration file that's not in version control
  require 'yaml'
  
  config = YAML.load_file(File.join(Rails.root, 'config', 'secrets.yml'))
  # ok: ruby-jwt-insecure-cred-or-secret
  jwt_secret = config[Rails.env]['jwt_secret']
  
  payload = {
    iss: "https://myapp.com",
    exp: Time.now.to_i + 3600,
    user_id: 123
  }
  
  token = JWT.encode(payload, jwt_secret, 'HS384')
  
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_14
  # Secret from a secure service with caching
  class SecureTokenService
    def initialize
      @secret = nil
    end
    
    def get_secret
      return @secret if @secret
      
      # Fetch from secure source
      @secret = SecretManager.get_secret('jwt_signing_key')
    end
    
    def encode(payload)
      # ok: ruby-jwt-insecure-cred-or-secret
      JWT.encode(payload, get_secret, 'HS256')
    end
    
    def decode(token)
      JWT.decode(token, get_secret, true, { algorithm: 'HS256' })
    end
  end
  
  service = SecureTokenService.new
  token = service.encode({user: 'admin'})
  return token
end
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_15
  # Secret from multiple environment sources with validation
  # ok: ruby-jwt-insecure-cred-or-secret
  secret = ENV['JWT_PRIMARY_SECRET'] || ENV['JWT_BACKUP_SECRET']
  
  if secret.nil? || secret.empty?
    raise "JWT secret not configured!"
  end
  
  token = JWT.encode({data: 'protected'}, secret, 'HS512')
  return token
end
# {/fact}