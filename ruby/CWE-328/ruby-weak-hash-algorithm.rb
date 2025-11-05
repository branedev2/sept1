require 'digest'
require 'openssl'
require 'sinatra'
require 'bcrypt'

# True Positives (Vulnerable Code)

# Case 1: Using MD5 for password hashing
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_1
  password = "user_password"
  # ruleid: ruby-weak-hash-algorithm
  hashed_password = Digest::MD5.hexdigest(password)
  puts "Hashed password: #{hashed_password}"
  return hashed_password
end
# {/fact}

# Case 2: Using SHA1 for password hashing
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_2
  password = "secret123"
  # ruleid: ruby-weak-hash-algorithm
  hashed_password = Digest::SHA1.hexdigest(password)
  puts "Hashed password: #{hashed_password}"
  return hashed_password
end
# {/fact}

# Case 3: Using MD5 with salt for password storage
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_3
  password = "user_input_password"
  salt = "random_salt_value"
  # ruleid: ruby-weak-hash-algorithm
  hashed_password = Digest::MD5.hexdigest(password + salt)
  puts "Salted and hashed password: #{hashed_password}"
  return hashed_password
end
# {/fact}

# Case 4: Using SHA1 with OpenSSL for file integrity
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_4
  file_content = File.read("important_file.txt")
  # ruleid: ruby-weak-hash-algorithm
  digest = OpenSSL::Digest::SHA1.new
  hash_value = digest.digest(file_content)
  puts "File hash: #{hash_value.unpack('H*').first}"
  return hash_value
end
# {/fact}

# Case 5: Using MD5 for token generation
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_5
  user_id = "12345"
  timestamp = Time.now.to_i.to_s
  # ruleid: ruby-weak-hash-algorithm
  token = Digest::MD5.hexdigest(user_id + timestamp)
  puts "Generated token: #{token}"
  return token
end
# {/fact}

# Case 6: Using SHA1 in a web application for URL verification
post '/verify' do
  data = request.body.read
  provided_hash = params[:hash]
  secret_key = "application_secret_key"
  # ruleid: ruby-weak-hash-algorithm
  calculated_hash = Digest::SHA1.hexdigest(data + secret_key)
  
  if calculated_hash == provided_hash
    return "Verification successful"
  else
    return "Verification failed"
  end
end

# Case 7: Using MD5 for API request signing
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_7
  payload = '{"user":"admin","action":"delete"}'
  api_key = "secret_api_key"
  # ruleid: ruby-weak-hash-algorithm
  signature = Digest::MD5.hexdigest(payload + api_key)
  puts "API request signature: #{signature}"
  return signature
end
# {/fact}

# Case 8: Using SHA1 for cookie signing
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_8
  user_data = '{"id":123,"role":"admin"}'
  secret = "cookie_signing_secret"
  # ruleid: ruby-weak-hash-algorithm
  signature = Digest::SHA1.hexdigest(user_data + secret)
  cookie = "#{user_data}|#{signature}"
  puts "Signed cookie: #{cookie}"
  return cookie
end
# {/fact}

# Case 9: Using MD5 for email verification token
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_9
  email = "user@example.com"
  timestamp = Time.now.to_i.to_s
  secret = "email_verification_secret"
  # ruleid: ruby-weak-hash-algorithm
  verification_token = Digest::MD5.hexdigest(email + timestamp + secret)
  puts "Email verification token: #{verification_token}"
  return verification_token
end
# {/fact}

# Case 10: Using SHA1 for password reset token
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_10
  user_id = "54321"
  expiry = (Time.now + 3600).to_i.to_s
  # ruleid: ruby-weak-hash-algorithm
  reset_token = Digest::SHA1.hexdigest(user_id + expiry + "reset_secret")
  puts "Password reset token: #{reset_token}"
  return reset_token
end
# {/fact}

# Case 11: Using MD5 for file checksum in a file upload system
post '/upload' do
  file = params[:file][:tempfile]
  filename = params[:file][:filename]
  content = file.read
  # ruleid: ruby-weak-hash-algorithm
  checksum = Digest::MD5.hexdigest(content)
  
  File.write("uploads/#{filename}", content)
  return "File uploaded with checksum: #{checksum}"
end

# Case 12: Using SHA1 for session token generation
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_12
  user_id = "789"
  user_agent = "Mozilla/5.0"
  timestamp = Time.now.to_i.to_s
  # ruleid: ruby-weak-hash-algorithm
  session_token = Digest::SHA1.hexdigest(user_id + user_agent + timestamp)
  puts "Session token: #{session_token}"
  return session_token
end
# {/fact}

# Case 13: Using MD5 for database record fingerprinting
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_13
  record_data = '{"name":"John Doe","email":"john@example.com","role":"user"}'
  # ruleid: ruby-weak-hash-algorithm
  fingerprint = Digest::MD5.hexdigest(record_data)
  puts "Record fingerprint: #{fingerprint}"
  return fingerprint
end
# {/fact}

# Case 14: Using SHA1 for webhook payload verification
post '/webhook' do
  payload = request.body.read
  provided_signature = request.env['HTTP_X_SIGNATURE']
  webhook_secret = "webhook_secret_key"
  # ruleid: ruby-weak-hash-algorithm
  calculated_signature = Digest::SHA1.hexdigest(payload + webhook_secret)
  
  if calculated_signature == provided_signature
    return "Webhook accepted"
  else
    return "Invalid signature"
  end
end

# Case 15: Using MD5 for cache key generation
# {fact rule=clear-text-credentials@v1.0 defects=1}
def bad_case_15
  query = "SELECT * FROM users WHERE active = true"
  # ruleid: ruby-weak-hash-algorithm
  cache_key = Digest::MD5.hexdigest(query)
  puts "Cache key: #{cache_key}"
  return cache_key
end
# {/fact}

# True Negatives (Secure Code)

# Case 1: Using SHA-256 for password hashing
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_1
  password = "user_password"
  # ok: ruby-weak-hash-algorithm
  hashed_password = Digest::SHA256.hexdigest(password)
  puts "Hashed password: #{hashed_password}"
  return hashed_password
end
# {/fact}

# Case 2: Using SHA-512 for password hashing
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_2
  password = "secret123"
  # ok: ruby-weak-hash-algorithm
  hashed_password = Digest::SHA512.hexdigest(password)
  puts "Hashed password: #{hashed_password}"
  return hashed_password
end
# {/fact}

# Case 3: Using bcrypt for password storage
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_3
  password = "user_input_password"
  # ok: ruby-weak-hash-algorithm
  hashed_password = BCrypt::Password.create(password)
  puts "Bcrypt hashed password: #{hashed_password}"
  return hashed_password
end
# {/fact}

# Case 4: Using SHA-256 with OpenSSL for file integrity
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_4
  file_content = File.read("important_file.txt")
  # ok: ruby-weak-hash-algorithm
  digest = OpenSSL::Digest::SHA256.new
  hash_value = digest.digest(file_content)
  puts "File hash: #{hash_value.unpack('H*').first}"
  return hash_value
end
# {/fact}

# Case 5: Using SHA-384 for token generation
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_5
  user_id = "12345"
  timestamp = Time.now.to_i.to_s
  # ok: ruby-weak-hash-algorithm
  token = Digest::SHA384.hexdigest(user_id + timestamp)
  puts "Generated token: #{token}"
  return token
end
# {/fact}

# Case 6: Using SHA-256 in a web application for URL verification
post '/verify_secure' do
  data = request.body.read
  provided_hash = params[:hash]
  secret_key = "application_secret_key"
  # ok: ruby-weak-hash-algorithm
  calculated_hash = Digest::SHA256.hexdigest(data + secret_key)
  
  if calculated_hash == provided_hash
    return "Verification successful"
  else
    return "Verification failed"
  end
end

# Case 7: Using SHA-512 for API request signing
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_7
  payload = '{"user":"admin","action":"delete"}'
  api_key = "secret_api_key"
  # ok: ruby-weak-hash-algorithm
  signature = Digest::SHA512.hexdigest(payload + api_key)
  puts "API request signature: #{signature}"
  return signature
end
# {/fact}

# Case 8: Using HMAC-SHA256 for cookie signing
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_8
  user_data = '{"id":123,"role":"admin"}'
  secret = "cookie_signing_secret"
  # ok: ruby-weak-hash-algorithm
  signature = OpenSSL::HMAC.hexdigest('SHA256', secret, user_data)
  cookie = "#{user_data}|#{signature}"
  puts "Signed cookie: #{cookie}"
  return cookie
end
# {/fact}

# Case 9: Using SHA-256 for email verification token
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_9
  email = "user@example.com"
  timestamp = Time.now.to_i.to_s
  secret = "email_verification_secret"
  # ok: ruby-weak-hash-algorithm
  verification_token = Digest::SHA256.hexdigest(email + timestamp + secret)
  puts "Email verification token: #{verification_token}"
  return verification_token
end
# {/fact}

# Case 10: Using SHA-512 for password reset token
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_10
  user_id = "54321"
  expiry = (Time.now + 3600).to_i.to_s
  # ok: ruby-weak-hash-algorithm
  reset_token = Digest::SHA512.hexdigest(user_id + expiry + "reset_secret")
  puts "Password reset token: #{reset_token}"
  return reset_token
end
# {/fact}

# Case 11: Using SHA-256 for file checksum in a file upload system
post '/upload_secure' do
  file = params[:file][:tempfile]
  filename = params[:file][:filename]
  content = file.read
  # ok: ruby-weak-hash-algorithm
  checksum = Digest::SHA256.hexdigest(content)
  
  File.write("uploads/#{filename}", content)
  return "File uploaded with checksum: #{checksum}"
end

# Case 12: Using HMAC-SHA256 for session token generation
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_12
  user_id = "789"
  user_agent = "Mozilla/5.0"
  timestamp = Time.now.to_i.to_s
  secret = "session_secret_key"
  # ok: ruby-weak-hash-algorithm
  session_token = OpenSSL::HMAC.hexdigest('SHA256', secret, user_id + user_agent + timestamp)
  puts "Session token: #{session_token}"
  return session_token
end
# {/fact}

# Case 13: Using SHA-256 for database record fingerprinting
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_13
  record_data = '{"name":"John Doe","email":"john@example.com","role":"user"}'
  # ok: ruby-weak-hash-algorithm
  fingerprint = Digest::SHA256.hexdigest(record_data)
  puts "Record fingerprint: #{fingerprint}"
  return fingerprint
end
# {/fact}

# Case 14: Using HMAC-SHA256 for webhook payload verification
post '/webhook_secure' do
  payload = request.body.read
  provided_signature = request.env['HTTP_X_SIGNATURE']
  webhook_secret = "webhook_secret_key"
  # ok: ruby-weak-hash-algorithm
  calculated_signature = OpenSSL::HMAC.hexdigest('SHA256', webhook_secret, payload)
  
  if calculated_signature == provided_signature
    return "Webhook accepted"
  else
    return "Invalid signature"
  end
end

# Case 15: Using SHA-256 for cache key generation
# {fact rule=clear-text-credentials@v1.0 defects=0}
def good_case_15
  query = "SELECT * FROM users WHERE active = true"
  # ok: ruby-weak-hash-algorithm
  cache_key = Digest::SHA256.hexdigest(query)
  puts "Cache key: #{cache_key}"
  return cache_key
end
# {/fact}