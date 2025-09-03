require 'openssl'
require 'base64'

# True Positives (Vulnerable Code)

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_1
  # Using a 512-bit RSA key (too small)
  # ruleid: ruby-insufficient-rsa-key-size
  rsa_key = OpenSSL::PKey::RSA.new(512)
  data = "sensitive information"
  encrypted = rsa_key.public_encrypt(data)
  Base64.encode64(encrypted)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_2
  # Using a 1024-bit RSA key (still insufficient)
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(1024)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  key.to_pem(cipher, "password")
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_3
  # Using a 768-bit RSA key with explicit generation
  # ruleid: ruby-insufficient-rsa-key-size
  key_size = 768
  rsa = OpenSSL::PKey::RSA.generate(key_size)
  rsa.export
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_4
  # Using a variable with insufficient key size
  key_length = 1536
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(key_length)
  key.public_key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_5
  # Using a 1024-bit key for certificate signing
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(1024)
  
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 1
  cert.subject = OpenSSL::X509::Name.parse("/CN=example.com")
  cert.issuer = cert.subject
  cert.public_key = key.public_key
  cert.sign(key, OpenSSL::Digest::SHA256.new)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_6
  # Using an insufficient key size in a method with multiple parameters
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.generate(1024, 65537)
  key.to_der
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_7
  # Using an insufficient key size with conditional logic
  size = 1024
  if ENV['ENVIRONMENT'] == 'development'
    size = 512
  end
  
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(size)
  key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_8
  # Using an insufficient key size with a different constructor form
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.generate(1536)
  data = "secret message"
  encrypted = key.public_encrypt(data, OpenSSL::PKey::RSA::PKCS1_PADDING)
  Base64.encode64(encrypted)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_9
  # Using an insufficient key size with mathematical calculation
  base_size = 512
  multiplier = 2
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(base_size * multiplier) # 1024 bits
  key.public_key.export
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_10
  # Using an insufficient key size in a loop
  sizes = [512, 1024, 1536]
  keys = []
  
  sizes.each do |size|
    # ruleid: ruby-insufficient-rsa-key-size
    keys << OpenSSL::PKey::RSA.new(size)
  end
# {/fact}
  
  keys.map(&:to_pem)
end

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_11
  # Using an insufficient key size with a hash configuration
  config = {
    algorithm: 'RSA',
    key_size: 1024,
    exponent: 65537
  }
  
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(config[:key_size])
  key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_12
  # Using an insufficient key size with string conversion
  size_str = "1024"
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(size_str.to_i)
  key.public_key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_13
  # Using an insufficient key size with bit shifting
  base = 256
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(base << 2) # 1024 bits
  key.to_der
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_14
  # Using an insufficient key size with a ternary operator
  is_test = true
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(is_test ? 1024 : 1536)
  key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=1}
def bad_case_15
  # Using an insufficient key size with a constant
  KEY_SIZE = 1024
  # ruleid: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.generate(KEY_SIZE)
  key.to_pem
end
# {/fact}

# True Negatives (Secure Code)

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_1
  # Using a 2048-bit RSA key (sufficient)
  # ok: ruby-insufficient-rsa-key-size
  rsa_key = OpenSSL::PKey::RSA.new(2048)
  data = "sensitive information"
  encrypted = rsa_key.public_encrypt(data)
  Base64.encode64(encrypted)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_2
  # Using a 4096-bit RSA key (more than sufficient)
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(4096)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  key.to_pem(cipher, "password")
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_3
  # Using a 3072-bit RSA key with explicit generation
  # ok: ruby-insufficient-rsa-key-size
  key_size = 3072
  rsa = OpenSSL::PKey::RSA.generate(key_size)
  rsa.export
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_4
  # Using a variable with sufficient key size
  key_length = 2048
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(key_length)
  key.public_key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_5
  # Using a 2048-bit key for certificate signing
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(2048)
  
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 1
  cert.subject = OpenSSL::X509::Name.parse("/CN=example.com")
  cert.issuer = cert.subject
  cert.public_key = key.public_key
  cert.sign(key, OpenSSL::Digest::SHA256.new)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_6
  # Using a sufficient key size in a method with multiple parameters
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.generate(2048, 65537)
  key.to_der
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_7
  # Using a sufficient key size with conditional logic
  size = 2048
  if ENV['ENVIRONMENT'] == 'production'
    size = 4096
  end
  
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(size)
  key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_8
  # Using a sufficient key size with a different constructor form
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.generate(2048)
  data = "secret message"
  encrypted = key.public_encrypt(data, OpenSSL::PKey::RSA::PKCS1_PADDING)
  Base64.encode64(encrypted)
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_9
  # Using a sufficient key size with mathematical calculation
  base_size = 1024
  multiplier = 2
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(base_size * multiplier) # 2048 bits
  key.public_key.export
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_10
  # Using sufficient key sizes in a loop
  sizes = [2048, 3072, 4096]
  keys = []
  
  sizes.each do |size|
    # ok: ruby-insufficient-rsa-key-size
    keys << OpenSSL::PKey::RSA.new(size)
  end
# {/fact}
  
  keys.map(&:to_pem)
end

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_11
  # Using a sufficient key size with a hash configuration
  config = {
    algorithm: 'RSA',
    key_size: 2048,
    exponent: 65537
  }
  
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(config[:key_size])
  key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_12
  # Using a sufficient key size with string conversion
  size_str = "2048"
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(size_str.to_i)
  key.public_key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_13
  # Using a sufficient key size with bit shifting
  base = 512
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(base << 2) # 2048 bits
  key.to_der
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_14
  # Using a sufficient key size with a ternary operator
  is_test = false
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.new(is_test ? 2048 : 4096)
  key.to_pem
end
# {/fact}

# {fact rule=cryptographic-key-generator@v1.0 defects=0}
def good_case_15
  # Using a sufficient key size with a constant
  KEY_SIZE = 2048
  # ok: ruby-insufficient-rsa-key-size
  key = OpenSSL::PKey::RSA.generate(KEY_SIZE)
  key.to_pem
end
# {/fact}