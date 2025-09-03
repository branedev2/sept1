// File: hmac_key_generation_tests.js
const crypto = require('crypto');

// True Positive Examples (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
  // Using a key that's only 16 bytes (128 bits) for HMAC
  // ruleid: javascript-crypto-key-generator
  const key = crypto.randomBytes(16);
  const hmac = crypto.createHmac('sha256', key);
  const data = 'Hello, world!';
  const signature = hmac.update(data).digest('hex');
  return signature;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
  // Using a key that's 32 bytes (256 bits) - still less than 256 bytes
  // ruleid: javascript-crypto-key-generator
  const key = crypto.randomBytes(32);
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Sensitive data';
  return hmac.update(data).digest('base64');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
  // Using a key that's 64 bytes (512 bits) - still less than 256 bytes
  // ruleid: javascript-crypto-key-generator
  const key = Buffer.from(crypto.randomBytes(64));
  const hmac = crypto.createHmac('sha256', key);
  const message = JSON.stringify({user: 'admin', action: 'delete'});
  return hmac.update(message).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
  // Using a hardcoded key that's 24 bytes (192 bits) - less than 256 bytes
  // ruleid: javascript-crypto-key-generator
  const key = Buffer.from('secretkey123456789abcdefgh', 'utf8'); // 24 bytes
  const hmac = crypto.createHmac('sha1', key);
  const payload = 'Important transaction data';
  return hmac.update(payload).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
  // Using a key derived from password with insufficient length (20 bytes/160 bits)
  // ruleid: javascript-crypto-key-generator
  const password = 'user_password';
  const salt = 'random_salt';
  const key = crypto.pbkdf2Sync(password, salt, 10000, 20, 'sha256');
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Verify this message').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
  // Using a key from environment variable but with insufficient length (16 bytes/128 bits)
  // ruleid: javascript-crypto-key-generator
  const keyHex = process.env.API_KEY || '0123456789abcdef0123456789abcdef';
  const key = Buffer.from(keyHex, 'hex'); // 16 bytes
  const hmac = crypto.createHmac('sha256', key);
  const data = 'API request payload';
  return hmac.update(data).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
  // Using a key generated with insufficient entropy (8 bytes/64 bits)
  // ruleid: javascript-crypto-key-generator
  const timestamp = Date.now().toString();
  const key = crypto.createHash('md5').update(timestamp).digest().slice(0, 8);
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Time-sensitive data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
  // Using a key that's 128 bytes (1024 bits) - still less than 256 bytes
  // ruleid: javascript-crypto-key-generator
  const key = crypto.randomBytes(128);
  const hmac = crypto.createHmac('sha512', key);
  const data = Buffer.from('Binary data for verification');
  return hmac.update(data).digest();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
  // Using a key from a file but with insufficient length (48 bytes/384 bits)
  // ruleid: javascript-crypto-key-generator
  const fs = require('fs');
  let key;
  try {
    key = fs.readFileSync('./secret_key.bin');
    if (key.length < 48) {
      key = crypto.randomBytes(48);
      fs.writeFileSync('./secret_key.bin', key);
    }
  } catch (err) {
    key = crypto.randomBytes(48);
    fs.writeFileSync('./secret_key.bin', key);
  }
  const hmac = crypto.createHmac('sha384', key);
  return hmac.update('File integrity check').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
  // Using a key with exactly 255 bytes (just under the 256 byte requirement)
  // ruleid: javascript-crypto-key-generator
  const key = crypto.randomBytes(255);
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Almost secure, but not quite';
  return hmac.update(data).digest('base64');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
  // Using a key derived from multiple sources but still insufficient (64 bytes/512 bits)
  // ruleid: javascript-crypto-key-generator
  const part1 = crypto.randomBytes(32);
  const part2 = crypto.randomBytes(32);
  const key = Buffer.concat([part1, part2]); // 64 bytes total
  const hmac = crypto.createHmac('sha256', key);
  const message = 'Multi-part key test';
  return hmac.update(message).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
  // Using a key from Base64 string with insufficient length (24 bytes/192 bits)
  // ruleid: javascript-crypto-key-generator
  const keyBase64 = 'SGVsbG8gV29ybGQgU2VjcmV0IEtleQ=='; // 24 bytes when decoded
  const key = Buffer.from(keyBase64, 'base64');
  const hmac = crypto.createHmac('sha1', key);
  const data = {id: 123, action: 'purchase'};
  return hmac.update(JSON.stringify(data)).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
  // Using a key derived from user input with insufficient length (32 bytes/256 bits)
  // ruleid: javascript-crypto-key-generator
  function generateKeyFromUserInput(username, deviceId) {
    const combined = `${username}:${deviceId}:${Date.now()}`;
    return crypto.createHash('sha256').update(combined).digest(); // 32 bytes
  }
  
  const key = generateKeyFromUserInput('alice', 'device123');
  const hmac = crypto.createHmac('sha512', key);
  const data = 'User authentication request';
  return hmac.update(data).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
  // Using a key with conditional logic but always insufficient (max 128 bytes/1024 bits)
  // ruleid: javascript-crypto-key-generator
  let key;
  const securityLevel = process.env.SECURITY_LEVEL || 'medium';
  
  if (securityLevel === 'high') {
    key = crypto.randomBytes(128); // 128 bytes (1024 bits)
  } else if (securityLevel === 'medium') {
    key = crypto.randomBytes(64);  // 64 bytes (512 bits)
  } else {
    key = crypto.randomBytes(32);  // 32 bytes (256 bits)
  }
  
  const hmac = crypto.createHmac('sha256', key);
  const message = 'Security-level dependent message';
  return hmac.update(message).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
  // Using a key from hexadecimal string with insufficient length (16 bytes/128 bits)
  // ruleid: javascript-crypto-key-generator
  const keyHex = '0123456789abcdef0123456789abcdef'; // 16 bytes when decoded
  const key = Buffer.from(keyHex, 'hex');
  const hmac = crypto.createHmac('sha256', key);
  const data = 'Hex-encoded key test';
  return hmac.update(data).digest('base64');
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
  // Using a key that's 256 bytes (2048 bits) - meets minimum requirement
  // ok: javascript-crypto-key-generator
  const key = crypto.randomBytes(256);
  const hmac = crypto.createHmac('sha256', key);
  const data = 'Hello, world!';
  const signature = hmac.update(data).digest('hex');
  return signature;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
  // Using a key that's 512 bytes (4096 bits) - exceeds minimum requirement
  // ok: javascript-crypto-key-generator
  const key = crypto.randomBytes(512);
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Sensitive data';
  return hmac.update(data).digest('base64');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
  // Using a key derived from password with sufficient length (256 bytes/2048 bits)
  // ok: javascript-crypto-key-generator
  const password = 'user_password';
  const salt = 'random_salt';
  const key = crypto.pbkdf2Sync(password, salt, 10000, 256, 'sha512');
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Verify this message').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
  // Using a key from environment variable with sufficient length (256 bytes/2048 bits)
  // ok: javascript-crypto-key-generator
  // In a real scenario, this would be a long environment variable
  const keyBase64 = process.env.HMAC_KEY || crypto.randomBytes(256).toString('base64');
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length < 256) {
    // Ensure key meets minimum length requirement
    const newKey = crypto.randomBytes(256);
    const hmac = crypto.createHmac('sha256', newKey);
    return hmac.update('API request payload').digest('hex');
  }
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('API request payload').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
  // Using a key from a file with sufficient length (384 bytes/3072 bits)
  // ok: javascript-crypto-key-generator
  const fs = require('fs');
  let key;
  try {
    key = fs.readFileSync('./secure_key.bin');
    if (key.length < 256) {
      key = crypto.randomBytes(384);
      fs.writeFileSync('./secure_key.bin', key);
    }
  } catch (err) {
    key = crypto.randomBytes(384);
    fs.writeFileSync('./secure_key.bin', key);
  }
  const hmac = crypto.createHmac('sha384', key);
  return hmac.update('File integrity check').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
  // Using a key with exactly 256 bytes (meets the minimum requirement)
  // ok: javascript-crypto-key-generator
  const key = crypto.randomBytes(256);
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Exactly secure';
  return hmac.update(data).digest('base64');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
  // Using a key derived from multiple sources with sufficient length (512 bytes/4096 bits)
  // ok: javascript-crypto-key-generator
  const part1 = crypto.randomBytes(256);
  const part2 = crypto.randomBytes(256);
  const key = Buffer.concat([part1, part2]); // 512 bytes total
  const hmac = crypto.createHmac('sha256', key);
  const message = 'Multi-part key test';
  return hmac.update(message).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
  // Using a secure key management system (simulated)
  // ok: javascript-crypto-key-generator
  function getSecureKeyFromKeyManagementSystem() {
    // In a real scenario, this would call a secure key management service
    // Here we simulate it with a sufficiently large random key
    return crypto.randomBytes(320); // 320 bytes (2560 bits)
  }
  
  const key = getSecureKeyFromKeyManagementSystem();
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Protected by key management system';
  return hmac.update(data).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
  // Using a key with conditional logic ensuring sufficient length (min 256 bytes/2048 bits)
  // ok: javascript-crypto-key-generator
  let key;
  const securityLevel = process.env.SECURITY_LEVEL || 'medium';
  
  if (securityLevel === 'high') {
    key = crypto.randomBytes(512); // 512 bytes (4096 bits)
  } else if (securityLevel === 'medium') {
    key = crypto.randomBytes(384);  // 384 bytes (3072 bits)
  } else {
    key = crypto.randomBytes(256);  // 256 bytes (2048 bits)
  }
  
  const hmac = crypto.createHmac('sha256', key);
  const message = 'Security-level dependent message';
  return hmac.update(message).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
  // Using a key derived from user input with sufficient length (256 bytes/2048 bits)
  // ok: javascript-crypto-key-generator
  function generateSecureKeyFromUserInput(username, deviceId) {
    // Generate a seed from user input
    const seed = `${username}:${deviceId}:${Date.now()}`;
    // Use the seed to generate a secure key of sufficient length
    const hash = crypto.createHash('sha256').update(seed).digest();
    // Expand the hash to a key of sufficient length
    return crypto.pbkdf2Sync(hash, 'static_salt', 100000, 256, 'sha512');
  }
  
  const key = generateSecureKeyFromUserInput('alice', 'device123');
  const hmac = crypto.createHmac('sha512', key);
  const data = 'User authentication request';
  return hmac.update(data).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
  // Using a hardware security module (HSM) for key generation (simulated)
  // ok: javascript-crypto-key-generator
  function getKeyFromHSM() {
    // In a real scenario, this would interact with an HSM
    // Here we simulate it with a sufficiently large random key
    return crypto.randomBytes(384); // 384 bytes (3072 bits)
  }
  
  const key = getKeyFromHSM();
  const hmac = crypto.createHmac('sha256', key);
  const message = 'HSM-protected message';
  return hmac.update(message).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
  // Using a key rotation system with sufficient key length
  // ok: javascript-crypto-key-generator
  function getCurrentKey() {
    // In a real scenario, this would fetch the current key from a rotation system
    const keyId = Math.floor(Date.now() / (24 * 60 * 60 * 1000)); // Daily rotation
    const keySource = `rotation_key_${keyId}`;
    // Generate a deterministic but secure key of sufficient length
    return crypto.pbkdf2Sync(keySource, 'rotation_salt', 50000, 256, 'sha512');
  }
  
  const key = getCurrentKey();
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Message protected with rotating keys';
  return hmac.update(data).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
  // Using a key derived from multiple hash iterations with sufficient length
  // ok: javascript-crypto-key-generator
  function deriveSecureKey(seed) {
    let key = crypto.createHash('sha512').update(seed).digest();
    // Perform multiple iterations to strengthen the key
    for (let i = 0; i < 10000; i++) {
      key = crypto.createHash('sha512').update(key).digest();
    }
    // Expand to sufficient length
    const expandedKey = Buffer.alloc(256);
    for (let i = 0; i < 4; i++) {
      const part = crypto.createHash('sha512')
        .update(Buffer.concat([key, Buffer.from([i])]))
        .digest();
      part.copy(expandedKey, i * 64);
    }
    return expandedKey;
  }
  
  const key = deriveSecureKey('initial_seed_value');
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Multi-iteration derived key').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
  // Using a key split across multiple parts for added security, with sufficient total length
  // ok: javascript-crypto-key-generator
  function combineKeyParts() {
    // In a real scenario, these might come from different secure sources
    const part1 = crypto.randomBytes(128);
    const part2 = crypto.randomBytes(128);
    const part3 = crypto.randomBytes(128);
    return Buffer.concat([part1, part2, part3]); // 384 bytes total
  }
  
  const key = combineKeyParts();
  const hmac = crypto.createHmac('sha384', key);
  const data = 'Protected with multi-part key';
  return hmac.update(data).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
  // Using a key with additional entropy sources and sufficient length
  // ok: javascript-crypto-key-generator
  function generateEnhancedKey() {
    const systemEntropy = crypto.randomBytes(128);
    const timeEntropy = Buffer.from(Date.now().toString());
    const processEntropy = Buffer.from(process.hrtime().toString());
    
    // Combine entropy sources
    const combinedEntropy = Buffer.concat([
      systemEntropy,
      timeEntropy,
      processEntropy
    ]);
    
    // Generate final key with sufficient length
    const finalKey = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) {
      finalKey[i] = combinedEntropy[i % combinedEntropy.length];
    }
    
    // Additional mixing for better distribution
    return crypto.pbkdf2Sync(finalKey, 'enhanced_entropy', 10000, 256, 'sha512');
  }
  
  const key = generateEnhancedKey();
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Enhanced entropy protection';
  return hmac.update(data).digest('hex');
}
// {/fact}