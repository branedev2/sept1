import * as crypto from 'crypto';
import { createHmac, randomBytes, scryptSync, createCipheriv } from 'crypto';

// True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
  // Using a key that's only 16 bytes (128 bits) for HMAC
  const key = crypto.randomBytes(16);
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  const data = 'Hello, world!';
  const signature = hmac.update(data).digest('hex');
  return signature;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
  // Using a key that's 32 bytes (256 bits) for HMAC - still less than 256 bytes
  const key = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Sensitive data';
  return hmac.update(data).digest('base64');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
  // Using a string key that's converted to bytes but still too small
  const key = 'this-is-a-secret-key-but-not-long-enough';
  // ruleid: typescript-crypto-key-generator
  const hmac = createHmac('sha256', key);
  const message = 'Message to authenticate';
  return hmac.update(message).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
  // Using a key derived from a password but still too small (32 bytes)
  const password = 'user-supplied-password';
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32);
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Critical data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
  // Using a hex string that's decoded to bytes but still too small
  const hexKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const key = Buffer.from(hexKey, 'hex');
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha384', key);
  return hmac.update('Financial transaction data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
  // Using a key from Base64 encoding but still too small
  const base64Key = 'SGVsbG8gV29ybGQgVGhpcyBJcyBBIFRlc3QgS2V5IEJ1dCBOb3QgTG9uZyBFbm91Z2g=';
  const key = Buffer.from(base64Key, 'base64');
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  const data = { userId: 123, action: 'withdraw' };
  return hmac.update(JSON.stringify(data)).digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
  // Using a key generated from a weak source (only 64 bytes)
  function generateWeakKey(): Buffer {
    return crypto.randomBytes(64);
  }
  const key = generateWeakKey();
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('API request payload').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
  // Using a key derived from PBKDF2 but still too small (128 bytes)
  const password = 'user-password';
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 10000, 128, 'sha512');
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Authentication token').digest('base64');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
  // Using a concatenation of multiple values but still too small
  const part1 = crypto.randomBytes(64);
  const part2 = crypto.randomBytes(64);
  const key = Buffer.concat([part1, part2]); // 128 bytes total
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  return hmac.update('Sensitive customer data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
  // Using a key from environment variable but still too small
  const apiKey = process.env.API_KEY || 'default-key-for-testing-not-secure-enough';
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', apiKey);
  return hmac.update('Payment information').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
  // Using a key from a file but still too small
  class KeyManager {
    getKeyFromFile(): Buffer {
      // Simulating reading a key from a file
      return Buffer.from('this-is-a-key-from-file-but-still-not-long-enough-for-proper-security');
    }
  }
  const keyManager = new KeyManager();
  const key = keyManager.getKeyFromFile();
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('User credentials').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
  // Using a key with conditional logic but still too small
  let key: Buffer;
  const useStrongKey = false;
  
  if (useStrongKey) {
    key = crypto.randomBytes(300); // This would be sufficient
  } else {
    key = crypto.randomBytes(200); // Still less than 256 bytes
  }
  
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Transaction data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
  // Using a key from a custom generator but still too small
  class SecurityService {
    generateHmacKey(): Buffer {
      // This service generates keys that are too small
      return crypto.randomBytes(128);
    }
  }
  
  const securityService = new SecurityService();
  const key = securityService.generateHmacKey();
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  return hmac.update('Health records').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
  // Using a key derived from multiple sources but still too small
  const userSalt = 'user-specific-salt';
  const appSecret = 'application-secret-key';
  const combinedInput = userSalt + appSecret;
  const key = crypto.createHash('sha256').update(combinedInput).digest(); // 32 bytes
  // ruleid: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha384', key);
  return hmac.update('Confidential document').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
  // Using a key with async/await pattern but still too small
  async function generateKeyAsync(): Promise<Buffer> {
    return new Promise((resolve) => {
      // Simulating async key generation
      setTimeout(() => {
        resolve(crypto.randomBytes(64));
      }, 100);
    });
  }
  
  // For demonstration purposes, using immediately invoked async function
  (async () => {
    const key = await generateKeyAsync();
    // ruleid: typescript-crypto-key-generator
    const hmac = crypto.createHmac('sha256', key);
    return hmac.update('Secure message').digest('hex');
  })();
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
  // Using a key that's 256 bytes (2048 bits) for HMAC
  const key = crypto.randomBytes(256);
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  const data = 'Hello, world!';
  const signature = hmac.update(data).digest('hex');
  return signature;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
  // Using a key that's 300 bytes (2400 bits) for HMAC - more than 256 bytes
  const key = crypto.randomBytes(300);
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  const data = 'Sensitive data';
  return hmac.update(data).digest('base64');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
  // Using a key derived from a password with sufficient length (300 bytes)
  const password = 'user-supplied-password';
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 300);
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Critical data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
  // Using a key from PBKDF2 with sufficient length (300 bytes)
  const password = 'user-password';
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 10000, 300, 'sha512');
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Authentication token').digest('base64');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
  // Using a concatenation of multiple values to achieve sufficient length
  const part1 = crypto.randomBytes(128);
  const part2 = crypto.randomBytes(128);
  const part3 = crypto.randomBytes(128);
  const key = Buffer.concat([part1, part2, part3]); // 384 bytes total
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  return hmac.update('Sensitive customer data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
  // Using a key from a secure key management service with sufficient length
  class SecureKeyManager {
    getSecureKey(): Buffer {
      // Simulating a secure key from a key management service
      return crypto.randomBytes(300);
    }
  }
  
  const keyManager = new SecureKeyManager();
  const key = keyManager.getSecureKey();
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Payment information').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
  // Using a key with conditional logic ensuring sufficient length
  let key: Buffer;
  const useStrongKey = true;
  
  if (useStrongKey) {
    key = crypto.randomBytes(300); // Sufficient
  } else {
    key = crypto.randomBytes(400); // Also sufficient
  }
  
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', key);
  return hmac.update('Transaction data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
  // Using a key from a custom generator with sufficient length
  class EnhancedSecurityService {
    generateSecureHmacKey(): Buffer {
      // This service generates keys with sufficient length
      return crypto.randomBytes(300);
    }
  }
  
  const securityService = new EnhancedSecurityService();
  const key = securityService.generateSecureHmacKey();
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  return hmac.update('Health records').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
  // Using a key derived from multiple sources with sufficient length
  function deriveStrongKey(input: string): Buffer {
    // Derive a key with multiple iterations to achieve sufficient length
    let key = Buffer.from(input);
    for (let i = 0; i < 10; i++) {
      key = crypto.createHash('sha512').update(key).digest();
    }
    
    // Expand to 300 bytes by repeating the hash
    const expandedKey = Buffer.alloc(300);
    for (let i = 0; i < 300; i += key.length) {
      key.copy(expandedKey, i, 0, Math.min(key.length, 300 - i));
    }
    
    return expandedKey;
  }
  
  const userSalt = 'user-specific-salt';
  const appSecret = 'application-secret-key';
  const combinedInput = userSalt + appSecret;
  const key = deriveStrongKey(combinedInput); // 300 bytes
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha384', key);
  return hmac.update('Confidential document').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
  // Using a key with async/await pattern with sufficient length
  async function generateSecureKeyAsync(): Promise<Buffer> {
    return new Promise((resolve) => {
      // Simulating async secure key generation
      setTimeout(() => {
        resolve(crypto.randomBytes(300));
      }, 100);
    });
  }
  
  // For demonstration purposes, using immediately invoked async function
  (async () => {
    const key = await generateSecureKeyAsync();
    // ok: typescript-crypto-key-generator
    const hmac = crypto.createHmac('sha256', key);
    return hmac.update('Secure message').digest('hex');
  })();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
  // Using a key for HMAC that's exactly 256 bytes (minimum required)
  const exactlyRightSizeKey = Buffer.alloc(256).fill('x');
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', exactlyRightSizeKey);
  return hmac.update('Boundary test case').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
  // Using a key from environment with fallback to secure generation
  function getSecureKey(): Buffer {
    const envKey = process.env.HMAC_KEY;
    if (envKey && Buffer.from(envKey, 'base64').length >= 256) {
      return Buffer.from(envKey, 'base64');
    }
    // Fallback to secure generation
    return crypto.randomBytes(300);
  }
  
  const key = getSecureKey();
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  return hmac.update('API authentication').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
  // Using a key rotation strategy with sufficient key size
  class KeyRotationManager {
    getCurrentKey(): Buffer {
      // In a real implementation, this would retrieve the current key from a secure store
      return crypto.randomBytes(300);
    }
  }
  
  const rotationManager = new KeyRotationManager();
  const currentKey = rotationManager.getCurrentKey();
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha256', currentKey);
  return hmac.update('Rotated key usage').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
  // Using a key with additional entropy sources but ensuring sufficient length
  function generateEnhancedKey(): Buffer {
    const timestamp = Date.now().toString();
    const randomData = crypto.randomBytes(250).toString('hex');
    const combinedData = timestamp + randomData;
    
    // Hash the combined data to create a seed
    const seed = crypto.createHash('sha512').update(combinedData).digest();
    
    // Use the seed to generate a key of sufficient length
    const key = Buffer.alloc(300);
    for (let i = 0; i < key.length; i++) {
      key[i] = seed[i % seed.length];
    }
    
    return key;
  }
  
  const key = generateEnhancedKey();
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha384', key);
  return hmac.update('Enhanced security data').digest('hex');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
  // Using a hardware security module (HSM) simulation with proper key size
  class HsmSimulator {
    generateKey(): Buffer {
      // In real-world, this would interface with an HSM
      // Here we simulate a 300-byte key from an HSM
      return crypto.randomBytes(300);
    }
  }
  
  const hsm = new HsmSimulator();
  const key = hsm.generateKey();
  // ok: typescript-crypto-key-generator
  const hmac = crypto.createHmac('sha512', key);
  return hmac.update('HSM-protected data').digest('hex');
}
// {/fact}