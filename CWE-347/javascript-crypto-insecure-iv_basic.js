// Filename: crypto_iv_test_cases.js
const crypto = require('crypto');
const fs = require('fs');

// True Positive Cases (Vulnerable Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_1() {
  // Using a static, hardcoded IV
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from('1234567890123456');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_2() {
  // Using a zero-filled IV
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('confidential information', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_3() {
  // Reusing the same IV for multiple encryptions
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from('abcdefghijklmnop');
  
  // First encryption
  const cipher1 = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted1 = cipher1.update('first message', 'utf8', 'hex') + cipher1.final('hex');
  
  // Second encryption with same IV
  const cipher2 = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted2 = cipher2.update('second message', 'utf8', 'hex') + cipher2.final('hex');
  
  return { encrypted1, encrypted2 };
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_4() {
  // Using predictable IV from timestamp
  const key = crypto.randomBytes(32);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from(timestamp.padEnd(16, '0'));
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('secret message', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_5() {
  // Using a constant from configuration
  const key = crypto.randomBytes(32);
  const config = { iv: '0123456789abcdef' };
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from(config.iv);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('private data', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_6() {
  // Using an IV derived from the key
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from(key.slice(0, 16));
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('sensitive content', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_7() {
  // Using an IV from a predictable counter
  let counter = 1;
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from(counter.toString().padStart(16, '0'));
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('classified information', 'utf8', 'hex') + cipher.final('hex');
  counter++;
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_8() {
  // Using an IV from a weak random source
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from(Array(16).fill().map(() => Math.floor(Math.random() * 256)));
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('protected data', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_9() {
  // Using an IV from user input (predictable)
  const key = crypto.randomBytes(32);
  const userInput = "user-provided-iv123";
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from(userInput.substring(0, 16).padEnd(16, '0'));
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('restricted content', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_10() {
  // Using a fixed IV in a loop for multiple encryptions
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from('fedcba9876543210');
  
  const messages = ['message1', 'message2', 'message3'];
  const encryptedMessages = [];
  
  for (const message of messages) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update(message, 'utf8', 'hex') + cipher.final('hex');
    encryptedMessages.push(encrypted);
  }
  
  return encryptedMessages;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_11() {
  // Using an IV from a file that doesn't change
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from(fs.readFileSync('static_iv.txt').toString().substring(0, 16));
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('confidential document', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_12() {
  // Using an IV derived from a constant string
  const key = crypto.randomBytes(32);
  const constantString = "ThisIsAConstantString";
  // ruleid: javascript-crypto-insecure-iv
  const iv = crypto.createHash('md5').update(constantString).digest().slice(0, 16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('secure information', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_13() {
  // Using an IV from environment variable (which doesn't change frequently)
  const key = crypto.randomBytes(32);
  // ruleid: javascript-crypto-insecure-iv
  const iv = Buffer.from(process.env.STATIC_IV || '0000000000000000');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('private message', 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_14() {
  // Using a sequential IV that's incremented
  let ivCounter = Buffer.alloc(16, 0);
  const key = crypto.randomBytes(32);
  
  function encryptMessage(message) {
    // ruleid: javascript-crypto-insecure-iv
    const cipher = crypto.createCipheriv('aes-256-cbc', key, ivCounter);
    const encrypted = cipher.update(message, 'utf8', 'hex') + cipher.final('hex');
    
    // Increment the last byte for next use (predictable)
    ivCounter[15] += 1;
    
    return encrypted;
  }
  
  return encryptMessage('sensitive data');
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_15() {
  // Using an IV derived from the plaintext itself
  const key = crypto.randomBytes(32);
  const plaintext = 'secret information to encrypt';
  // ruleid: javascript-crypto-insecure-iv
  const iv = crypto.createHash('sha1').update(plaintext).digest().slice(0, 16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}
// {/fact}

// True Negative Cases (Secure Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_1() {
  // Using a cryptographically secure random IV
  const key = crypto.randomBytes(32);
  // ok: javascript-crypto-insecure-iv
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
  return { encrypted, iv: iv.toString('hex') };
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_2() {
  // Using crypto.randomFillSync for IV generation
  const key = crypto.randomBytes(32);
  const iv = Buffer.alloc(16);
  // ok: javascript-crypto-insecure-iv
  crypto.randomFillSync(iv);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('confidential information', 'utf8', 'hex') + cipher.final('hex');
  return { encrypted, iv: iv.toString('hex') };
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_3() {
  // Using a unique IV for each encryption in a loop
  const key = crypto.randomBytes(32);
  const messages = ['message1', 'message2', 'message3'];
  const results = [];
  
  for (const message of messages) {
    // ok: javascript-crypto-insecure-iv
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update(message, 'utf8', 'hex') + cipher.final('hex');
    results.push({ encrypted, iv: iv.toString('hex') });
  }
  
  return results;
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_4() {
  // Using crypto.randomBytes with Promise API
  const key = crypto.randomBytes(32);
  
  return new Promise((resolve, reject) => {
    // ok: javascript-crypto-insecure-iv
    crypto.randomBytes(16, (err, iv) => {
      if (err) {
        reject(err);
        return;
      }
      
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      const encrypted = cipher.update('secret message', 'utf8', 'hex') + cipher.final('hex');
      resolve({ encrypted, iv: iv.toString('hex') });
    });
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_5() {
  // Using a function that always returns a fresh random IV
  function getSecureIV() {
    // ok: javascript-crypto-insecure-iv
    return crypto.randomBytes(16);
  }
  
  const key = crypto.randomBytes(32);
  const iv = getSecureIV();
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('private data', 'utf8', 'hex') + cipher.final('hex');
  return { encrypted, iv: iv.toString('hex') };
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_6() {
  // Using crypto.randomBytes with async/await
  async function encryptData(data) {
    return new Promise((resolve, reject) => {
      const key = crypto.randomBytes(32);
      
      // ok: javascript-crypto-insecure-iv
      crypto.randomBytes(16, (err, iv) => {
        if (err) {
          reject(err);
          return;
        }
        
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        const encrypted = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
        resolve({ encrypted, iv: iv.toString('hex'), key: key.toString('hex') });
      });
    });
  }
  
  return encryptData('sensitive content');
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_7() {
  // Using a secure IV for GCM mode (which requires 12 bytes)
  const key = crypto.randomBytes(32);
  // ok: javascript-crypto-insecure-iv
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = cipher.update('classified information', 'utf8', 'hex');
  const final = cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return { encrypted: encrypted + final, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_8() {
  // Using a secure IV with a factory pattern
  class Encryptor {
    constructor() {
      this.key = crypto.randomBytes(32);
    }
    
    encrypt(data) {
      // ok: javascript-crypto-insecure-iv
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv);
      const encrypted = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
      return { encrypted, iv: iv.toString('hex') };
    }
  }
  
  const encryptor = new Encryptor();
  return encryptor.encrypt('protected data');
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_9() {
  // Using a secure IV with error handling
  const key = crypto.randomBytes(32);
  let iv;
  
  try {
    // ok: javascript-crypto-insecure-iv
    iv = crypto.randomBytes(16);
  } catch (error) {
    // Fallback to a different secure random source if crypto.randomBytes fails
    const fallbackArray = new Uint8Array(16);
    crypto.getRandomValues(fallbackArray);
    iv = Buffer.from(fallbackArray);
  }
  
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update('restricted content', 'utf8', 'hex') + cipher.final('hex');
  return { encrypted, iv: iv.toString('hex') };
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_10() {
  // Using a secure IV with a wrapper function
  function secureEncrypt(data, key) {
    // ok: javascript-crypto-insecure-iv
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
    return { encrypted, iv: iv.toString('hex') };
  }
  
  const key = crypto.randomBytes(32);
  return secureEncrypt('confidential document', key);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_11() {
  // Using a secure IV with a callback pattern
  function encryptWithCallback(data, callback) {
    const key = crypto.randomBytes(32);
    
    // ok: javascript-crypto-insecure-iv
    crypto.randomBytes(16, (err, iv) => {
      if (err) {
        callback(err);
        return;
      }
      
      try {
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        const encrypted = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
        callback(null, { encrypted, iv: iv.toString('hex') });
      } catch (error) {
        callback(error);
      }
    });
  }
  
  return new Promise((resolve, reject) => {
    encryptWithCallback('secure information', (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_12() {
  // Using a secure IV with ChaCha20-Poly1305
  const key = crypto.randomBytes(32);
  // ok: javascript-crypto-insecure-iv
  const iv = crypto.randomBytes(12); // ChaCha20-Poly1305 uses 12-byte nonce
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  const encrypted = cipher.update('private message', 'utf8', 'hex');
  const final = cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return { encrypted: encrypted + final, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_13() {
  // Using a secure IV with a custom encryption wrapper
  class SecureEncryption {
    static encrypt(plaintext) {
      const key = crypto.randomBytes(32);
      // ok: javascript-crypto-insecure-iv
      const iv = crypto.randomBytes(16);
      
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      const encrypted = Buffer.concat([
        cipher.update(Buffer.from(plaintext, 'utf8')),
        cipher.final()
      ]);
      
      return {
        key: key.toString('hex'),
        iv: iv.toString('hex'),
        encrypted: encrypted.toString('hex')
      };
    }
  }
  
  return SecureEncryption.encrypt('sensitive data');
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_14() {
  // Using a secure IV with stream processing
  function encryptStream(inputStream, outputStream) {
    const key = crypto.randomBytes(32);
    // ok: javascript-crypto-insecure-iv
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    // Write the IV at the beginning of the output
    outputStream.write(iv);
    
    // Pipe the input through the cipher to the output
    inputStream.pipe(cipher).pipe(outputStream);
    
    return { key: key.toString('hex'), iv: iv.toString('hex') };
  }
  
  const inputStream = fs.createReadStream('input.txt');
  const outputStream = fs.createWriteStream('encrypted.bin');
  return encryptStream(inputStream, outputStream);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_15() {
  // Using a secure IV with multiple cipher operations
  const key = crypto.randomBytes(32);
  
  function encryptChunk(chunk) {
    // ok: javascript-crypto-insecure-iv
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update(chunk, 'utf8', 'hex') + cipher.final('hex');
    return { encrypted, iv: iv.toString('hex') };
  }
  
  const chunks = ['chunk1', 'chunk2', 'chunk3'];
  return chunks.map(chunk => encryptChunk(chunk));
}
// {/fact}