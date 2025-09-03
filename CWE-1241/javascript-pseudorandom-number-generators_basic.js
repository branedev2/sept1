// File: pseudorandom_number_generator_tests.js

const crypto = require('crypto');
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_1() {
  // Using Math.random() for generating encryption key
  const key = Math.random().toString(36).substring(2, 15);
  // ruleid: javascript-pseudorandom-number-generators
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_2() {
  // Using Math.random() for generating IV
  const key = crypto.randomBytes(32);
  // ruleid: javascript-pseudorandom-number-generators
  const iv = Buffer.from(Math.random().toString());
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_3() {
  // Using hardcoded value for encryption
  // ruleid: javascript-pseudorandom-number-generators
  const key = "1234567890abcdef1234567890abcdef";
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_4() {
  // Using Date.now() as a seed for random number generation in encryption
  const seed = Date.now();
  const pseudoRandom = (seed * 9301 + 49297) % 233280;
  // ruleid: javascript-pseudorandom-number-generators
  const key = pseudoRandom.toString(36).substring(2, 15);
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_5() {
  // Using a simple PRNG for salt generation in password hashing
  const password = "user_password";
  // ruleid: javascript-pseudorandom-number-generators
  const salt = Math.floor(Math.random() * 1000000).toString();
  const hashedPassword = bcrypt.hashSync(password, salt);
  return hashedPassword;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_6() {
  // Using Math.random() for JWT secret
  // ruleid: javascript-pseudorandom-number-generators
  const secret = Math.random().toString(36).substring(7);
  const token = jwt.sign({ user: 'user123' }, secret, { expiresIn: '1h' });
  return token;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_7() {
  // Using a custom weak PRNG for encryption key
  function weakRandom() {
    return (new Date().getTime() % 1000) / 1000;
  }
  
  // ruleid: javascript-pseudorandom-number-generators
  const key = Buffer.from(Array(32).fill().map(() => Math.floor(weakRandom() * 256)));
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_8() {
  // Using hardcoded IV with proper key
  const key = crypto.randomBytes(32);
  // ruleid: javascript-pseudorandom-number-generators
  const iv = Buffer.from("0123456789abcdef");
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_9() {
  // Using Math.random() for generating a nonce in encryption
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  // ruleid: javascript-pseudorandom-number-generators
  const nonce = Math.random().toString(36).substring(2, 10);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(nonce + 'sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_10() {
  // Using a predictable pattern for key generation
  let key = '';
  for (let i = 0; i < 32; i++) {
    // ruleid: javascript-pseudorandom-number-generators
    key += String.fromCharCode(65 + (i % 26));
  }
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_11() {
  // Using Math.random() for session token generation
  app.get('/login', (req, res) => {
    const username = req.query.username;
    const password = req.query.password;
    
    if (username === 'admin' && password === 'password') {
      // ruleid: javascript-pseudorandom-number-generators
      const sessionToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      res.cookie('session', sessionToken, { httpOnly: true });
      res.send('Logged in successfully');
    }
  });
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_12() {
  // Using a fixed seed for crypto operations
  const seed = 12345;
  function seededRandom() {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  }
  
  // ruleid: javascript-pseudorandom-number-generators
  const key = Buffer.from(Array(32).fill().map(() => Math.floor(seededRandom() * 256)));
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_13() {
  // Using Math.random() for generating password reset tokens
  app.post('/reset-password', (req, res) => {
    const email = req.body.email;
    
    // ruleid: javascript-pseudorandom-number-generators
    const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    
    // Store token in database and send email
    res.send('Password reset email sent');
  });
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_14() {
  // Using timestamp as encryption key
  // ruleid: javascript-pseudorandom-number-generators
  const key = new Date().toISOString();
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=1}
function bad_case_15() {
  // Using process.pid as part of encryption key
  // ruleid: javascript-pseudorandom-number-generators
  const key = `secret-${process.pid}-key`;
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_1() {
  // Using crypto.randomBytes for generating encryption key
  // ok: javascript-pseudorandom-number-generators
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_2() {
  // Using crypto.randomBytes for both key and IV
  // ok: javascript-pseudorandom-number-generators
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_3() {
  // Using environment variables for encryption key (not hardcoded)
  // ok: javascript-pseudorandom-number-generators
  const key = process.env.ENCRYPTION_KEY;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_4() {
  // Using crypto.randomBytes for salt generation in password hashing
  const password = "user_password";
  // ok: javascript-pseudorandom-number-generators
  const salt = crypto.randomBytes(16).toString('hex');
  const hashedPassword = bcrypt.hashSync(password, salt);
  return hashedPassword;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_5() {
  // Using bcrypt's built-in salt generation
  const password = "user_password";
  // ok: javascript-pseudorandom-number-generators
  const hashedPassword = bcrypt.hashSync(password, 10); // 10 rounds of hashing
  return hashedPassword;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_6() {
  // Using environment variable for JWT secret
  // ok: javascript-pseudorandom-number-generators
  const secret = process.env.JWT_SECRET;
  const token = jwt.sign({ user: 'user123' }, secret, { expiresIn: '1h' });
  return token;
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_7() {
  // Using a secure key management service
  async function encryptWithKMS() {
    // ok: javascript-pseudorandom-number-generators
    const AWS = require('aws-sdk');
    const kms = new AWS.KMS({ region: 'us-west-2' });
    
    const params = {
      KeyId: process.env.KMS_KEY_ID,
      Plaintext: Buffer.from('sensitive data')
    };
    
    const result = await kms.encrypt(params).promise();
    return result.CiphertextBlob.toString('base64');
  }
  
  return encryptWithKMS();
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_8() {
  // Using a key derivation function
  const password = "user_supplied_password";
  // ok: javascript-pseudorandom-number-generators
  crypto.pbkdf2(password, crypto.randomBytes(16), 100000, 32, 'sha512', (err, derivedKey) => {
    if (err) throw err;
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
    let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  });
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_9() {
  // Using secure random for session token generation
  app.get('/login', (req, res) => {
    const username = req.query.username;
    const password = req.query.password;
    
    if (username === 'admin' && password === 'password') {
      // ok: javascript-pseudorandom-number-generators
      const sessionToken = crypto.randomBytes(32).toString('hex');
      res.cookie('session', sessionToken, { httpOnly: true });
      res.send('Logged in successfully');
    }
  });
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_10() {
  // Using a secure token generator for password reset
  app.post('/reset-password', (req, res) => {
    const email = req.body.email;
    
    // ok: javascript-pseudorandom-number-generators
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    // Store token in database and send email
    res.send('Password reset email sent');
  });
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_11() {
  // Using a hardware security module (HSM) for encryption
  function encryptWithHSM() {
    // ok: javascript-pseudorandom-number-generators
    const HSM = require('node-hsm-client');
    const hsm = new HSM.Client({
      endpoint: process.env.HSM_ENDPOINT,
      credentials: {
        accessKeyId: process.env.HSM_ACCESS_KEY,
        secretAccessKey: process.env.HSM_SECRET_KEY
      }
    });
    
    return hsm.encrypt({
      KeyId: process.env.HSM_KEY_ID,
      Plaintext: Buffer.from('sensitive data')
    });
  }
  
  return encryptWithHSM();
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_12() {
  // Using secure key rotation
  function encryptWithRotatingKeys() {
    // ok: javascript-pseudorandom-number-generators
    const keyManager = {
      getActiveKey: function() {
        // Fetch the current active key from a secure key management service
        return process.env.CURRENT_ENCRYPTION_KEY;
      }
    };
    
    const key = keyManager.getActiveKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv: iv.toString('hex') };
  }
  
  return encryptWithRotatingKeys();
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_13() {
  // Using a secure random number generator for nonce
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  // ok: javascript-pseudorandom-number-generators
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(nonce);
  let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return { encrypted, tag, nonce: nonce.toString('hex') };
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_14() {
  // Using a secure key store
  async function encryptWithKeyStore() {
    const KeyStore = require('secure-key-store');
    // ok: javascript-pseudorandom-number-generators
    const keyStore = new KeyStore({
      provider: 'vault',
      config: {
        endpoint: process.env.VAULT_ENDPOINT,
        token: process.env.VAULT_TOKEN
      }
    });
    
    const key = await keyStore.getKey('encryption-key');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }
  
  return encryptWithKeyStore();
}
// {/fact}

// {fact rule=predictable-random-number-generator@v1.0 defects=0}
function good_case_15() {
  // Using a secure random UUID for identification
  const { v4: uuidv4 } = require('uuid');
  
  function generateSecureToken() {
    // ok: javascript-pseudorandom-number-generators
    return uuidv4(); // Uses crypto.randomBytes internally
  }
  
  const token = generateSecureToken();
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  
  return { token, hashedToken };
}
// {/fact}

module.exports = {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};