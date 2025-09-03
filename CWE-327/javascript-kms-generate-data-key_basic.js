// Import required AWS SDK modules
const AWS = require('aws-sdk');
const { KMS } = require('@aws-sdk/client-kms');

// True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
  // Using KMS to generate a data key but not properly handling the plaintext key
  const kms = new AWS.KMS();
  
  kms.generateDataKey({
    KeyId: 'alias/my-key',
    KeySpec: 'AES_256'
  }, (err, data) => {
    if (err) {
      console.error(err);
      return;
    }
    
    // ruleid: javascript-kms-generate-data-key
    // Storing plaintext key in a variable and using it directly is insecure
    const plaintextKey = data.Plaintext;
    const encryptedData = encrypt(sensitiveData, plaintextKey);
    
    // Storing plaintext key in memory for extended periods
    globalThis.cachedKey = plaintextKey;
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
  // Using KMS to generate a data key and logging the plaintext key
  const kms = new AWS.KMS();
  
  async function encryptSensitiveData(data) {
    try {
      const response = await kms.generateDataKey({
        KeyId: 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
        KeySpec: 'AES_256'
      }).promise();
      
      // ruleid: javascript-kms-generate-data-key
      // Logging plaintext key is a security risk
      console.log("Generated key:", response.Plaintext.toString('base64'));
      
      return encrypt(data, response.Plaintext);
    } catch (error) {
      console.error("Error generating data key:", error);
    }
  }
  
  encryptSensitiveData("sensitive information");
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
  // Using KMS to generate a data key and storing it in a file
  const kms = new AWS.KMS();
  const fs = require('fs');
  
  kms.generateDataKey({
    KeyId: 'alias/my-encryption-key',
    KeySpec: 'AES_256'
  }, (err, data) => {
    if (err) throw err;
    
    // ruleid: javascript-kms-generate-data-key
    // Writing plaintext key to a file is insecure
    fs.writeFileSync('encryption-key.txt', data.Plaintext);
    
    const ciphertextBlob = data.CiphertextBlob;
    fs.writeFileSync('encrypted-key.enc', ciphertextBlob);
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
  // Using KMS to generate a data key and sending it over HTTP
  const kms = new AWS.KMS();
  const http = require('http');
  
  async function handleRequest(req, res) {
    try {
      const keyData = await kms.generateDataKey({
        KeyId: 'alias/app-key',
        KeySpec: 'AES_256'
      }).promise();
      
      // ruleid: javascript-kms-generate-data-key
      // Sending plaintext key over HTTP response
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        key: keyData.Plaintext.toString('base64'),
        encryptedKey: keyData.CiphertextBlob.toString('base64')
      }));
    } catch (error) {
      res.writeHead(500);
      res.end('Error generating key');
    }
  }
  
  const server = http.createServer(handleRequest);
  server.listen(3000);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
  // Using KMS to generate multiple data keys and storing them in a database
  const kms = new AWS.KMS();
  const db = require('./database');
  
  async function generateAndStoreKeys(count) {
    for (let i = 0; i < count; i++) {
      const keyData = await kms.generateDataKey({
        KeyId: 'alias/multi-key',
        KeySpec: 'AES_256'
      }).promise();
      
      // ruleid: javascript-kms-generate-data-key
      // Storing plaintext keys in a database
      await db.storeKey({
        keyId: `key-${i}`,
        plaintextKey: keyData.Plaintext,
        encryptedKey: keyData.CiphertextBlob
      });
    }
  }
  
  generateAndStoreKeys(5);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
  // Using KMS with the AWS SDK v3 client but not handling the plaintext key securely
  const kmsClient = new KMS({ region: 'us-west-2' });
  
  async function encryptWithGeneratedKey(data) {
    const params = {
      KeyId: 'alias/my-key',
      KeySpec: 'AES_256'
    };
    
    try {
      const response = await kmsClient.generateDataKey(params);
      
      // ruleid: javascript-kms-generate-data-key
      // Storing plaintext key in localStorage is insecure
      if (typeof window !== 'undefined') {
        localStorage.setItem('encryption_key', response.Plaintext.toString('base64'));
      }
      
      return encrypt(data, response.Plaintext);
    } catch (error) {
      console.error("Failed to generate data key:", error);
    }
  }
  
  encryptWithGeneratedKey("sensitive data");
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
  // Using KMS to generate a data key and exposing it through an API
  const kms = new AWS.KMS();
  const express = require('express');
  const app = express();
  
  app.get('/generate-key', async (req, res) => {
    try {
      const keyData = await kms.generateDataKey({
        KeyId: 'alias/customer-key',
        KeySpec: 'AES_256'
      }).promise();
      
      // ruleid: javascript-kms-generate-data-key
      // Exposing plaintext key through an API
      res.json({
        success: true,
        key: keyData.Plaintext.toString('base64'),
        encryptedKey: keyData.CiphertextBlob.toString('base64')
      });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
  // Using KMS to generate a data key with weak key spec
  const kms = new AWS.KMS();
  
  async function encryptWithWeakKey(data) {
    try {
      // ruleid: javascript-kms-generate-data-key
      // Using a weaker key specification (AES_128 instead of AES_256)
      const response = await kms.generateDataKey({
        KeyId: 'alias/weak-key',
        KeySpec: 'AES_128'
      }).promise();
      
      return encrypt(data, response.Plaintext);
    } catch (error) {
      console.error("Error generating data key:", error);
    }
  }
  
  encryptWithWeakKey("sensitive information");
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
  // Using KMS to generate a data key and storing it in a cookie
  const kms = new AWS.KMS();
  const express = require('express');
  const app = express();
  
  app.get('/set-encryption-cookie', async (req, res) => {
    try {
      const keyData = await kms.generateDataKey({
        KeyId: 'alias/cookie-key',
        KeySpec: 'AES_256'
      }).promise();
      
      // ruleid: javascript-kms-generate-data-key
      // Setting plaintext key in a cookie is insecure
      res.cookie('encryptionKey', keyData.Plaintext.toString('base64'), { maxAge: 3600000 });
      res.send('Encryption key cookie set');
    } catch (error) {
      res.status(500).send('Error setting encryption cookie');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
  // Using KMS to generate a data key and passing it to client-side code
  const kms = new AWS.KMS();
  
  async function setupClientSideEncryption() {
    try {
      const keyData = await kms.generateDataKey({
        KeyId: 'alias/client-key',
        KeySpec: 'AES_256'
      }).promise();
      
      // ruleid: javascript-kms-generate-data-key
      // Passing plaintext key to client-side code
      const clientScript = `
        <script>
          const encryptionKey = "${keyData.Plaintext.toString('base64')}";
          function encryptClientData(data) {
            // Client-side encryption using the key
            return window.btoa(data); // Simplified for example
          }
        </script>
      `;
      
      return clientScript;
    } catch (error) {
      console.error("Error setting up client-side encryption:", error);
    }
  }
  
  setupClientSideEncryption();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
  // Using KMS to generate a data key and storing it in environment variables
  const kms = new AWS.KMS();
  
  async function setupEncryptionEnvironment() {
    try {
      const keyData = await kms.generateDataKey({
        KeyId: 'alias/env-key',
        KeySpec: 'AES_256'
      }).promise();
      
      // ruleid: javascript-kms-generate-data-key
      // Setting plaintext key in environment variables
      process.env.ENCRYPTION_KEY = keyData.Plaintext.toString('base64');
      process.env.ENCRYPTED_KEY = keyData.CiphertextBlob.toString('base64');
      
      console.log('Encryption environment set up');
    } catch (error) {
      console.error("Error setting up encryption environment:", error);
    }
  }
  
  setupEncryptionEnvironment();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
  // Using KMS to generate a data key and caching it for too long
  const kms = new AWS.KMS();
  
  class KeyManager {
    constructor() {
      this.keyCache = {};
    }
    
    async getOrGenerateKey(keyAlias) {
      // Check if key exists in cache and is not expired
      if (this.keyCache[keyAlias] && this.keyCache[keyAlias].expiry > Date.now()) {
        return this.keyCache[keyAlias].key;
      }
      
      try {
        const keyData = await kms.generateDataKey({
          KeyId: `alias/${keyAlias}`,
          KeySpec: 'AES_256'
        }).promise();
        
        // ruleid: javascript-kms-generate-data-key
        // Caching plaintext key for 24 hours is too long
        this.keyCache[keyAlias] = {
          key: keyData.Plaintext,
          expiry: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
        };
        
        return keyData.Plaintext;
      } catch (error) {
        console.error(`Error generating key for ${keyAlias}:`, error);
        throw error;
      }
    }
  }
  
  const keyManager = new KeyManager();
  keyManager.getOrGenerateKey('app-key');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
  // Using KMS to generate a data key and sharing it across multiple services
  const kms = new AWS.KMS();
  const axios = require('axios');
  
  async function distributeEncryptionKey() {
    try {
      const keyData = await kms.generateDataKey({
        KeyId: 'alias/shared-key',
        KeySpec: 'AES_256'
      }).promise();
      
      const serviceEndpoints = [
        'https://service1.example.com/set-key',
        'https://service2.example.com/set-key',
        'https://service3.example.com/set-key'
      ];
      
      // ruleid: javascript-kms-generate-data-key
      // Distributing plaintext key to multiple services
      const distributionPromises = serviceEndpoints.map(endpoint => 
        axios.post(endpoint, {
          plaintextKey: keyData.Plaintext.toString('base64'),
          encryptedKey: keyData.CiphertextBlob.toString('base64')
        })
      );
      
      await Promise.all(distributionPromises);
      console.log('Key distributed to all services');
    } catch (error) {
      console.error("Error distributing encryption key:", error);
    }
  }
  
  distributeEncryptionKey();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
  // Using KMS to generate a data key and using it for multiple purposes
  const kms = new AWS.KMS();
  const crypto = require('crypto');
  
  async function setupMultipurposeKey() {
    try {
      const keyData = await kms.generateDataKey({
        KeyId: 'alias/multipurpose-key',
        KeySpec: 'AES_256'
      }).promise();
      
      // ruleid: javascript-kms-generate-data-key
      // Using the same key for multiple cryptographic purposes
      const plaintextKey = keyData.Plaintext;
      
      // Using same key for encryption
      function encryptData(data) {
        const cipher = crypto.createCipher('aes-256-cbc', plaintextKey);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
      }
      
      // Using same key for HMAC
      function signData(data) {
        const hmac = crypto.createHmac('sha256', plaintextKey);
        hmac.update(data);
        return hmac.digest('hex');
      }
      
      return {
        encrypt: encryptData,
        sign: signData
      };
    } catch (error) {
      console.error("Error setting up multipurpose key:", error);
    }
  }
  
  setupMultipurposeKey();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
  // Using KMS to generate a data key without context
  const kms = new AWS.KMS();
  
  async function encryptWithoutContext(data) {
    try {
      // ruleid: javascript-kms-generate-data-key
      // Not using encryption context for additional security
      const response = await kms.generateDataKey({
        KeyId: 'alias/no-context-key',
        KeySpec: 'AES_256'
      }).promise();
      
      const plaintextKey = response.Plaintext;
      return encrypt(data, plaintextKey);
    } catch (error) {
      console.error("Error generating data key:", error);
    }
  }
  
  encryptWithoutContext("sensitive information");
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
  // Using KMS to generate a data key and properly handling the plaintext key
  const kms = new AWS.KMS();
  
  async function encryptData(data) {
    try {
      // ok: javascript-kms-generate-data-key
      const response = await kms.generateDataKey({
        KeyId: 'alias/my-key',
        KeySpec: 'AES_256',
        EncryptionContext: {
          'AppName': 'MyApp',
          'Purpose': 'DataEncryption'
        }
      }).promise();
      
      // Use the plaintext key to encrypt data, then immediately remove it from memory
      const encryptedData = encrypt(data, response.Plaintext);
      
      // Store only the encrypted key for later decryption
      return {
        encryptedData,
        encryptedKey: response.CiphertextBlob
      };
    } catch (error) {
      console.error("Error encrypting data:", error);
      throw error;
    }
  }
  
  encryptData("sensitive information");
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
  // Using KMS to generate a data key with proper key rotation
  const kms = new AWS.KMS();
  
  class SecureKeyManager {
    constructor() {
      this.keyCache = {};
      this.keyRotationInterval = 3600000; // 1 hour
    }
    
    async getEncryptionKey(keyAlias) {
      const now = Date.now();
      const cacheEntry = this.keyCache[keyAlias];
      
      if (cacheEntry && cacheEntry.expiry > now) {
        return {
          encryptedKey: cacheEntry.encryptedKey,
          plaintextKey: await this.decryptKey(cacheEntry.encryptedKey)
        };
      }
      
      // ok: javascript-kms-generate-data-key
      const response = await kms.generateDataKey({
        KeyId: `alias/${keyAlias}`,
        KeySpec: 'AES_256',
        EncryptionContext: {
          'KeyRotation': new Date().toISOString()
        }
      }).promise();
      
      this.keyCache[keyAlias] = {
        encryptedKey: response.CiphertextBlob,
        expiry: now + this.keyRotationInterval
      };
      
      return {
        encryptedKey: response.CiphertextBlob,
        plaintextKey: response.Plaintext
      };
    }
    
    async decryptKey(encryptedKey) {
      const response = await kms.decrypt({
        CiphertextBlob: encryptedKey,
        EncryptionContext: {
          'KeyRotation': new Date().toISOString()
        }
      }).promise();
      
      return response.Plaintext;
    }
  }
  
  const keyManager = new SecureKeyManager();
  keyManager.getEncryptionKey('app-key');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
  // Using KMS to generate a data key and properly storing only the encrypted key
  const kms = new AWS.KMS();
  const fs = require('fs');
  
  async function generateAndStoreKey() {
    try {
      // ok: javascript-kms-generate-data-key
      const response = await kms.generateDataKey({
        KeyId: 'alias/my-encryption-key',
        KeySpec: 'AES_256',
        EncryptionContext: {
          'Purpose': 'FileEncryption',
          'CreatedAt': new Date().toISOString()
        }
      }).promise();
      
      // Use the plaintext key for immediate encryption
      const dataToEncrypt = fs.readFileSync('sensitive-data.txt');
      const encryptedData = encrypt(dataToEncrypt, response.Plaintext);
      
      // Store only the encrypted key alongside the encrypted data
      fs.writeFileSync('data.enc', encryptedData);
      fs.writeFileSync('key.enc', response.CiphertextBlob);
      
      console.log('Data encrypted and stored successfully');
    } catch (error) {
      console.error("Error generating and storing key:", error);
    }
  }
  
  generateAndStoreKey();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
  // Using KMS to generate a data key and securely handling it in a web application
  const kms = new AWS.KMS();
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/encrypt', async (req, res) => {
    try {
      const { data } = req.body;
      
      if (!data) {
        return res.status(400).json({ error: 'No data provided for encryption' });
      }
      
      // ok: javascript-kms-generate-data-key
      const keyResponse = await kms.generateDataKey({
        KeyId: 'alias/web-app-key',
        KeySpec: 'AES_256',
        EncryptionContext: {
          'RequestId': crypto.randomUUID(),
          'Timestamp': new Date().toISOString()
        }
      }).promise();
      
      // Encrypt the data with the plaintext key
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', keyResponse.Plaintext, iv);
      let encrypted = cipher.update(data, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      
      // Return only the encrypted data and encrypted key
      res.json({
        encryptedData: encrypted,
        iv: iv.toString('base64'),
        encryptedKey: keyResponse.CiphertextBlob.toString('base64')
      });
    } catch (error) {
      console.error('Encryption error:', error);
      res.status(500).json({ error: 'Failed to encrypt data' });
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
  // Using KMS with the AWS SDK v3 client and properly handling the data key
  const kmsClient = new KMS({ region: 'us-west-2' });
  const crypto = require('crypto');
  
  async function encryptFile(filePath) {
    const fileData = require('fs').readFileSync(filePath);
    
    // ok: javascript-kms-generate-data-key
    const keyResponse = await kmsClient.generateDataKey({
      KeyId: 'alias/file-encryption-key',
      KeySpec: 'AES_256',
      EncryptionContext: {
        'FilePath': filePath,
        'Operation': 'FileEncryption'
      }
    });
    
    // Generate a random IV
    const iv = crypto.randomBytes(16);
    
    // Encrypt the file data
    const cipher = crypto.createCipheriv('aes-256-cbc', keyResponse.Plaintext, iv);
    let encryptedData = cipher.update(fileData);
    encryptedData = Buffer.concat([encryptedData, cipher.final()]);
    
    // Create the output structure with encrypted data, IV, and encrypted key
    const output = {
      iv: iv.toString('base64'),
      encryptedData: encryptedData.toString('base64'),
      encryptedKey: Buffer.from(keyResponse.CiphertextBlob).toString('base64')
    };
    
    // Write the encrypted file
    require('fs').writeFileSync(`${filePath}.enc`, JSON.stringify(output));
    console.log(`File encrypted: ${filePath}.enc`);
  }
  
  encryptFile('document.txt');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
  // Using KMS to generate a data key with proper context and key usage
  const kms = new AWS.KMS();
  
  async function encryptUserData(userId, userData) {
    try {
      // Create a specific encryption context for this user
      const encryptionContext = {
        'UserId': userId,
        'Purpose': 'UserDataEncryption',
        'Timestamp': new Date().toISOString()
      };
      
      // ok: javascript-kms-generate-data-key
      const keyResponse = await kms.generateDataKey({
        KeyId: 'alias/user-data-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
      }).promise();
      
      // Encrypt the user data
      const encryptedData = encrypt(userData, keyResponse.Plaintext);
      
      // Store the encrypted data along with the encrypted key and context
      return {
        userId,
        encryptedData,
        encryptedKey: keyResponse.CiphertextBlob,
        // Store the encryption context for later decryption
        encryptionContext
      };
    } catch (error) {
      console.error(`Error encrypting data for user ${userId}:`, error);
      throw error;
    }
  }
  
  encryptUserData('user123', { name: 'John Doe', email: 'john@example.com' });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
  // Using KMS to generate a data key with proper key derivation
  const kms = new AWS.KMS();
  const crypto = require('crypto');
  
  async function encryptWithKeyDerivation(data, purpose) {
    try {
      // ok: javascript-kms-generate-data-key
      const keyResponse = await kms.generateDataKey({
        KeyId: 'alias/master-key',
        KeySpec: 'AES_256',
        EncryptionContext: {
          'Purpose': 'MasterKey',
          'Application': 'SecureApp'
        }
      }).promise();
      
      // Derive different keys for different purposes using HKDF
      const masterKey = keyResponse.Plaintext;
      const derivedKey = crypto.createHmac('sha256', masterKey)
        .update(purpose)
        .digest();
      
      // Encrypt with the derived key
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
      let encryptedData = cipher.update(data, 'utf8', 'base64');
      encryptedData += cipher.final('base64');
      
      return {
        encryptedData,
        iv: iv.toString('base64'),
        encryptedMasterKey: keyResponse.CiphertextBlob.toString('base64'),
        purpose
      };
    } catch (error) {
      console.error("Error encrypting with key derivation:", error);
      throw error;
    }
  }
  
  encryptWithKeyDerivation('sensitive data', 'data-encryption');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
  // Using KMS to generate a data key with proper key rotation and memory management
  const kms = new AWS.KMS();
  
  class SecureEncryptionService {
    constructor(keyId) {
      this.keyId = keyId;
      this.keyCache = new Map();
      
      // Set up automatic key rotation
      setInterval(() => this.rotateKeys(), 3600000); // Rotate keys every hour
    }
    
    async rotateKeys() {
      console.log('Rotating encryption keys');
      this.keyCache.clear();
    }
    
    async encrypt(data, context = {}) {
      const keyMaterial = await this.getOrGenerateKey(context);
      
      try {
        // Encrypt the data
        const encrypted = this.performEncryption(data, keyMaterial.plaintextKey);
        
        // Return result with the encrypted key
        return {
          encryptedData: encrypted,
          encryptedKey: keyMaterial.encryptedKey,
          context
        };
      } finally {
        // Explicitly overwrite the plaintext key in memory
        if (keyMaterial.plaintextKey) {
          keyMaterial.plaintextKey.fill(0);
        }
      }
    }
    
    async getOrGenerateKey(context) {
      const contextKey = JSON.stringify(context);
      
      if (this.keyCache.has(contextKey)) {
        return this.keyCache.get(contextKey);
      }
      
      // ok: javascript-kms-generate-data-key
      const response = await kms.generateDataKey({
        KeyId: this.keyId,
        KeySpec: 'AES_256',
        EncryptionContext: context
      }).promise();
      
      const keyMaterial = {
        plaintextKey: response.Plaintext,
        encryptedKey: response.CiphertextBlob
      };
      
      this.keyCache.set(contextKey, keyMaterial);
      return keyMaterial;
    }
    
    performEncryption(data, key) {
      // Implementation of encryption using the key
      return Buffer.from(data).toString('base64'); // Simplified for example
    }
  }
  
  const encryptionService = new SecureEncryptionService('alias/secure-service-key');
  encryptionService.encrypt('sensitive data', { purpose: 'test' });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
  // Using KMS to generate a data key with envelope encryption pattern
  const kms = new AWS.KMS();
  const crypto = require('crypto');
  
  async function envelopeEncrypt(data) {
    try {
      // ok: javascript-kms-generate-data-key
      const keyResponse = await kms.generateDataKey({
        KeyId: 'alias/envelope-key',
        KeySpec: 'AES_256',
        EncryptionContext: {
          'Purpose': 'EnvelopeEncryption',
          'Timestamp': Date.now().toString()
        }
      }).promise();
      
      // Generate a random IV
      const iv = crypto.randomBytes(16);
      
      // Encrypt the data with the data key
      const cipher = crypto.createCipheriv('aes-256-gcm', keyResponse.Plaintext, iv);
      let encryptedData = cipher.update(data, 'utf8', 'base64');
      encryptedData += cipher.final('base64');
      const authTag = cipher.getAuthTag();
      
      // Return the encrypted data, IV, auth tag, and encrypted data key
      return {
        encryptedData,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        encryptedDataKey: keyResponse.CiphertextBlob.toString('base64')
      };
    } catch (error) {
      console.error("Error performing envelope encryption:", error);
      throw error;
    }
  }
  
  envelopeEncrypt('sensitive data to encrypt');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
  // Using KMS to generate a data key with proper error handling and retry logic
  const kms = new AWS.KMS();
  
  async function encryptWithRetry(data, maxRetries = 3) {
    let retries = 0;
    
    while (retries <= maxRetries) {
      try {
        // ok: javascript-kms-generate-data-key
        const keyResponse = await kms.generateDataKey({
          KeyId: 'alias/retry-key',
          KeySpec: 'AES_256',
          EncryptionContext: {
            'AttemptNumber': retries.toString(),
            'Timestamp': new Date().toISOString()
          }
        }).promise();
        
        // Encrypt the data
        const encryptedData = encrypt(data, keyResponse.Plaintext);
        
        return {
          encryptedData,
          encryptedKey: keyResponse.CiphertextBlob
        };
      } catch (error) {
        retries++;
        console.error(`KMS operation failed (attempt ${retries}/${maxRetries}):`, error);
        
        if (retries > maxRetries) {
          throw new Error(`Failed to encrypt data after ${maxRetries} attempts`);
        }
        
        // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, 2 ** retries * 100));
      }
    }
  }
  
  encryptWithRetry('important data');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
  // Using KMS to generate a data key with proper key usage separation
  const kms = new AWS.KMS();
  const crypto = require('crypto');
  
  class KeyPurposeManager {
    constructor(masterKeyId) {
      this.masterKeyId = masterKeyId;
    }
    
    async generatePurposeSpecificKeys() {
      // ok: javascript-kms-generate-data-key
      const response = await kms.generateDataKey({
        KeyId: this.masterKeyId,
        KeySpec: 'AES_256',
        EncryptionContext: {
          'Operation': 'KeyGeneration',
          'Timestamp': new Date().toISOString()
        }
      }).promise();
      
      // Derive separate keys for encryption and authentication
      const masterKey = response.Plaintext;
      
      const encryptionKey = crypto.createHmac('sha256', masterKey)
        .update('encryption')
        .digest();
        
      const authenticationKey = crypto.createHmac('sha256', masterKey)
        .update('authentication')
        .digest();
      
      // Return the purpose-specific keys and the encrypted master key
      return {
        encryptionKey,
        authenticationKey,
        encryptedMasterKey: response.CiphertextBlob
      };
    }
    
    async encryptAndAuthenticate(data) {
      const keys = await this.generatePurposeSpecificKeys();
      
      try {
        // Encrypt the data
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', keys.encryptionKey, iv);
        let encryptedData = cipher.update(data, 'utf8', 'base64');
        encryptedData += cipher.final('base64');
        
        // Create HMAC for authentication
        const hmac = crypto.createHmac('sha256', keys.authenticationKey);
        hmac.update(encryptedData);
        hmac.update(iv.toString('base64'));
        const signature = hmac.digest('base64');
        
        return {
          encryptedData,
          iv: iv.toString('base64'),
          signature,
          encryptedMasterKey: keys.encryptedMasterKey.toString('base64')
        };
      } finally {
        // Clear sensitive key material from memory
        if (keys.encryptionKey) keys.encryptionKey.fill(0);
        if (keys.authenticationKey) keys.authenticationKey.fill(0);
      }
    }
  }
  
  const keyManager = new KeyPurposeManager('alias/purpose-specific-key');
  keyManager.encryptAndAuthenticate('sensitive data');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
  // Using KMS to generate a data key with proper AWS SDK v3 client configuration
  const kmsClient = new KMS({
    region: 'us-west-2',
    maxAttempts: 3,
    retryMode: 'standard'
  });
  
  async function secureEncrypt(data, metadata) {
    // Create a unique encryption context based on the metadata
    const encryptionContext = {
      ...metadata,
      'Timestamp': new Date().toISOString()
    };
    
    try {
      // ok: javascript-kms-generate-data-key
      const keyResponse = await kmsClient.generateDataKey({
        KeyId: 'alias/secure-v3-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
      });
      
      // Use the plaintext key for encryption
      const encryptedData = encrypt(data, keyResponse.Plaintext);
      
      // Return the encrypted data along with the encrypted key and context
      return {
        encryptedData,
        encryptedKey: Buffer.from(keyResponse.CiphertextBlob).toString('base64'),
        encryptionContext
      };
    } catch (error) {
      console.error("Encryption error:", error);
      throw new Error("Failed to encrypt data securely");
    }
  }
  
  secureEncrypt('sensitive data', { department: 'finance', userId: '12345' });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
  // Using KMS to generate a data key with proper audit logging
  const kms = new AWS.KMS();
  const winston = require('winston');
  
  // Set up secure logger (without sensitive data)
  const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
      new winston.transports.File({ filename: 'encryption-audit.log' })
    ]
  });
  
  async function auditedEncryption(data, userId) {
    const requestId = require('crypto').randomUUID();
    
    try {
      logger.info({
        action: 'ENCRYPTION_STARTED',
        requestId,
        userId,
        timestamp: new Date().toISOString()
      });
      
      // ok: javascript-kms-generate-data-key
      const keyResponse = await kms.generateDataKey({
        KeyId: 'alias/audited-key',
        KeySpec: 'AES_256',
        EncryptionContext: {
          'RequestId': requestId,
          'UserId': userId
        }
      }).promise();
      
      // Encrypt the data
      const encryptedData = encrypt(data, keyResponse.Plaintext);
      
      logger.info({
        action: 'ENCRYPTION_COMPLETED',
        requestId,
        userId,
        timestamp: new Date().toISOString(),
        success: true
      });
      
      return {
        requestId,
        encryptedData,
        encryptedKey: keyResponse.CiphertextBlob
      };
    } catch (error) {
      logger.error({
        action: 'ENCRYPTION_FAILED',
        requestId,
        userId,
        timestamp: new Date().toISOString(),
        error: error.message
      });
      
      throw error;
    }
  }
  
  auditedEncryption('sensitive customer data', 'user-123');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
  // Using KMS to generate a data key with proper key caching and memory management
  const kms = new AWS.KMS();
  
  class SecureDataEncryptor {
    constructor() {
      this.keyCache = new Map();
      this.cacheTTL = 300000; // 5 minutes
      
      // Clean up expired keys periodically
      setInterval(() => this.cleanupExpiredKeys(), 60000);
    }
    
    cleanupExpiredKeys() {
      const now = Date.now();
      for (const [cacheKey, entry] of this.keyCache.entries()) {
        if (entry.expiry <= now) {
          // Securely clear the key material before removing from cache
          if (entry.plaintextKey) {
            entry.plaintextKey.fill(0);
          }
          this.keyCache.delete(cacheKey);
        }
      }
    }
    
    async encrypt(data, context) {
      const cacheKey = JSON.stringify(context);
      const now = Date.now();
      let keyMaterial;
      
      // Check if we have a non-expired key in the cache
      if (this.keyCache.has(cacheKey)) {
        const cachedEntry = this.keyCache.get(cacheKey);
        if (cachedEntry.expiry > now) {
          keyMaterial = cachedEntry;
        }
      }
      
      // Generate a new key if needed
      if (!keyMaterial) {
        // ok: javascript-kms-generate-data-key
        const response = await kms.generateDataKey({
          KeyId: 'alias/secure-encryptor-key',
          KeySpec: 'AES_256',
          EncryptionContext: context
        }).promise();
        
        keyMaterial = {
          plaintextKey: response.Plaintext,
          encryptedKey: response.CiphertextBlob,
          expiry: now + this.cacheTTL
        };
        
        this.keyCache.set(cacheKey, keyMaterial);
      }
      
      try {
        // Encrypt the data
        const encryptedData = encrypt(data, keyMaterial.plaintextKey);
        
        return {
          encryptedData,
          encryptedKey: keyMaterial.encryptedKey,
          context
        };
      } catch (error) {
        console.error("Encryption error:", error);
        throw error;
      }
    }
  }
  
  const encryptor = new SecureDataEncryptor();
  encryptor.encrypt('sensitive data', { purpose: 'customer-record' });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
  // Using KMS to generate a data key with proper AWS SDK configuration and context
  const kms = new AWS.KMS({
    region: 'us-west-2',
    maxRetries: 3,
    httpOptions: {
      timeout: 5000
    }
  });
  
  async function encryptWithContext(data, applicationContext) {
    // Create a comprehensive encryption context
    const encryptionContext = {
      ...applicationContext,
      'Application': 'SecureService',
      'Environment': process.env.NODE_ENV || 'development',
      'Timestamp': new Date().toISOString(),
      'RequestId': require('crypto').randomUUID()
    };
    
    try {
      // ok: javascript-kms-generate-data-key
      const keyResponse = await kms.generateDataKey({
        KeyId: 'alias/context-aware-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
      }).promise();
      
      // Use the plaintext key for encryption
      const encryptedData = encrypt(data, keyResponse.Plaintext);
      
      // Return the encrypted data along with the encrypted key and context
      return {
        encryptedData,
        encryptedKey: keyResponse.CiphertextBlob,
        // Store the encryption context for later decryption
        encryptionContext
      };
    } catch (error) {
      console.error("Failed to encrypt data:", error);
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }
  
  encryptWithContext('sensitive data', { userId: '12345', action: 'payment' });
}
// {/fact}

// Helper function for encryption (simplified for example purposes)
function encrypt(data, key) {
  // In a real implementation, this would use proper cryptographic methods
  return Buffer.from(data).toString('base64');
}