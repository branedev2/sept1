// File: crypto_cipher_test_cases.js
const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const CryptoJS = require('crypto-js');
const forge = require('node-forge');
const sjcl = require('sjcl');

// True Positive Cases (Vulnerable)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
  // Using Node.js crypto with ECB mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  // ruleid: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
  
  const text = 'This is a secret message';
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
  // Using CryptoJS with ECB mode explicitly
  const key = CryptoJS.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
  
  // ruleid: javascript-crypto-compliant-cipher
  const encrypted = CryptoJS.AES.encrypt('Secret data', key, {
    mode: CryptoJS.mode.ECB
  });
  
  return encrypted.toString();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
  // Using node-forge with ECB mode
  const key = forge.random.getBytesSync(16);
  
  // ruleid: javascript-crypto-compliant-cipher
  const cipher = forge.cipher.createCipher('AES-ECB', key);
  
  cipher.start();
  cipher.update(forge.util.createBuffer('Sensitive information'));
  cipher.finish();
  
  return cipher.output.toHex();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
  // Using crypto in a function with conditional logic but still using ECB
  const key = crypto.randomBytes(32);
  const data = 'Confidential data';
  let mode = 'ecb';
  
  if (data.length > 100) {
    mode = 'cbc';
  }
  
  // ruleid: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv(`aes-256-${mode}`, key, mode === 'cbc' ? crypto.randomBytes(16) : '');
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
  // Using ECB mode with a wrapper function
  const key = crypto.randomBytes(32);
  
  function encryptData(data, encryptionKey) {
    // ruleid: javascript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ecb', encryptionKey, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }
  
  return encryptData('Top secret information', key);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
  // Using ECB mode with string concatenation to form the algorithm name
  const key = crypto.randomBytes(32);
  const algorithm = 'aes-256-' + 'ecb';
  
  // ruleid: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv(algorithm, key, '');
  
  let encrypted = cipher.update('Sensitive customer data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
  // Using ECB mode in a loop for multiple data blocks
  const key = crypto.randomBytes(32);
  const dataBlocks = ['Block 1', 'Block 2', 'Block 3'];
  const results = [];
  
  for (const block of dataBlocks) {
    // ruleid: javascript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
    let encrypted = cipher.update(block, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    results.push(encrypted);
  }
  
  return results.join('');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
  // Using ECB mode with a variable algorithm name
  const key = crypto.randomBytes(32);
  const modes = ['cbc', 'ecb', 'ctr'];
  const selectedMode = modes[1]; // Selecting ECB
  
  // ruleid: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv(`aes-256-${selectedMode}`, key, selectedMode === 'cbc' ? crypto.randomBytes(16) : '');
  
  let encrypted = cipher.update('Private user information', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
  // Using ECB mode with CryptoJS in an object-oriented pattern
  class Encryptor {
    constructor(key) {
      this.key = CryptoJS.enc.Hex.parse(key);
    }
    
    encrypt(data) {
      // ruleid: javascript-crypto-compliant-cipher
      return CryptoJS.AES.encrypt(data, this.key, {
        mode: CryptoJS.mode.ECB
      }).toString();
    }
  }
  
  const encryptor = new Encryptor('000102030405060708090a0b0c0d0e0f');
  return encryptor.encrypt('Confidential business data');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
  // Using ECB mode with a try-catch block
  const key = crypto.randomBytes(32);
  
  try {
    // ruleid: javascript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
    let encrypted = cipher.update('Financial transaction data', 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch (error) {
    console.error('Encryption failed:', error);
    return null;
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
  // Using ECB mode with a promise
  const key = crypto.randomBytes(32);
  
  return new Promise((resolve, reject) => {
    try {
      // ruleid: javascript-crypto-compliant-cipher
      const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
      let encrypted = cipher.update('Health record data', 'utf8', 'hex');
      encrypted += cipher.final('hex');
      resolve(encrypted);
    } catch (error) {
      reject(error);
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
  // Using ECB mode with async/await
  const key = crypto.randomBytes(32);
  
  async function encryptAsync(data) {
    // ruleid: javascript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }
  
  return encryptAsync('Personal identification data');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
  // Using ECB mode with a switch statement
  const key = crypto.randomBytes(32);
  const operationType = 'encrypt';
  let result;
  
  switch (operationType) {
    case 'encrypt':
      // ruleid: javascript-crypto-compliant-cipher
      const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
      result = cipher.update('Credit card information', 'utf8', 'hex');
      result += cipher.final('hex');
      break;
    case 'decrypt':
      // Decryption logic would go here
      break;
    default:
      throw new Error('Invalid operation type');
  }
  
  return result;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
  // Using ECB mode with a factory pattern
  const key = crypto.randomBytes(32);
  
  const cryptoFactory = {
    createCipher: function(algorithm, key) {
      if (algorithm.includes('ecb')) {
        // ruleid: javascript-crypto-compliant-cipher
        return crypto.createCipheriv(algorithm, key, '');
      } else {
        return crypto.createCipheriv(algorithm, key, crypto.randomBytes(16));
      }
    }
  };
  
  const cipher = cryptoFactory.createCipher('aes-256-ecb', key);
  let encrypted = cipher.update('Password data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
  // Using ECB mode with a higher-order function
  const key = crypto.randomBytes(32);
  
  const withEncryption = (fn) => {
    return (data) => {
      // ruleid: javascript-crypto-compliant-cipher
      const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return fn(encrypted);
    };
  };
  
  const processData = withEncryption(result => `Processed: ${result}`);
  return processData('Authentication token');
}
// {/fact}

// True Negative Cases (Secure)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
  // Using Node.js crypto with CBC mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  // ok: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  
  const text = 'This is a secret message';
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
  // Using CryptoJS with CBC mode
  const key = CryptoJS.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
  const iv = CryptoJS.enc.Hex.parse('101112131415161718191a1b1c1d1e1f');
  
  // ok: javascript-crypto-compliant-cipher
  const encrypted = CryptoJS.AES.encrypt('Secret data', key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  
  return encrypted.toString();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
  // Using node-forge with CBC mode
  const key = forge.random.getBytesSync(16);
  const iv = forge.random.getBytesSync(16);
  
  // ok: javascript-crypto-compliant-cipher
  const cipher = forge.cipher.createCipher('AES-CBC', key);
  cipher.start({iv: iv});
  cipher.update(forge.util.createBuffer('Sensitive information'));
  cipher.finish();
  
  return cipher.output.toHex();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
  // Using crypto with CTR mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  // ok: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  
  let encrypted = cipher.update('Confidential data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
  // Using crypto with GCM mode (authenticated encryption)
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12); // GCM recommends 12 bytes
  
  // ok: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update('Top secret information', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  
  return { encrypted, authTag: authTag.toString('hex') };
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
  // Using CryptoJS with CTR mode
  const key = CryptoJS.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
  const iv = CryptoJS.enc.Hex.parse('101112131415161718191a1b1c1d1e1f');
  
  // ok: javascript-crypto-compliant-cipher
  const encrypted = CryptoJS.AES.encrypt('Sensitive customer data', key, {
    iv: iv,
    mode: CryptoJS.mode.CTR,
    padding: CryptoJS.pad.Pkcs7
  });
  
  return encrypted.toString();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
  // Using crypto with OFB mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  // ok: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv('aes-256-ofb', key, iv);
  
  let encrypted = cipher.update('Private user information', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
  // Using crypto with CFB mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  // ok: javascript-crypto-compliant-cipher
  const cipher = crypto.createCipheriv('aes-256-cfb', key, iv);
  
  let encrypted = cipher.update('Confidential business data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
  // Using crypto with a wrapper function for CBC mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  function encryptData(data, encryptionKey, initVector) {
    // ok: javascript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, initVector);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }
  
  return encryptData('Financial transaction data', key, iv);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
  // Using crypto with a promise for GCM mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  
  return new Promise((resolve, reject) => {
    try {
      // ok: javascript-crypto-compliant-cipher
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      let encrypted = cipher.update('Health record data', 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag();
      resolve({ encrypted, authTag: authTag.toString('hex') });
    } catch (error) {
      reject(error);
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
  // Using crypto with async/await for CBC mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  async function encryptAsync(data) {
    // ok: javascript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }
  
  return encryptAsync('Personal identification data');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
  // Using crypto with a factory pattern for secure modes
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  const cryptoFactory = {
    createCipher: function(algorithm, key, iv) {
      // ok: javascript-crypto-compliant-cipher
      return crypto.createCipheriv(algorithm, key, iv);
    }
  };
  
  const cipher = cryptoFactory.createCipher('aes-256-cbc', key, iv);
  let encrypted = cipher.update('Password data', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
  // Using sjcl (Stanford JavaScript Crypto Library) with CBC mode
  const key = sjcl.random.randomWords(8); // 256-bit key
  const iv = sjcl.random.randomWords(4);  // 128-bit IV
  
  // ok: javascript-crypto-compliant-cipher
  const params = {
    iv: iv,
    mode: 'cbc',
    ks: 256
  };
  
  const encrypted = sjcl.encrypt(key, 'Authentication token', params);
  return encrypted;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
  // Using crypto with a switch statement for different secure modes
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const mode = 'cbc'; // Could be 'cbc', 'ctr', 'gcm', etc.
  let result;
  
  switch (mode) {
    case 'cbc':
      // ok: javascript-crypto-compliant-cipher
      const cipherCbc = crypto.createCipheriv('aes-256-cbc', key, iv);
      result = cipherCbc.update('Credit card information', 'utf8', 'hex');
      result += cipherCbc.final('hex');
      break;
    case 'ctr':
      const cipherCtr = crypto.createCipheriv('aes-256-ctr', key, iv);
      result = cipherCtr.update('Credit card information', 'utf8', 'hex');
      result += cipherCtr.final('hex');
      break;
    case 'gcm':
      const cipherGcm = crypto.createCipheriv('aes-256-gcm', key, iv.slice(0, 12));
      result = cipherGcm.update('Credit card information', 'utf8', 'hex');
      result += cipherGcm.final('hex');
      break;
    default:
      throw new Error('Invalid mode');
  }
  
  return result;
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
  // Using a higher-order function with CBC mode
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  const withSecureEncryption = (fn) => {
    return (data) => {
      // ok: javascript-crypto-compliant-cipher
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return fn(encrypted);
    };
  };
  
  const processData = withSecureEncryption(result => `Processed: ${result}`);
  return processData('Authentication token');
}
// {/fact}