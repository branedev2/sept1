// Import necessary crypto libraries
const crypto = require('crypto');
const md5 = require('md5');
const sha1 = require('sha1');
const jsSHA = require('jssha');
const CryptoJS = require('crypto-js');

// True Positive Examples (Vulnerable Code)

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_1() {
  const password = "user_password";
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
  console.log(`Hashed password: ${hashedPassword}`);
  return hashedPassword;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_2() {
  const userData = { username: "john", password: "secret123" };
  const dataString = JSON.stringify(userData);
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const checksum = crypto.createHash('sha1').update(dataString).digest('hex');
  return checksum;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_3() {
  const sensitiveData = "credit_card_number";
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const hash = md5(sensitiveData);
  console.log(`MD5 hash: ${hash}`);
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_4() {
  const userInput = "user_provided_data";
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const hash = sha1(userInput);
  return { data: userInput, hash: hash };
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_5() {
  const message = "important_message";
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const shaObj = new jsSHA("SHA-1", "TEXT");
  shaObj.update(message);
  const hash = shaObj.getHash("HEX");
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_6() {
  const data = "sensitive_information";
  const key = "secret_key";
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const hmac = crypto.createHmac('md5', key).update(data).digest('hex');
  return hmac;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_7() {
  const fileContent = "file_content_to_verify";
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const hash = CryptoJS.MD5(fileContent).toString();
  console.log(`File hash: ${hash}`);
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_8() {
  const userData = { id: 123, name: "Alice" };
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const hash = CryptoJS.RIPEMD160(JSON.stringify(userData)).toString();
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_9() {
  const message = "message_to_sign";
  const key = "signing_key";
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const signature = CryptoJS.HmacSHA1(message, key).toString();
  return { message, signature };
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_10() {
  const data = Buffer.from("binary_data");
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('ripemd160').update(data).digest('base64');
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_11() {
  class SecurityService {
    hashPassword(password) {
      // ruleid: javascript-avoid-weak-hashing-algorithms
      return crypto.createHash('md4').update(password).digest('hex');
    }
  }
  
  const security = new SecurityService();
  return security.hashPassword("user_password");
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_12() {
  const generateToken = (userId) => {
    const timestamp = Date.now();
    const data = `${userId}-${timestamp}`;
    // ruleid: javascript-avoid-weak-hashing-algorithms
    return crypto.createHash('md6').update(data).digest('hex');
  };
  
  return generateToken(12345);
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_13() {
  const verifyData = (data, hash) => {
    // ruleid: javascript-avoid-weak-hashing-algorithms
    const calculatedHash = CryptoJS.RIPEMD128(data).toString();
    return calculatedHash === hash;
  };
  
  return verifyData("important_data", "stored_hash");
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_14() {
  const data = "data_to_hash";
  let algorithm = 'md5';
  if (process.env.NODE_ENV === 'production') {
    algorithm = 'md5'; // Still using MD5 even in production
  }
  // ruleid: javascript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash(algorithm).update(data).digest('hex');
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_15() {
  function hashWithFallback(data, primaryAlgo = 'sha256', fallbackAlgo = 'sha1') {
    try {
      return crypto.createHash(primaryAlgo).update(data).digest('hex');
    } catch (e) {
      // ruleid: javascript-avoid-weak-hashing-algorithms
      return crypto.createHash(fallbackAlgo).update(data).digest('hex');
    }
  }
  
  // Force fallback to SHA-1
  const result = hashWithFallback("test_data", "invalid_algo");
  return result;
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_1() {
  const password = "user_password";
  // ok: javascript-avoid-weak-hashing-algorithms
  const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
  console.log(`Hashed password: ${hashedPassword}`);
  return hashedPassword;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_2() {
  const userData = { username: "john", password: "secret123" };
  const dataString = JSON.stringify(userData);
  // ok: javascript-avoid-weak-hashing-algorithms
  const checksum = crypto.createHash('sha512').update(dataString).digest('hex');
  return checksum;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_3() {
  const sensitiveData = "credit_card_number";
  // ok: javascript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('sha3-256').update(sensitiveData).digest('hex');
  console.log(`SHA3-256 hash: ${hash}`);
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_4() {
  const userInput = "user_provided_data";
  // ok: javascript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('sha384').update(userInput).digest('hex');
  return { data: userInput, hash: hash };
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_5() {
  const message = "important_message";
  // ok: javascript-avoid-weak-hashing-algorithms
  const shaObj = new jsSHA("SHA-256", "TEXT");
  shaObj.update(message);
  const hash = shaObj.getHash("HEX");
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_6() {
  const data = "sensitive_information";
  const key = "secret_key";
  // ok: javascript-avoid-weak-hashing-algorithms
  const hmac = crypto.createHmac('sha256', key).update(data).digest('hex');
  return hmac;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_7() {
  const fileContent = "file_content_to_verify";
  // ok: javascript-avoid-weak-hashing-algorithms
  const hash = CryptoJS.SHA256(fileContent).toString();
  console.log(`File hash: ${hash}`);
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_8() {
  const userData = { id: 123, name: "Alice" };
  // ok: javascript-avoid-weak-hashing-algorithms
  const hash = CryptoJS.SHA3(JSON.stringify(userData)).toString();
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_9() {
  const message = "message_to_sign";
  const key = "signing_key";
  // ok: javascript-avoid-weak-hashing-algorithms
  const signature = CryptoJS.HmacSHA256(message, key).toString();
  return { message, signature };
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_10() {
  const data = Buffer.from("binary_data");
  // ok: javascript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('sha512').update(data).digest('base64');
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_11() {
  const bcrypt = require('bcrypt');
  const password = "user_password";
  const saltRounds = 10;
  
  // ok: javascript-avoid-weak-hashing-algorithms
  // Using bcrypt which is designed specifically for passwords
  const hashedPassword = bcrypt.hashSync(password, saltRounds);
  return hashedPassword;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_12() {
  const argon2 = require('argon2');
  
  async function secureHash(password) {
    // ok: javascript-avoid-weak-hashing-algorithms
    // Using Argon2 which is a modern password hashing algorithm
    return await argon2.hash(password);
  }
  
  return secureHash("user_password");
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_13() {
  const { scrypt, randomBytes } = require('crypto');
  const { promisify } = require('util');
  
  async function hashWithScrypt(password) {
    const salt = randomBytes(16).toString('hex');
    // ok: javascript-avoid-weak-hashing-algorithms
    // Using scrypt which is a password-based key derivation function
    const derivedKey = await promisify(scrypt)(password, salt, 64);
    return salt + ':' + derivedKey.toString('hex');
  }
  
  return hashWithScrypt("user_password");
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_14() {
  const data = "data_to_hash";
  let algorithm = 'sha256';
  if (process.env.NODE_ENV === 'production') {
    algorithm = 'sha512'; // Using stronger hash in production
  }
  // ok: javascript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash(algorithm).update(data).digest('hex');
  return hash;
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_15() {
  const { generateKeyPairSync, createSign } = require('crypto');
  
  // Using asymmetric cryptography for signing
  function signData(data) {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });
    
    // ok: javascript-avoid-weak-hashing-algorithms
    const sign = createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'hex');
  }
  
  return signData("data_to_sign");
}
// {/fact}