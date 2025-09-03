// Import necessary crypto libraries
const crypto = require('crypto');
const { publicEncrypt, privateDecrypt } = require('crypto');
const CryptoJS = require('crypto-js');
const NodeRSA = require('node-rsa');
const openpgp = require('openpgp');
const sjcl = require('sjcl');
const forge = require('node-forge');
const sodium = require('libsodium-wrappers');
const webcrypto = require('crypto').webcrypto;

// Custom encryption library that provides both decrypt+encrypt and reEncrypt APIs
class SecureCrypto {
  constructor(key) {
    this.key = key;
  }

  encrypt(data, targetKey) {
    // Encrypt implementation
    return crypto.publicEncrypt(targetKey, Buffer.from(data));
  }

  decrypt(data) {
    // Decrypt implementation
    return crypto.privateDecrypt(this.key, data).toString();
  }

  reEncrypt(data, sourceKey, targetKey) {
    // Direct reEncryption without intermediate plaintext
    // Implementation would use techniques like key wrapping
    return Buffer.from("reencrypted data");
  }
}

// Create instances for testing
const secureCrypto = new SecureCrypto("private-key");
const sourceKey = "source-key";
const targetKey = "target-key";

// TRUE POSITIVES (Vulnerable/Insecure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const encryptedData = fetchEncryptedData();
  
  // Decrypt data with one key and immediately encrypt with another
  const decryptedData = secureCrypto.decrypt(encryptedData);
  // ruleid: javascript-reencrypt
  const reEncryptedData = secureCrypto.encrypt(decryptedData, targetKey);
  
  return reEncryptedData;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const encryptedMessage = getEncryptedMessage();
  
  // Using Node.js crypto module to decrypt and then encrypt
  const privateKey = getPrivateKey();
  const publicKey = getPublicKey();
  
  const decrypted = privateDecrypt(privateKey, encryptedMessage);
  // ruleid: javascript-reencrypt
  const encrypted = publicEncrypt(publicKey, decrypted);
  
  sendEncryptedData(encrypted);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const encryptedData = fetchFromDatabase();
  const key1 = getUserKey();
  const key2 = getRecipientKey();
  
  // Using CryptoJS to decrypt and then encrypt
  const bytes = CryptoJS.AES.decrypt(encryptedData, key1);
  const decrypted = bytes.toString(CryptoJS.enc.Utf8);
  
  // ruleid: javascript-reencrypt
  const reEncrypted = CryptoJS.AES.encrypt(decrypted, key2);
  
  storeEncryptedData(reEncrypted);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  // Using Node-RSA for key conversion
  const privateKeyData = getPrivateKeyData();
  const publicKeyData = getPublicKeyData();
  
  const privateKey = new NodeRSA(privateKeyData);
  const publicKey = new NodeRSA(publicKeyData);
  
  const encryptedBuffer = getEncryptedBuffer();
  const decrypted = privateKey.decrypt(encryptedBuffer);
  
  // ruleid: javascript-reencrypt
  const reEncrypted = publicKey.encrypt(decrypted);
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
async function bad_case_5() {
  // Using OpenPGP.js
  const encryptedMessage = await fetchEncryptedPGPMessage();
  const privateKeyArmored = getPrivateKeyArmored();
  const publicKeyArmored = getPublicKeyArmored();
  
  const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
  const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  
  const message = await openpgp.readMessage({ armoredMessage: encryptedMessage });
  const { data: decrypted } = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey
  });
  
  // ruleid: javascript-reencrypt
  const { data: encrypted } = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: decrypted }),
    encryptionKeys: publicKey
  });
  
  return encrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  // Using Stanford Javascript Crypto Library (SJCL)
  const encryptedData = getEncryptedData();
  const key1 = sjcl.codec.utf8String.toBits("password1");
  const key2 = sjcl.codec.utf8String.toBits("password2");
  
  const decrypted = sjcl.decrypt(key1, encryptedData);
  
  // ruleid: javascript-reencrypt
  const reEncrypted = sjcl.encrypt(key2, decrypted);
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  // Using Node-Forge
  const encryptedData = getEncryptedData();
  const key1 = getKey1();
  const key2 = getKey2();
  const iv1 = getIV1();
  const iv2 = getIV2();
  
  // Decrypt
  const decipher = forge.cipher.createDecipher('AES-CBC', key1);
  decipher.start({iv: iv1});
  decipher.update(forge.util.createBuffer(encryptedData));
  decipher.finish();
  const decrypted = decipher.output.getBytes();
  
  // ruleid: javascript-reencrypt
  // Re-encrypt
  const cipher = forge.cipher.createCipher('AES-CBC', key2);
  cipher.start({iv: iv2});
  cipher.update(forge.util.createBuffer(decrypted));
  cipher.finish();
  const reEncrypted = cipher.output.getBytes();
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
async function bad_case_8() {
  // Using libsodium
  await sodium.ready;
  
  const encryptedMessage = getEncryptedMessage();
  const nonce1 = getNonce1();
  const nonce2 = getNonce2();
  const key1 = getKey1();
  const key2 = getKey2();
  
  const decrypted = sodium.crypto_secretbox_open_easy(encryptedMessage, nonce1, key1);
  
  // ruleid: javascript-reencrypt
  const reEncrypted = sodium.crypto_secretbox_easy(decrypted, nonce2, key2);
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
async function bad_case_9() {
  // Using Web Crypto API
  const encryptedData = await getEncryptedData();
  const key1 = await getDecryptionKey();
  const key2 = await getEncryptionKey();
  const iv = getIV();
  
  const decrypted = await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key1,
    encryptedData
  );
  
  // ruleid: javascript-reencrypt
  const reEncrypted = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key2,
    decrypted
  );
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  // Using a custom encryption class
  const encryptedData = getEncryptedData();
  const encryptor = new CustomEncryptor();
  
  const decrypted = encryptor.decrypt(encryptedData, "key1");
  
  // ruleid: javascript-reencrypt
  const reEncrypted = encryptor.encrypt(decrypted, "key2");
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  // Using crypto module with different algorithms
  const encryptedData = getEncryptedData();
  const key1 = getKey1();
  const key2 = getKey2();
  const iv1 = getIV1();
  const iv2 = getIV2();
  
  const decipher = crypto.createDecipheriv('aes-256-cbc', key1, iv1);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  // ruleid: javascript-reencrypt
  const cipher = crypto.createCipheriv('aes-256-gcm', key2, iv2);
  let reEncrypted = cipher.update(decrypted, 'utf8', 'hex');
  reEncrypted += cipher.final('hex');
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  // Using crypto with callbacks
  const encryptedData = getEncryptedData();
  const key1 = getKey1();
  const key2 = getKey2();
  
  crypto.privateDecrypt(key1, encryptedData, (err, decrypted) => {
    if (err) throw err;
    
    // ruleid: javascript-reencrypt
    crypto.publicEncrypt(key2, decrypted, (err, reEncrypted) => {
      if (err) throw err;
      sendData(reEncrypted);
    });
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  // Using a hybrid approach with multiple crypto libraries
  const encryptedData = getEncryptedData();
  
  // Decrypt with Node's crypto
  const decrypted = crypto.privateDecrypt(
    {
      key: getPrivateKey(),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    },
    encryptedData
  );
  
  // ruleid: javascript-reencrypt
  // Re-encrypt with CryptoJS
  const reEncrypted = CryptoJS.AES.encrypt(
    decrypted.toString(),
    CryptoJS.enc.Hex.parse(getSymmetricKey()),
    { iv: CryptoJS.enc.Hex.parse(getIV()) }
  );
  
  return reEncrypted.toString();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  // Using crypto with streams
  const encryptedFile = getEncryptedFile();
  const key1 = getKey1();
  const key2 = getKey2();
  const iv1 = getIV1();
  const iv2 = getIV2();
  
  const decryptStream = crypto.createDecipheriv('aes-256-cbc', key1, iv1);
  
  let decrypted = '';
  decryptStream.on('data', (chunk) => {
    decrypted += chunk.toString();
  });
  
  decryptStream.on('end', () => {
    // ruleid: javascript-reencrypt
    const encryptStream = crypto.createCipheriv('aes-256-cbc', key2, iv2);
    let reEncrypted = encryptStream.update(decrypted, 'utf8', 'hex');
    reEncrypted += encryptStream.final('hex');
    
    saveToFile(reEncrypted);
  });
  
  encryptedFile.pipe(decryptStream);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  // Using async/await with promises
  async function processData() {
    const encryptedData = await fetchEncryptedData();
    const key1 = await getDecryptionKey();
    const key2 = await getEncryptionKey();
    
    return new Promise((resolve, reject) => {
      crypto.privateDecrypt(key1, encryptedData, (err, decrypted) => {
        if (err) return reject(err);
        
        // ruleid: javascript-reencrypt
        crypto.publicEncrypt(key2, decrypted, (err, reEncrypted) => {
          if (err) return reject(err);
          resolve(reEncrypted);
        });
      });
    });
  }
  
  return processData();
}
// {/fact}

// TRUE NEGATIVES (Safe/Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const encryptedData = fetchEncryptedData();
  
  // Using the reEncrypt API directly
  // ok: javascript-reencrypt
  const reEncryptedData = secureCrypto.reEncrypt(encryptedData, sourceKey, targetKey);
  
  return reEncryptedData;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const encryptedMessage = getEncryptedMessage();
  
  // Using a secure key conversion function that doesn't expose the plaintext
  // ok: javascript-reencrypt
  const convertedMessage = crypto.convertEncryptionKey(encryptedMessage, sourceKey, targetKey);
  
  sendEncryptedData(convertedMessage);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const encryptedData = fetchFromDatabase();
  const key1 = getUserKey();
  const key2 = getRecipientKey();
  
  // Using a secure reEncrypt function from a library
  // ok: javascript-reencrypt
  const reEncrypted = CryptoJS.AES.reEncrypt(encryptedData, key1, key2);
  
  storeEncryptedData(reEncrypted);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  // Using Node-RSA's key conversion functionality
  const privateKeyData = getPrivateKeyData();
  const publicKeyData = getPublicKeyData();
  
  const privateKey = new NodeRSA(privateKeyData);
  const publicKey = new NodeRSA(publicKeyData);
  
  const encryptedBuffer = getEncryptedBuffer();
  
  // ok: javascript-reencrypt
  const reEncrypted = privateKey.reEncrypt(encryptedBuffer, publicKey);
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
async function good_case_5() {
  // Using OpenPGP.js with direct key conversion
  const encryptedMessage = await fetchEncryptedPGPMessage();
  const privateKeyArmored = getPrivateKeyArmored();
  const publicKeyArmored = getPublicKeyArmored();
  
  const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
  const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  
  const message = await openpgp.readMessage({ armoredMessage: encryptedMessage });
  
  // ok: javascript-reencrypt
  const reEncrypted = await openpgp.reEncrypt({
    message,
    decryptionKeys: privateKey,
    encryptionKeys: publicKey
  });
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  // Using a secure envelope approach
  const encryptedData = getEncryptedData();
  const sourceKey = getSourceKey();
  const targetKey = getTargetKey();
  
  // ok: javascript-reencrypt
  const reEncrypted = crypto.keyTransfer(encryptedData, {
    from: sourceKey,
    to: targetKey
  });
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  // Using Node-Forge with secure key wrapping
  const encryptedData = getEncryptedData();
  const key1 = getKey1();
  const key2 = getKey2();
  
  // ok: javascript-reencrypt
  const reEncrypted = forge.pki.rsa.convertEncryption(encryptedData, key1, key2);
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
async function good_case_8() {
  // Using libsodium with key conversion
  await sodium.ready;
  
  const encryptedMessage = getEncryptedMessage();
  const key1 = getKey1();
  const key2 = getKey2();
  
  // ok: javascript-reencrypt
  const reEncrypted = sodium.crypto_box_seal_open_then_seal(
    encryptedMessage,
    key1,
    key2
  );
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
async function good_case_9() {
  // Using Web Crypto API with key wrapping
  const encryptedData = await getEncryptedData();
  const wrappingKey = await getWrappingKey();
  const unwrappingKey = await getUnwrappingKey();
  
  // ok: javascript-reencrypt
  const reEncrypted = await webcrypto.subtle.rewrapKey(
    encryptedData,
    unwrappingKey,
    wrappingKey,
    { name: "AES-KW" }
  );
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  // Using a custom encryption class with reEncrypt method
  const encryptedData = getEncryptedData();
  const encryptor = new CustomEncryptor();
  
  // ok: javascript-reencrypt
  const reEncrypted = encryptor.reEncrypt(encryptedData, "key1", "key2");
  
  return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  // Encrypting fresh data (not re-encrypting)
  const plainData = getUserInput();
  const key = getEncryptionKey();
  const iv = getIV();
  
  // ok: javascript-reencrypt
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plainData, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  // Only decrypting data, not re-encrypting
  const encryptedData = getEncryptedData();
  const key = getDecryptionKey();
  const iv = getIV();
  
  // ok: javascript-reencrypt
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  // Using a secure key exchange protocol
  const encryptedData = getEncryptedData();
  const senderKey = getSenderKey();
  const recipientKey = getRecipientKey();
  
  // ok: javascript-reencrypt
  const secureTransfer = crypto.secureKeyExchange(encryptedData, {
    senderKey,
    recipientKey,
    algorithm: 'ECDH'
  });
  
  return secureTransfer;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  // Using envelope encryption pattern correctly
  const dataKey = generateDataKey();
  const masterKey = getMasterKey();
  
  // Encrypt the data with the data key
  const data = getUserData();
  const encryptedData = encryptWithKey(data, dataKey);
  
  // Encrypt the data key with the master key
  // ok: javascript-reencrypt
  const encryptedDataKey = encryptKey(dataKey, masterKey);
  
  return {
    encryptedData,
    encryptedDataKey
  };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  // Processing data without exposing plaintext
  const encryptedData = getEncryptedData();
  const processingKey = getProcessingKey();
  
  // ok: javascript-reencrypt
  const processedData = crypto.processEncrypted(encryptedData, processingKey, {
    operation: 'transform',
    preserveConfidentiality: true
  });
  
  return processedData;
}
// {/fact}

// Helper functions (not part of the examples)
function fetchEncryptedData() { return Buffer.from("encrypted data"); }
function getEncryptedMessage() { return Buffer.from("encrypted message"); }
function getPrivateKey() { return "private-key"; }
function getPublicKey() { return "public-key"; }
function fetchFromDatabase() { return "encrypted-data-from-db"; }
function getUserKey() { return "user-key"; }
function getRecipientKey() { return "recipient-key"; }
function storeEncryptedData(data) { /* Store data */ }
function getPrivateKeyData() { return "private-key-data"; }
function getPublicKeyData() { return "public-key-data"; }
function getEncryptedBuffer() { return Buffer.from("encrypted buffer"); }
function fetchEncryptedPGPMessage() { return "-----BEGIN PGP MESSAGE-----\nVersion: OpenPGP.js v4.10.10\nComment: https://openpgpjs.org\n\nwcBMA3QfMlUUg7L9AQf/Test\n-----END PGP MESSAGE-----"; }
function getPrivateKeyArmored() { return "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: OpenPGP.js v4.10.10\nComment: https://openpgpjs.org\n\nxcLYBF5FmtkBCADi\n-----END PGP PRIVATE KEY BLOCK-----"; }
function getPublicKeyArmored() { return "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP.js v4.10.10\nComment: https://openpgpjs.org\n\nxjMEXkWa2RYJKwYBBAHaRw8BAQdA\n-----END PGP PUBLIC KEY BLOCK-----"; }
function sendData(data) { /* Send data */ }
function getEncryptedData() { return "encrypted-data"; }
function getKey1() { return Buffer.from("key1"); }
function getKey2() { return Buffer.from("key2"); }
function getIV1() { return Buffer.from("iv1"); }
function getIV2() { return Buffer.from("iv2"); }
function getEncryptedFile() { return { pipe: (stream) => {} }; }
function saveToFile(data) { /* Save to file */ }
function getDecryptionKey() { return "decryption-key"; }
function getEncryptionKey() { return "encryption-key"; }
function getIV() { return Buffer.from("iv"); }
function getSourceKey() { return "source-key"; }
function getTargetKey() { return "target-key"; }
function getSymmetricKey() { return "symmetric-key"; }
function getWrappingKey() { return "wrapping-key"; }
function getUnwrappingKey() { return "unwrapping-key"; }
function getUserInput() { return "user input"; }
function getSenderKey() { return "sender-key"; }
function generateDataKey() { return "data-key"; }
function getMasterKey() { return "master-key"; }
function getUserData() { return "user-data"; }
function encryptWithKey(data, key) { return "encrypted-with-key"; }
function encryptKey(dataKey, masterKey) { return "encrypted-key"; }
function getProcessingKey() { return "processing-key"; }

class CustomEncryptor {
  encrypt(data, key) { return "encrypted"; }
  decrypt(data, key) { return "decrypted"; }
  reEncrypt(data, sourceKey, targetKey) { return "reencrypted"; }
}