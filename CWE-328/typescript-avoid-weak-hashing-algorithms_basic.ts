// Import necessary libraries
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import * as argon2 from 'argon2';
import * as CryptoJS from 'crypto-js';
import * as forge from 'node-forge';
import * as jssha from 'jssha';

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Using MD5 with Node.js crypto module
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_1(): string {
  const data = "sensitive data to hash";
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('md5').update(data).digest('hex');
  console.log(`MD5 hash: ${hash}`);
  return hash;
}
// {/fact}

// Example 2: Using SHA1 with Node.js crypto module
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_2(): string {
  const password = "user_password";
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('sha1').update(password).digest('hex');
  return hash;
}
// {/fact}

// Example 3: Using RIPEMD160 with Node.js crypto module
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_3(userData: string): string {
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('ripemd160').update(userData).digest('hex');
  return hash;
}
// {/fact}

// Example 4: Using MD5 with CryptoJS
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_4(): string {
  const data = "sensitive information";
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hash = CryptoJS.MD5(data).toString();
  return hash;
}
// {/fact}

// Example 5: Using SHA1 with CryptoJS
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_5(input: string): string {
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hash = CryptoJS.SHA1(input).toString();
  return `Hash: ${hash}`;
}
// {/fact}

// Example 6: Using HMAC-MD5 with Node.js crypto
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_6(): string {
  const key = "secret_key";
  const data = "data to authenticate";
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hmac = crypto.createHmac('md5', key).update(data).digest('hex');
  return hmac;
}
// {/fact}

// Example 7: Using HMAC-SHA1 with Node.js crypto
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_7(message: string): string {
  const secretKey = "my_secret";
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hmac = crypto.createHmac('sha1', secretKey).update(message).digest('base64');
  return hmac;
}
// {/fact}

// Example 8: Using MD5 with node-forge
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_8(): string {
  const data = "sensitive data";
  const md = forge.md.md5.create();
  // ruleid: typescript-avoid-weak-hashing-algorithms
  md.update(data);
  return md.digest().toHex();
}
// {/fact}

// Example 9: Using SHA1 with node-forge
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_9(input: string): string {
  const md = forge.md.sha1.create();
  // ruleid: typescript-avoid-weak-hashing-algorithms
  md.update(input);
  return md.digest().toHex();
}
// {/fact}

// Example 10: Using jsSHA for SHA1
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_10(): string {
  const data = "data to hash";
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const shaObj = new jssha("SHA-1", "TEXT");
  shaObj.update(data);
  return shaObj.getHash("HEX");
}
// {/fact}

// Example 11: Using CryptoJS RIPEMD160
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_11(userData: string): string {
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hash = CryptoJS.RIPEMD160(userData).toString();
  return hash;
}
// {/fact}

// Example 12: Using MD5 in a password verification function
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_12(password: string, storedHash: string): boolean {
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
  return hashedPassword === storedHash;
}
// {/fact}

// Example 13: Using SHA1 in a file integrity check
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_13(fileContent: string): string {
  console.log("Checking file integrity...");
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const fileHash = crypto.createHash('sha1').update(fileContent).digest('hex');
  return fileHash;
}
// {/fact}

// Example 14: Using MD5 with a salt (still insecure)
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_14(password: string): string {
  const salt = "static_salt_value";
  const saltedPassword = password + salt;
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('md5').update(saltedPassword).digest('hex');
  return hash;
}
// {/fact}

// Example 15: Using HMAC-RIPEMD160
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_15(data: string): string {
  const key = "authentication_key";
  // ruleid: typescript-avoid-weak-hashing-algorithms
  const hmac = crypto.createHmac('ripemd160', key).update(data).digest('hex');
  return hmac;
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// Example 1: Using SHA256 with Node.js crypto module
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_1(): string {
  const data = "sensitive data to hash";
  // ok: typescript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('sha256').update(data).digest('hex');
  console.log(`SHA256 hash: ${hash}`);
  return hash;
}
// {/fact}

// Example 2: Using SHA512 with Node.js crypto module
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_2(): string {
  const password = "user_password";
  // ok: typescript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('sha512').update(password).digest('hex');
  return hash;
}
// {/fact}

// Example 3: Using bcrypt for password hashing
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_3(password: string): string {
  const saltRounds = 10;
  // ok: typescript-avoid-weak-hashing-algorithms
  const hash = bcrypt.hashSync(password, saltRounds);
  return hash;
}
// {/fact}

// Example 4: Using SHA3-256 with Node.js crypto
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_4(): string {
  const data = "sensitive information";
  // ok: typescript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('sha3-256').update(data).digest('hex');
  return hash;
}
// {/fact}

// Example 5: Using Argon2 for password hashing
// {fact rule=clear-text-credentials@v1.0 defects=0}
async function good_case_5(password: string): Promise<string> {
  // ok: typescript-avoid-weak-hashing-algorithms
  const hash = await argon2.hash(password);
  return hash;
}
// {/fact}

// Example 6: Using HMAC-SHA256 with Node.js crypto
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_6(): string {
  const key = "secret_key";
  const data = "data to authenticate";
  // ok: typescript-avoid-weak-hashing-algorithms
  const hmac = crypto.createHmac('sha256', key).update(data).digest('hex');
  return hmac;
}
// {/fact}

// Example 7: Using HMAC-SHA512 with Node.js crypto
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_7(message: string): string {
  const secretKey = "my_secret";
  // ok: typescript-avoid-weak-hashing-algorithms
  const hmac = crypto.createHmac('sha512', secretKey).update(message).digest('base64');
  return hmac;
}
// {/fact}

// Example 8: Using SHA256 with node-forge
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_8(): string {
  const data = "sensitive data";
  const md = forge.md.sha256.create();
  // ok: typescript-avoid-weak-hashing-algorithms
  md.update(data);
  return md.digest().toHex();
}
// {/fact}

// Example 9: Using SHA512 with node-forge
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_9(input: string): string {
  const md = forge.md.sha512.create();
  // ok: typescript-avoid-weak-hashing-algorithms
  md.update(input);
  return md.digest().toHex();
}
// {/fact}

// Example 10: Using jsSHA for SHA256
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_10(): string {
  const data = "data to hash";
  // ok: typescript-avoid-weak-hashing-algorithms
  const shaObj = new jssha("SHA-256", "TEXT");
  shaObj.update(data);
  return shaObj.getHash("HEX");
}
// {/fact}

// Example 11: Using CryptoJS SHA256
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_11(userData: string): string {
  // ok: typescript-avoid-weak-hashing-algorithms
  const hash = CryptoJS.SHA256(userData).toString();
  return hash;
}
// {/fact}

// Example 12: Using bcrypt for password verification
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_12(password: string, storedHash: string): boolean {
  // ok: typescript-avoid-weak-hashing-algorithms
  return bcrypt.compareSync(password, storedHash);
}
// {/fact}

// Example 13: Using SHA256 in a file integrity check
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_13(fileContent: string): string {
  console.log("Checking file integrity...");
  // ok: typescript-avoid-weak-hashing-algorithms
  const fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');
  return fileHash;
}
// {/fact}

// Example 14: Using SHA512 with a random salt
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_14(password: string): { hash: string, salt: string } {
// {/fact}

  const salt = crypto.randomBytes(16).toString('hex');
  const saltedPassword = password + salt;
  // ok: typescript-avoid-weak-hashing-algorithms
  const hash = crypto.createHash('sha512').update(saltedPassword).digest('hex');
  return { hash, salt };
}

// Example 15: Using HMAC-SHA3-256
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_15(data: string): string {
  const key = "authentication_key";
  // ok: typescript-avoid-weak-hashing-algorithms
  const hmac = crypto.createHmac('sha3-256', key).update(data).digest('hex');
  return hmac;
}
// {/fact}