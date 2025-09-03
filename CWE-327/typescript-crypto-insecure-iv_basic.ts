import * as crypto from 'crypto';
import { promisify } from 'util';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

// TRUE POSITIVES (Vulnerable Code)

// Bad Case 1: Using a hardcoded IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from('1234567890123456'); // Hardcoded IV
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('sensitive data'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 2: Using a zero-filled IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.alloc(16, 0); // Zero-filled IV
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('secret message'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 3: Using a static IV from a constant
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const STATIC_IV = '0123456789abcdef';
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(STATIC_IV);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('confidential data'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 4: Reusing the same IV for multiple encryptions
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from('abcdefghijklmnop');
    
    // First encryption
    const cipher1 = crypto.createCipheriv(algorithm, key, iv);
    const encrypted1 = Buffer.concat([cipher1.update('message 1'), cipher1.final()]);
    
    // Second encryption with the same IV
    const cipher2 = crypto.createCipheriv(algorithm, key, iv);
    const encrypted2 = Buffer.concat([cipher2.update('message 2'), cipher2.final()]);
    
    return { encrypted1, encrypted2 };
}
// {/fact}

// Bad Case 5: Using predictable IV from timestamp
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const timestamp = new Date().getTime().toString();
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(timestamp.substring(0, 16).padEnd(16, '0'));
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('sensitive info'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 6: Using an IV derived from the key
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(key.slice(0, 16)); // Deriving IV from the key
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('private data'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 7: Using a counter as IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    let counter = 1;
    
    function encryptData(data: string) {
        // ruleid: typescript-crypto-insecure-iv
        const ivStr = counter.toString().padStart(16, '0');
        const iv = Buffer.from(ivStr);
        counter++;
        
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }
    
    const encrypted1 = encryptData('message 1');
    const encrypted2 = encryptData('message 2');
    
    return { encrypted1, encrypted2 };
}
// {/fact}

// Bad Case 8: Using a fixed string with concatenation as IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const userId = "user123";
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(("FIXED_PREFIX_" + userId).substring(0, 16));
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('user data'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 9: Using an environment variable as IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(process.env.STATIC_IV || '0000000000000000');
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('environment data'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 10: Using a configuration value as IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const config = {
        iv: 'configuredIvValue16'
    };
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(config.iv);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('config data'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 11: Using a database value as IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // Simulating a database fetch
    const dbRecord = { iv: 'databaseStoredIv16' };
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(dbRecord.iv);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('database record'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 12: Using a hash of fixed data as IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const fixedData = 'always-the-same-data';
    // ruleid: typescript-crypto-insecure-iv
    const hash = crypto.createHash('md5').update(fixedData).digest();
    const iv = hash.slice(0, 16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('hashed fixed data'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 13: Using a predictable pattern for IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const date = new Date();
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(`${date.getFullYear()}${(date.getMonth() + 1).toString().padStart(2, '0')}${date.getDate().toString().padStart(2, '0')}0000000`);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('date-based data'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 14: Using user input as IV
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // Simulating user input
    const userInput = "user-provided-iv";
    // ruleid: typescript-crypto-insecure-iv
    const iv = Buffer.from(userInput.padEnd(16, '0').substring(0, 16));
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('user controlled'), cipher.final()]);
    
    return encrypted;
}
// {/fact}

// Bad Case 15: Using a static IV in a class
class EncryptionService {
    private algorithm: string;
    private key: Buffer;
    private iv: Buffer;
    
    constructor() {
        this.algorithm = 'aes-256-cbc';
        this.key = crypto.randomBytes(32);
        // ruleid: typescript-crypto-insecure-iv
        this.iv = Buffer.from('staticClassIvValue');
    }
    
    encrypt(data: string): Buffer {
        const cipher = crypto.createCipheriv(this.algorithm, this.key, this.iv);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }
}

// TRUE NEGATIVES (Secure Code)

// Good Case 1: Using a random IV for each encryption
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // ok: typescript-crypto-insecure-iv
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('sensitive data'), cipher.final()]);
    
    return { encrypted, iv }; // Return IV with ciphertext for decryption
}
// {/fact}

// Good Case 2: Using crypto.randomFillSync for IV
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const iv = Buffer.alloc(16);
    // ok: typescript-crypto-insecure-iv
    crypto.randomFillSync(iv);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('secret message'), cipher.final()]);
    
    return { encrypted, iv };
}
// {/fact}

// Good Case 3: Using async randomBytes for IV
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
async function good_case_3() {
    const algorithm = 'aes-256-cbc';
    const key = await promisify(crypto.randomBytes)(32);
    // ok: typescript-crypto-insecure-iv
    const iv = await promisify(crypto.randomBytes)(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('confidential data'), cipher.final()]);
    
    return { encrypted, iv };
}
// {/fact}

// Good Case 4: Using a new random IV for each encryption
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    
    function encryptData(data: string) {
        // ok: typescript-crypto-insecure-iv
        const iv = crypto.randomBytes(16);
        
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        
        return { encrypted, iv };
    }
    
    const result1 = encryptData('message 1');
    const result2 = encryptData('message 2');
    
    return { result1, result2 };
}
// {/fact}

// Good Case 5: Using a secure random IV with GCM mode
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
    const algorithm = 'aes-256-gcm';
    const key = crypto.randomBytes(32);
    // ok: typescript-crypto-insecure-iv
    const iv = crypto.randomBytes(12); // GCM typically uses 12 bytes
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('sensitive info'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return { encrypted, iv, authTag };
}
// {/fact}

// Good Case 6: Using randomBytes imported directly
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
    const algorithm = 'aes-256-cbc';
    const key = randomBytes(32);
    // ok: typescript-crypto-insecure-iv
    const iv = randomBytes(16);
    
    const cipher = createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('private data'), cipher.final()]);
    
    return { encrypted, iv };
}
// {/fact}

// Good Case 7: Using a secure random IV in a class with method
class SecureEncryptionService {
    private algorithm: string;
    private key: Buffer;
    
    constructor() {
        this.algorithm = 'aes-256-cbc';
        this.key = crypto.randomBytes(32);
    }
    
    encrypt(data: string): { encrypted: Buffer, iv: Buffer } {
        // ok: typescript-crypto-insecure-iv
        const iv = crypto.randomBytes(16);
        
        const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        
        return { encrypted, iv };
    }
}

// Good Case 8: Using a secure random IV with try-catch
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    
    try {
        // ok: typescript-crypto-insecure-iv
        const iv = crypto.randomBytes(16);
        
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        const encrypted = Buffer.concat([cipher.update('error handled data'), cipher.final()]);
        
        return { encrypted, iv };
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt data');
    }
}
// {/fact}

// Good Case 9: Using a secure random IV with a wrapper function
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    
    function generateSecureIV(size: number = 16): Buffer {
        // ok: typescript-crypto-insecure-iv
        return crypto.randomBytes(size);
    }
    
    const iv = generateSecureIV();
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('wrapped function data'), cipher.final()]);
    
    return { encrypted, iv };
}
// {/fact}

// Good Case 10: Using a secure random IV with async/await
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
async function good_case_10() {
    const algorithm = 'aes-256-cbc';
    
    async function generateKeyAndIV() {
        const key = await promisify(crypto.randomBytes)(32);
        // ok: typescript-crypto-insecure-iv
        const iv = await promisify(crypto.randomBytes)(16);
        return { key, iv };
    }
    
    const { key, iv } = await generateKeyAndIV();
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update('async data'), cipher.final()]);
    
    return { encrypted, iv };
}
// {/fact}

// Good Case 11: Using a secure random IV with a different crypto library wrapper
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
    // Simulating a wrapper around the crypto library
    class CryptoWrapper {
        static generateIV(size: number = 16): Buffer {
            // ok: typescript-crypto-insecure-iv
            return crypto.randomBytes(size);
        }
        
        static encrypt(data: string, algorithm: string, key: Buffer): { encrypted: Buffer, iv: Buffer } {
            const iv = this.generateIV();
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
            return { encrypted, iv };
        }
    }
    
    const key = crypto.randomBytes(32);
    const result = CryptoWrapper.encrypt('wrapper library data', 'aes-256-cbc', key);
    
    return result;
}
// {/fact}

// Good Case 12: Using a secure random IV with conditional logic
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12(useGCM: boolean = false) {
    const algorithm = useGCM ? 'aes-256-gcm' : 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    
    // ok: typescript-crypto-insecure-iv
    const iv = crypto.randomBytes(useGCM ? 12 : 16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = Buffer.concat([cipher.update('conditional data'), cipher.final()]);
    
    if (useGCM) {
        const authTag = cipher.getAuthTag();
        return { encrypted, iv, authTag };
    }
    
    return { encrypted, iv };
}
// {/fact}

// Good Case 13: Using a secure random IV with a factory pattern
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
    interface EncryptionResult {
        encrypted: Buffer;
        iv: Buffer;
        authTag?: Buffer;
    }
    
    class EncryptionFactory {
        static createAESEncryptor(mode: 'cbc' | 'gcm' = 'cbc') {
            const algorithm = `aes-256-${mode}`;
            const key = crypto.randomBytes(32);
            
            return {
                encrypt(data: string): EncryptionResult {
                    // ok: typescript-crypto-insecure-iv
                    const iv = crypto.randomBytes(mode === 'gcm' ? 12 : 16);
                    
                    const cipher = crypto.createCipheriv(algorithm, key, iv);
                    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
                    
                    if (mode === 'gcm') {
                        return { encrypted, iv, authTag: cipher.getAuthTag() };
                    }
                    
                    return { encrypted, iv };
                }
            };
        }
    }
    
    const encryptor = EncryptionFactory.createAESEncryptor('cbc');
    return encryptor.encrypt('factory pattern data');
}
// {/fact}

// Good Case 14: Using a secure random IV with promise-based approach
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    
    return new Promise<{ encrypted: Buffer, iv: Buffer }>((resolve, reject) => {
        try {
            // ok: typescript-crypto-insecure-iv
            crypto.randomBytes(16, (err, iv) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                const cipher = crypto.createCipheriv(algorithm, key, iv);
                const encrypted = Buffer.concat([cipher.update('promise data'), cipher.final()]);
                
                resolve({ encrypted, iv });
            });
        } catch (error) {
            reject(error);
        }
    });
}
// {/fact}

// Good Case 15: Using a secure random IV with TypeScript generics
function good_case_15<T extends string | Buffer>(data: T) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    // ok: typescript-crypto-insecure-iv
    const iv = crypto.randomBytes(16);
    
    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data as string);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
    
    return { encrypted, iv };
}