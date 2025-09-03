import * as crypto from 'crypto';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Direct use of ECB mode with AES
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
    const key = crypto.randomBytes(32);
    const data = 'Sensitive information to encrypt';
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// Example 2: Using ECB mode with a different key size
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
    const key = crypto.randomBytes(16);
    const sensitiveData = 'Credit card: 4111-1111-1111-1111';
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-128-ecb', key, '');
    let encryptedData = cipher.update(sensitiveData, 'utf8', 'base64');
    encryptedData += cipher.final('base64');
    
    return encryptedData;
}
// {/fact}

// Example 3: Using ECB mode with a variable containing the algorithm name
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
    const key = crypto.randomBytes(32);
    const algorithm = 'aes-256-ecb';
    const message = 'This is a secret message';
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv(algorithm, key, '');
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// Example 4: Using ECB mode in a class method
class EncryptionService {
    private key: Buffer;
    
    constructor() {
        this.key = crypto.randomBytes(32);
    }
    
    encryptData(data: string): string {
        // ruleid: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv('aes-256-ecb', this.key, '');
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    }
}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
    const service = new EncryptionService();
    return service.encryptData('Secret information');
}
// {/fact}

// Example 5: Using ECB mode with string concatenation in algorithm name
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
    const key = crypto.randomBytes(32);
    const mode = 'ecb';
    const algorithm = 'aes-256-' + mode;
    const data = 'Confidential data';
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv(algorithm, key, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// Example 6: Using ECB mode in an async function
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
async function bad_case_6() {
    const key = await Promise.resolve(crypto.randomBytes(32));
    const data = 'Async encrypted data';
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// Example 7: Using ECB mode with key derived from password
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
    const password = 'user-provided-password';
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, salt, 32);
    const data = 'Password-protected data';
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// Example 8: Using ECB mode with template literals
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
    const key = crypto.randomBytes(32);
    const keySize = '256';
    const mode = 'ecb';
    const algorithm = `aes-${keySize}-${mode}`;
    const data = 'Template literal encrypted data';
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv(algorithm, key, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// Example 9: Using ECB mode in a conditional block
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9(useStrongEncryption: boolean) {
    const key = crypto.randomBytes(32);
    const data = 'Conditionally encrypted data';
    
    if (!useStrongEncryption) {
        // ruleid: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    } else {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return { encrypted, iv: iv.toString('hex') };
    }
}
// {/fact}

// Example 10: Using ECB mode with destructuring
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
    const key = crypto.randomBytes(32);
    const data = 'Destructured encryption';
    const { createCipheriv } = crypto;
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = createCipheriv('aes-256-ecb', key, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// Example 11: Using ECB mode in a loop
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
    const key = crypto.randomBytes(32);
    const dataItems = ['item1', 'item2', 'item3'];
    const encryptedItems = [];
    
    for (const item of dataItems) {
        // ruleid: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
        let encrypted = cipher.update(item, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        encryptedItems.push(encrypted);
    }
    
    return encryptedItems;
}
// {/fact}

// Example 12: Using ECB mode with a switch statement
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12(encryptionType: string) {
    const key = crypto.randomBytes(32);
    const data = 'Switch statement encrypted data';
    let cipher;
    
    switch (encryptionType) {
        case 'fast':
            // ruleid: typescript-crypto-compliant-cipher
            cipher = crypto.createCipheriv('aes-256-ecb', key, '');
            break;
        case 'secure':
            const iv = crypto.randomBytes(16);
            cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
            break;
        default:
            throw new Error('Invalid encryption type');
    }
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// Example 13: Using ECB mode with error handling
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
    const key = crypto.randomBytes(32);
    const data = 'Try-catch encrypted data';
    
    try {
        // ruleid: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv('aes-256-ecb', key, '');
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    } catch (error) {
        console.error('Encryption failed:', error);
        return null;
    }
}
// {/fact}

// Example 14: Using ECB mode with a higher-order function
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
    const key = crypto.randomBytes(32);
    const data = 'Higher-order function encrypted data';
    
    const encrypt = (algorithm: string) => {
        // ruleid: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv(algorithm, key, '');
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    };
    
    return encrypt('aes-256-ecb');
}
// {/fact}

// Example 15: Using ECB mode with object destructuring and default parameters
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15({ algorithm = 'aes-256-ecb', data = 'Default parameter data' } = {}) {
// {/fact}

    const key = crypto.randomBytes(32);
    
    // ruleid: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv(algorithm, key, '');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}

// TRUE NEGATIVES (Secure Code Examples)

// Example 1: Using CBC mode with AES
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const data = 'Sensitive information to encrypt';
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return { encrypted, iv: iv.toString('hex') };
}
// {/fact}

// Example 2: Using GCM mode with AES
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const sensitiveData = 'Credit card: 4111-1111-1111-1111';
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encryptedData = cipher.update(sensitiveData, 'utf8', 'base64');
    encryptedData += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    
    return { encryptedData, iv: iv.toString('base64'), authTag: authTag.toString('base64') };
}
// {/fact}

// Example 3: Using CTR mode with AES
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const message = 'This is a secret message';
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return { encrypted, iv: iv.toString('hex') };
}
// {/fact}

// Example 4: Using CBC mode in a class method
class SecureEncryptionService {
    private key: Buffer;
    
    constructor() {
        this.key = crypto.randomBytes(32);
    }
    
    encryptData(data: string): { encrypted: string, iv: string } {
        const iv = crypto.randomBytes(16);
        // ok: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return { encrypted, iv: iv.toString('hex') };
    }
}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
    const service = new SecureEncryptionService();
    return service.encryptData('Secret information');
}
// {/fact}

// Example 5: Using GCM mode with string concatenation in algorithm name
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const mode = 'gcm';
    const algorithm = 'aes-256-' + mode;
    const data = 'Confidential data';
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}
// {/fact}

// Example 6: Using CBC mode in an async function
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
async function good_case_6() {
    const key = await Promise.resolve(crypto.randomBytes(32));
    const iv = await Promise.resolve(crypto.randomBytes(16));
    const data = 'Async encrypted data';
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return { encrypted, iv: iv.toString('hex') };
}
// {/fact}

// Example 7: Using CTR mode with key derived from password
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
    const password = 'user-provided-password';
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, salt, 32);
    const iv = crypto.randomBytes(16);
    const data = 'Password-protected data';
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return { encrypted, iv: iv.toString('hex'), salt: salt.toString('hex') };
}
// {/fact}

// Example 8: Using GCM mode with template literals
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const keySize = '256';
    const mode = 'gcm';
    const algorithm = `aes-${keySize}-${mode}`;
    const data = 'Template literal encrypted data';
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}
// {/fact}

// Example 9: Using CBC mode in a conditional block
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9(useFastEncryption: boolean) {
    const key = crypto.randomBytes(32);
    const data = 'Conditionally encrypted data';
    
    if (useFastEncryption) {
        const iv = crypto.randomBytes(16);
        // ok: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return { encrypted, iv: iv.toString('hex') };
    } else {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
    }
}
// {/fact}

// Example 10: Using CBC mode with destructuring
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const data = 'Destructured encryption';
    const { createCipheriv } = crypto;
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return { encrypted, iv: iv.toString('hex') };
}
// {/fact}

// Example 11: Using CTR mode in a loop
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
    const key = crypto.randomBytes(32);
    const dataItems = ['item1', 'item2', 'item3'];
    const encryptedItems = [];
    
    for (const item of dataItems) {
        const iv = crypto.randomBytes(16);
        // ok: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
        let encrypted = cipher.update(item, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        encryptedItems.push({ encrypted, iv: iv.toString('hex') });
    }
    
    return encryptedItems;
}
// {/fact}

// Example 12: Using GCM mode with a switch statement
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12(encryptionType: string) {
    const key = crypto.randomBytes(32);
    const data = 'Switch statement encrypted data';
    let cipher;
    let iv;
    let result: any = {};
    
    switch (encryptionType) {
        case 'fast':
            iv = crypto.randomBytes(16);
            // ok: typescript-crypto-compliant-cipher
            cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
            result.iv = iv.toString('hex');
            break;
        case 'secure':
            iv = crypto.randomBytes(12);
            cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
            result.iv = iv.toString('hex');
            break;
        default:
            throw new Error('Invalid encryption type');
    }
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    result.encrypted = encrypted;
    
    if (encryptionType === 'secure') {
        result.authTag = cipher.getAuthTag().toString('hex');
    }
    
    return result;
}
// {/fact}

// Example 13: Using CBC mode with error handling
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const data = 'Try-catch encrypted data';
    
    try {
        // ok: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return { encrypted, iv: iv.toString('hex') };
    } catch (error) {
        console.error('Encryption failed:', error);
        return null;
    }
}
// {/fact}

// Example 14: Using CTR mode with a higher-order function
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const data = 'Higher-order function encrypted data';
    
    const encrypt = (algorithm: string) => {
        // ok: typescript-crypto-compliant-cipher
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return { encrypted, iv: iv.toString('hex') };
    };
    
    return encrypt('aes-256-ctr');
}
// {/fact}

// Example 15: Using GCM mode with object destructuring and default parameters
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15({ algorithm = 'aes-256-gcm', data = 'Default parameter data' } = {}) {
// {/fact}

    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    
    // ok: typescript-crypto-compliant-cipher
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}