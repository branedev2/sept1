// File: pseudorandom_number_generators_test.ts
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as express from 'express';

// TRUE POSITIVES (Vulnerable code)

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_1() {
    // Using Math.random() for generating encryption key
    const key = Buffer.from(Math.random().toString());
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipher('aes-256-cbc', key);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_2() {
    // Using Date.now() as a seed for encryption
    const seed = Date.now().toString();
    // ruleid: typescript-pseudorandom-number-generators
    const hash = crypto.createHash('sha256').update(seed).digest('hex');
    return hash;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_3() {
    // Using hardcoded value for IV (Initialization Vector)
    const key = crypto.randomBytes(32);
    const iv = Buffer.from('1234567890123456'); // Hardcoded IV
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_4() {
    // Using Math.random() for password salt
    const password = 'userPassword123';
    const salt = Math.floor(Math.random() * 1000000).toString();
    // ruleid: typescript-pseudorandom-number-generators
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_5() {
    // Using a simple incrementing counter for nonce
    let nonce = 0;
    function getNextNonce() {
        return Buffer.from((nonce++).toString());
    }
    
    const key = crypto.randomBytes(32);
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipheriv('aes-256-gcm', key, getNextNonce());
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_6() {
    // Using Math.random() to generate session ID
    const sessionId = Math.random().toString(36).substring(2, 15);
    // ruleid: typescript-pseudorandom-number-generators
    const hmac = crypto.createHmac('sha256', sessionId).update('data').digest('hex');
    return hmac;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_7() {
    // Using process.pid as part of encryption key
    const pidBasedKey = process.pid.toString() + "secret";
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipher('aes-192-cbc', pidBasedKey);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_8() {
    // Using a custom weak PRNG for key generation
    function weakRandom() {
        return (new Date().getTime() * Math.random()) % 1000000;
    }
    
    const key = Buffer.from(weakRandom().toString());
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16, 0));
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_9() {
    // Using hardcoded encryption key
    const key = "ThisIsAHardcodedEncryptionKey12345";
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipher('aes-256-cbc', key);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_10() {
    // Using JavaScript's random() in a loop to generate a key
    let key = '';
    for (let i = 0; i < 32; i++) {
        key += Math.floor(Math.random() * 10);
    }
    
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipher('aes-256-cbc', key);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_11() {
    // Using timestamp for both key and IV
    const timestamp = new Date().getTime().toString();
    const key = Buffer.from(timestamp.substring(0, 16));
    const iv = Buffer.from(timestamp.substring(0, 16));
    
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_12() {
    // Using Math.random() for generating RSA parameters
    const prime1 = Math.floor(Math.random() * 1000);
    const prime2 = Math.floor(Math.random() * 1000);
    
    // ruleid: typescript-pseudorandom-number-generators
    const modulus = prime1 * prime2;
    const totient = (prime1 - 1) * (prime2 - 1);
    
    return { modulus, totient };
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_13() {
    // Using a simple hash of time for encryption
    const timeHash = crypto.createHash('md5').update(Date.now().toString()).digest('hex');
    
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipher('aes-256-cbc', timeHash);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_14() {
    // Using predictable pattern for IV generation
    const iv = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) {
        iv[i] = i * 2; // Predictable pattern
    }
    
    const key = crypto.randomBytes(32);
    // ruleid: typescript-pseudorandom-number-generators
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
function bad_case_15() {
    // Using Math.random() for JWT secret
    const jwtSecret = Math.random().toString(36).substring(2);
    
    // ruleid: typescript-pseudorandom-number-generators
    const signature = crypto.createHmac('sha256', jwtSecret)
        .update('header.payload')
        .digest('base64');
    
    return `header.payload.${signature}`;
}
// {/fact}

// TRUE NEGATIVES (Secure code)

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_1() {
    // Using crypto.randomBytes for key generation
    // ok: typescript-pseudorandom-number-generators
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_2() {
    // Using crypto.randomBytes for salt generation
    const password = 'userPassword123';
    // ok: typescript-pseudorandom-number-generators
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_3() {
    // Using crypto.randomUUID for session ID
    // ok: typescript-pseudorandom-number-generators
    const sessionId = crypto.randomUUID();
    const hmac = crypto.createHmac('sha256', sessionId).update('data').digest('hex');
    return hmac;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_4() {
    // Using environment variable for encryption key
    const key = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    // ok: typescript-pseudorandom-number-generators
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_5() {
    // Using secure key management system (simulated)
    function getSecureKeyFromVault(keyId: string): Buffer {
        // In a real scenario, this would fetch from a secure vault like AWS KMS, HashiCorp Vault, etc.
        return crypto.randomBytes(32); // Simulated secure key
    }
    
    // ok: typescript-pseudorandom-number-generators
    const key = getSecureKeyFromVault('encryption-key-id');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_6() {
    // Using crypto.randomBytes for nonce in GCM mode
    // ok: typescript-pseudorandom-number-generators
    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12); // 12 bytes is standard for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { encrypted, authTag, nonce };
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_7() {
    // Using crypto.randomBytes for JWT secret
    // ok: typescript-pseudorandom-number-generators
    const jwtSecret = crypto.randomBytes(64).toString('hex');
    const signature = crypto.createHmac('sha256', jwtSecret)
        .update('header.payload')
        .digest('base64');
    
    return `header.payload.${signature}`;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_8() {
    // Using a secure key derivation function with good parameters
    const password = 'userPassword123';
    // ok: typescript-pseudorandom-number-generators
    const salt = crypto.randomBytes(16);
    const iterations = 100000; // High number of iterations for security
    const keyLength = 64;
    const digest = 'sha512';
    
    const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest);
    return derivedKey.toString('hex');
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_9() {
    // Using secure random for both key and IV
    // ok: typescript-pseudorandom-number-generators
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Store IV with ciphertext (it doesn't need to be secret)
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([
        iv,
        cipher.update('sensitive data', 'utf8'),
        cipher.final()
    ]);
    
    return encrypted.toString('hex');
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_10() {
    // Using a hardware security module (HSM) for key operations (simulated)
    function getHSMGeneratedKey(): Buffer {
        // In a real scenario, this would use an HSM
        return crypto.randomBytes(32); // Simulated HSM-generated key
    }
    
    // ok: typescript-pseudorandom-number-generators
    const key = getHSMGeneratedKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_11() {
    // Using secure random for RSA key generation (simplified)
    // ok: typescript-pseudorandom-number-generators
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    return { publicKey, privateKey };
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_12() {
    // Using secure random for elliptic curve cryptography
    // ok: typescript-pseudorandom-number-generators
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    return { publicKey, privateKey };
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_13() {
    // Using secure random for digital signatures
    const message = 'Message to sign';
    
    // ok: typescript-pseudorandom-number-generators
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    const signature = crypto.sign('sha256', Buffer.from(message), privateKey);
    const isVerified = crypto.verify('sha256', Buffer.from(message), publicKey, signature);
    
    return { signature: signature.toString('base64'), isVerified };
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_14() {
    // Using a key rotation strategy with secure random (simulated)
    function getRotatingKey(): Buffer {
        const currentDate = new Date();
        const keyId = `key-${currentDate.getFullYear()}-${currentDate.getMonth() + 1}`;
        
        // In a real scenario, this would fetch from a secure key management system
        // ok: typescript-pseudorandom-number-generators
        return crypto.randomBytes(32); // Simulated rotating key
    }
    
    const key = getRotatingKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = cipher.update('sensitive data', 'utf8', 'hex') + cipher.final('hex');
    
    return encrypted;
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
function good_case_15() {
    // Using secure random for password reset tokens
    function generatePasswordResetToken(): string {
        // ok: typescript-pseudorandom-number-generators
        return crypto.randomBytes(32).toString('hex');
    }
    
    const token = generatePasswordResetToken();
    const expiryTime = Date.now() + 3600000; // 1 hour from now
    
    // In a real app, you would store this token in a database with the expiry time
    return { token, expiryTime };
}
// {/fact}

// Server example to show context
const app = express();
app.use(express.json());

app.post('/encrypt', (req, res) => {
    const data = req.body.data;
    if (!data) {
        return res.status(400).send('No data provided');
    }
    
    try {
        // Using secure encryption
        const key = crypto.randomBytes(32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        const encrypted = Buffer.concat([iv, cipher.update(data, 'utf8'), cipher.final()]);
        
        res.json({ encrypted: encrypted.toString('hex') });
    } catch (error) {
        res.status(500).send('Encryption failed');
    }
});

// Don't actually start the server in this example
// http.createServer(app).listen(3000);