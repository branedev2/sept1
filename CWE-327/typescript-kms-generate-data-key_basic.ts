import { KMS } from 'aws-sdk';
import { GenerateDataKeyRequest, GenerateDataKeyResponse } from 'aws-sdk/clients/kms';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { SecretsManager } from 'aws-sdk';
import { SSM } from 'aws-sdk';

// BAD CASES - Vulnerable code that should be detected

// Using KMS generateDataKey without specifying encryption context
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
    const kms = new KMS({ region: 'us-west-2' });
    
    const params: GenerateDataKeyRequest = {
        KeyId: 'alias/my-key',
        NumberOfBytes: 64
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params, (err, data) => {
        if (err) {
            console.error('Error generating data key:', err);
            return;
        }
        
        // Use the data key for encryption
        const plaintextKey = data.Plaintext;
        const encryptedData = encryptSensitiveData(plaintextKey, 'sensitive data');
    });
}
// {/fact}

// Using KMS generateDataKey with weak key spec
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
    const kms = new KMS();
    
    const params = {
        KeyId: 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
        KeySpec: 'AES_128' // Weak key spec
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            const plaintextKey = data.Plaintext;
            // Use plaintext key for encryption
            const cipher = crypto.createCipheriv('aes-128-cbc', plaintextKey, Buffer.alloc(16, 0));
            const encrypted = Buffer.concat([
                cipher.update('sensitive data', 'utf8'),
                cipher.final()
            ]);
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// Using KMS generateDataKey without proper error handling
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
    const kms = new KMS({ region: 'us-east-1' });
    
    const params = {
        KeyId: 'alias/test-key',
        NumberOfBytes: 32
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params, (err, data) => {
        // No error handling
        const plaintextKey = data.Plaintext;
        const cipher = crypto.createCipheriv('aes-256-cbc', plaintextKey, crypto.randomBytes(16));
        const encrypted = Buffer.concat([cipher.update('secret data', 'utf8'), cipher.final()]);
        fs.writeFileSync('encrypted.dat', encrypted);
    });
}
// {/fact}

// Using KMS generateDataKey and storing plaintext key insecurely
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
    const kms = new KMS();
    
    const params = {
        KeyId: 'alias/my-encryption-key',
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            // Storing plaintext key insecurely
            fs.writeFileSync('data-key.bin', data.Plaintext);
            console.log('Data key saved to file');
        })
        .catch(err => console.error('Error generating data key:', err));
}
// {/fact}

// Using KMS generateDataKey with hardcoded KeyId
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
    const kms = new KMS({ region: 'eu-west-1' });
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey({
        KeyId: 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234-ab12-cd34-ef56-abcdef123456', // Hardcoded KeyId
        KeySpec: 'AES_256'
    }).promise()
        .then(data => {
            const encryptedKey = data.CiphertextBlob;
            const plaintextKey = data.Plaintext;
            // Use plaintext key
            encryptFile(plaintextKey, 'secret.txt');
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// Using KMS generateDataKey without proper key rotation strategy
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
    const kms = new KMS();
    let cachedKey: Buffer | null = null;
    
    function getOrGenerateKey() {
        if (cachedKey) {
            // Reusing the same key indefinitely without rotation
            return Promise.resolve(cachedKey);
        }
        
        const params = {
            KeyId: 'alias/application-key',
            KeySpec: 'AES_256'
        };
        
        // ruleid: typescript-kms-generate-data-key
        return kms.generateDataKey(params).promise()
            .then(data => {
                cachedKey = data.Plaintext;
                return cachedKey;
            });
    }
    
    getOrGenerateKey()
        .then(key => {
            // Use key for encryption
            const encrypted = encryptData(key, 'sensitive information');
            console.log('Data encrypted');
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// Using KMS generateDataKey with insufficient key length
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
    const kms = new KMS({ region: 'ap-northeast-1' });
    
    const params = {
        KeyId: 'alias/weak-key',
        NumberOfBytes: 16 // Insufficient key length for high-security applications
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            const plaintextKey = data.Plaintext;
            // Use the key for encryption
            const cipher = crypto.createCipheriv('aes-128-cbc', plaintextKey, crypto.randomBytes(16));
            const encrypted = Buffer.concat([cipher.update('confidential data', 'utf8'), cipher.final()]);
            return encrypted;
        })
        .catch(err => console.error('Error generating key:', err));
}
// {/fact}

// Using KMS generateDataKey and exposing plaintext key in logs
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
    const kms = new KMS();
    
    const params = {
        KeyId: 'alias/logging-key',
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params, (err, data) => {
        if (err) {
            console.error('Error generating key:', err);
            return;
        }
        
        // Logging plaintext key (very bad practice)
        console.log('Generated key:', data.Plaintext.toString('hex'));
        
        // Use the key
        const encryptedData = encryptWithKey(data.Plaintext, 'sensitive data');
        saveEncryptedData(encryptedData, data.CiphertextBlob);
    });
}
// {/fact}

// Using KMS generateDataKey without proper access controls
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
    const kms = new KMS({ region: 'us-west-1' });
    
    const params = {
        KeyId: 'alias/unrestricted-key', // Key without proper access restrictions
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            // Store the encrypted key but keep using plaintext
            storeKeyForLaterUse(data.CiphertextBlob);
            
            // Use plaintext key directly
            const plaintextKey = data.Plaintext;
            return encryptUserData(plaintextKey, getUserData());
        })
        .catch(err => console.error('Failed to generate key:', err));
}
// {/fact}

// Using KMS generateDataKey with improper key usage
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
    const kms = new KMS();
    
    const params = {
        KeyId: 'alias/multi-purpose-key',
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            const key = data.Plaintext;
            
            // Using same key for multiple purposes (encryption, HMAC, etc.)
            const encryptedData = encryptData(key, 'secret message');
            const hmac = crypto.createHmac('sha256', key).update('message to authenticate').digest('hex');
            const derivedKey = crypto.pbkdf2Sync(key, 'salt', 1000, 32, 'sha256');
            
            return { encryptedData, hmac, derivedKey };
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// Using KMS generateDataKey without proper key management
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
    const kms = new KMS({ region: 'eu-central-1' });
    
    const params = {
        KeyId: 'alias/temp-key',
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            const plaintextKey = data.Plaintext;
            
            // Using key without proper lifecycle management
            globalKeyStore.setKey('application-key', plaintextKey); // Storing in global variable
            
            return encryptSensitiveRecords(plaintextKey);
        })
        .catch(err => console.error('Failed to generate key:', err));
}
// {/fact}

// Using KMS generateDataKey with weak cipher
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
    const kms = new KMS();
    
    const params = {
        KeyId: 'alias/encryption-key',
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params, (err, data) => {
        if (err) {
            console.error('Error:', err);
            return;
        }
        
        const key = data.Plaintext;
        
        // Using key with weak cipher mode (ECB)
        const cipher = crypto.createCipheriv('aes-256-ecb', key, ''); // ECB mode is vulnerable
        const encrypted = Buffer.concat([cipher.update('sensitive data', 'utf8'), cipher.final()]);
        
        storeEncryptedData(encrypted, data.CiphertextBlob);
    });
}
// {/fact}

// Using KMS generateDataKey without proper key destruction
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
    const kms = new KMS({ region: 'ap-southeast-2' });
    
    const params = {
        KeyId: 'alias/one-time-key',
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            const plaintextKey = data.Plaintext;
            
            // Use the key
            const encryptedData = encryptWithKey(plaintextKey, 'confidential information');
            
            // Key not properly destroyed after use
            // Missing code to zero out the buffer
            
            return { encryptedData, encryptedKey: data.CiphertextBlob };
        })
        .catch(err => console.error('Error generating key:', err));
}
// {/fact}

// Using KMS generateDataKey with improper key storage
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
    const kms = new KMS();
    
    const params = {
        KeyId: 'alias/database-key',
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            // Storing plaintext key in browser localStorage
            if (typeof window !== 'undefined') {
                localStorage.setItem('encryption_key', data.Plaintext.toString('base64'));
            } else {
                // Storing in a file with weak permissions
                fs.writeFileSync('key.dat', data.Plaintext, { mode: 0o644 });
            }
            
            return encryptDatabaseCredentials(data.Plaintext);
        })
        .catch(err => console.error('Failed to generate key:', err));
}
// {/fact}

// Using KMS generateDataKey without proper key rotation
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
    const kms = new KMS({ region: 'us-east-2' });
    
    // Static timestamp for key generation - no rotation logic
    const keyGenerationDate = new Date('2020-01-01').getTime();
    const currentDate = new Date().getTime();
    
    // No key rotation logic based on time
    const params = {
        KeyId: 'alias/static-key',
        KeySpec: 'AES_256'
    };
    
    // ruleid: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            const plaintextKey = data.Plaintext;
            
            // Use the key regardless of age
            const encryptedData = encryptSensitiveData(plaintextKey, 'confidential data');
            
            return {
                encryptedData,
                keyId: params.KeyId,
                encryptedKey: data.CiphertextBlob
            };
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// GOOD CASES - Secure code that should not be detected

// Using KMS generateDataKey with encryption context
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
    const kms = new KMS({ region: 'us-west-2' });
    
    const encryptionContext = {
        'AppName': 'MyApp',
        'Environment': 'Production',
        'Purpose': 'DataEncryption'
    };
    
    const params: GenerateDataKeyRequest = {
        KeyId: 'alias/my-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext // Using encryption context for added security
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params, (err, data) => {
        if (err) {
            console.error('Error generating data key:', err);
            return;
        }
        
        try {
            // Use the data key for encryption
            const plaintextKey = data.Plaintext;
            const encryptedData = encryptSensitiveData(plaintextKey, 'sensitive data');
            
            // Zero out the plaintext key when done
            if (plaintextKey instanceof Buffer) {
                plaintextKey.fill(0);
            }
            
            // Store the encrypted key and context
            storeEncryptedKey(data.CiphertextBlob, encryptionContext);
        } catch (error) {
            console.error('Encryption error:', error);
        }
    });
}
// {/fact}

// Using KMS generateDataKey with strong key spec and proper key handling
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
    const kms = new KMS();
    
    const encryptionContext = {
        'Department': 'Finance',
        'Purpose': 'Payroll'
    };
    
    const params = {
        KeyId: 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
        KeySpec: 'AES_256', // Strong key spec
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            try {
                const plaintextKey = data.Plaintext;
                
                // Use plaintext key for encryption with proper cipher mode
                const iv = crypto.randomBytes(16);
                const cipher = crypto.createCipheriv('aes-256-gcm', plaintextKey, iv);
                const encrypted = Buffer.concat([
                    cipher.update('sensitive data', 'utf8'),
                    cipher.final()
                ]);
                const authTag = cipher.getAuthTag();
                
                // Zero out the plaintext key when done
                if (plaintextKey instanceof Buffer) {
                    plaintextKey.fill(0);
                }
                
                return {
                    encryptedData: encrypted,
                    iv: iv,
                    authTag: authTag,
                    encryptedKey: data.CiphertextBlob,
                    encryptionContext: encryptionContext
                };
            } catch (error) {
                console.error('Encryption error:', error);
                throw error;
            }
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// Using KMS generateDataKey with proper error handling and key cleanup
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
    const kms = new KMS({ region: 'us-east-1' });
    
    const encryptionContext = {
        'Application': 'CustomerPortal',
        'DataType': 'PersonalInfo'
    };
    
    const params = {
        KeyId: 'alias/test-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params, (err, data) => {
        if (err) {
            console.error('Error generating data key:', err);
            return;
        }
        
        try {
            const plaintextKey = data.Plaintext;
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', plaintextKey, iv);
            const encrypted = Buffer.concat([cipher.update('secret data', 'utf8'), cipher.final()]);
            
            // Store encrypted data with IV and encrypted key
            const encryptedPackage = {
                data: encrypted.toString('base64'),
                iv: iv.toString('base64'),
                encryptedKey: data.CiphertextBlob.toString('base64'),
                context: encryptionContext
            };
            
            fs.writeFileSync('encrypted.json', JSON.stringify(encryptedPackage));
            
            // Zero out the plaintext key when done
            if (plaintextKey instanceof Buffer) {
                plaintextKey.fill(0);
            }
        } catch (error) {
            console.error('Encryption error:', error);
        }
    });
}
// {/fact}

// Using KMS generateDataKey and securely handling the plaintext key
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
    const kms = new KMS();
    
    const encryptionContext = {
        'Service': 'PaymentProcessing',
        'TransactionType': 'Purchase'
    };
    
    const params = {
        KeyId: 'alias/my-encryption-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            try {
                const plaintextKey = data.Plaintext;
                const encryptedKey = data.CiphertextBlob;
                
                // Use key in memory only, never store plaintext
                const encryptedData = encryptSensitiveData(plaintextKey, 'sensitive data');
                
                // Store only the encrypted key and encrypted data
                const securePackage = {
                    encryptedData: encryptedData.toString('base64'),
                    encryptedKey: encryptedKey.toString('base64'),
                    context: encryptionContext
                };
                
                fs.writeFileSync('secure-data.json', JSON.stringify(securePackage));
                
                // Zero out the plaintext key
                if (plaintextKey instanceof Buffer) {
                    plaintextKey.fill(0);
                }
                
                return securePackage;
            } catch (error) {
                console.error('Encryption error:', error);
                throw error;
            }
        })
        .catch(err => console.error('Error generating data key:', err));
}
// {/fact}

// Using KMS generateDataKey with KeyId from environment variable
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
    const kms = new KMS({ region: 'eu-west-1' });
    
    // Get KeyId from environment variable
    const keyId = process.env.KMS_KEY_ID;
    
    if (!keyId) {
        throw new Error('KMS_KEY_ID environment variable not set');
    }
    
    const encryptionContext = {
        'Purpose': 'FileEncryption',
        'Filename': 'confidential-report.pdf'
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey({
        KeyId: keyId, // Using environment variable instead of hardcoding
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
    }).promise()
        .then(data => {
            try {
                const encryptedKey = data.CiphertextBlob;
                const plaintextKey = data.Plaintext;
                
                // Use plaintext key
                const encryptedFile = encryptFile(plaintextKey, 'secret.txt');
                
                // Store encrypted file with encrypted key
                fs.writeFileSync('encrypted-file.bin', encryptedFile);
                fs.writeFileSync('encrypted-key.bin', encryptedKey);
                fs.writeFileSync('context.json', JSON.stringify(encryptionContext));
                
                // Zero out the plaintext key
                if (plaintextKey instanceof Buffer) {
                    plaintextKey.fill(0);
                }
            } catch (error) {
                console.error('Encryption error:', error);
            }
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// Using KMS generateDataKey with proper key rotation strategy
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
    const kms = new KMS();
    let keyCache: { key: Buffer; timestamp: number } | null = null;
    const KEY_ROTATION_INTERVAL = 3600000; // 1 hour in milliseconds
    
    function getDataKey() {
        const now = Date.now();
        
        // Check if we need to rotate the key
        if (!keyCache || now - keyCache.timestamp > KEY_ROTATION_INTERVAL) {
            // Key doesn't exist or needs rotation
            const encryptionContext = {
                'Application': 'SecureService',
                'Timestamp': new Date().toISOString()
            };
            
            const params = {
                KeyId: 'alias/application-key',
                KeySpec: 'AES_256',
                EncryptionContext: encryptionContext
            };
            
            // ok: typescript-kms-generate-data-key
            return kms.generateDataKey(params).promise()
                .then(data => {
                    // Store new key with timestamp
                    keyCache = {
                        key: data.Plaintext,
                        timestamp: now
                    };
                    
                    // Store encrypted key for recovery
                    storeEncryptedKey(data.CiphertextBlob, encryptionContext);
                    
                    return {
                        key: data.Plaintext,
                        encryptionContext
                    };
                });
        }
        
        // Use cached key
        return Promise.resolve({
            key: keyCache.key,
            encryptionContext: { 'Application': 'SecureService' }
        });
    }
    
    getDataKey()
        .then(({ key, encryptionContext }) => {
            // Use key for encryption
            const encrypted = encryptData(key, 'sensitive information', encryptionContext);
            console.log('Data encrypted');
            
            // Don't zero out the key here since it's cached
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// Using KMS generateDataKey with sufficient key length
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
    const kms = new KMS({ region: 'ap-northeast-1' });
    
    const encryptionContext = {
        'Purpose': 'HighSecurityEncryption',
        'Classification': 'TopSecret'
    };
    
    const params = {
        KeyId: 'alias/high-security-key',
        KeySpec: 'AES_256', // Sufficient key length for high-security applications
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            try {
                const plaintextKey = data.Plaintext;
                
                // Use the key for encryption with strong algorithm and mode
                const iv = crypto.randomBytes(16);
                const cipher = crypto.createCipheriv('aes-256-gcm', plaintextKey, iv);
                const encrypted = Buffer.concat([cipher.update('confidential data', 'utf8'), cipher.final()]);
                const authTag = cipher.getAuthTag();
                
                const encryptedPackage = {
                    data: encrypted.toString('base64'),
                    iv: iv.toString('base64'),
                    authTag: authTag.toString('base64'),
                    encryptedKey: data.CiphertextBlob.toString('base64'),
                    context: encryptionContext
                };
                
                // Zero out the plaintext key
                if (plaintextKey instanceof Buffer) {
                    plaintextKey.fill(0);
                }
                
                return encryptedPackage;
            } catch (error) {
                console.error('Encryption error:', error);
                throw error;
            }
        })
        .catch(err => console.error('Error generating key:', err));
}
// {/fact}

// Using KMS generateDataKey without exposing plaintext key in logs
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
    const kms = new KMS();
    
    const encryptionContext = {
        'Application': 'LoggingService',
        'Environment': 'Production'
    };
    
    const params = {
        KeyId: 'alias/logging-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params, (err, data) => {
        if (err) {
            console.error('Error generating key:', err);
            return;
        }
        
        try {
            // Log only non-sensitive information
            console.log('Key generated successfully with context:', encryptionContext);
            
            // Use the key
            const plaintextKey = data.Plaintext;
            const encryptedData = encryptWithKey(plaintextKey, 'sensitive data');
            
            saveEncryptedData(encryptedData, data.CiphertextBlob, encryptionContext);
            
            // Zero out the plaintext key
            if (plaintextKey instanceof Buffer) {
                plaintextKey.fill(0);
            }
        } catch (error) {
            console.error('Encryption error:', error);
        }
    });
}
// {/fact}

// Using KMS generateDataKey with proper access controls
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
    const kms = new KMS({ region: 'us-west-1' });
    
    // Get key ID from secure parameter store
    const ssm = new SSM({ region: 'us-west-1' });
    
    ssm.getParameter({
        Name: '/app/kms/key-id',
        WithDecryption: true
    }).promise()
        .then(parameter => {
            const keyId = parameter.Parameter.Value;
            const encryptionContext = {
                'AccessControl': 'Restricted',
                'Department': 'Security'
            };
            
            const params = {
                KeyId: keyId,
                KeySpec: 'AES_256',
                EncryptionContext: encryptionContext
            };
            
            // ok: typescript-kms-generate-data-key
            return kms.generateDataKey(params).promise();
        })
        .then(data => {
            try {
                const plaintextKey = data.Plaintext;
                
                // Use plaintext key with proper access controls
                const encryptedUserData = encryptUserData(plaintextKey, getUserData());
                
                // Zero out the plaintext key
                if (plaintextKey instanceof Buffer) {
                    plaintextKey.fill(0);
                }
                
                return {
                    encryptedData: encryptedUserData,
                    encryptedKey: data.CiphertextBlob
                };
            } catch (error) {
                console.error('Encryption error:', error);
                throw error;
            }
        })
        .catch(err => console.error('Failed to generate key:', err));
}
// {/fact}

// Using KMS generateDataKey with proper key usage separation
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
    const kms = new KMS();
    
    // Different keys for different purposes
    const getEncryptionKey = () => {
        const encryptionContext = {
            'Purpose': 'DataEncryption',
            'Application': 'SecureMessaging'
        };
        
        const params = {
            KeyId: 'alias/encryption-key',
            KeySpec: 'AES_256',
            EncryptionContext: encryptionContext
        };
        
        // ok: typescript-kms-generate-data-key
        return kms.generateDataKey(params).promise();
    };
    
    const getSigningKey = () => {
        const encryptionContext = {
            'Purpose': 'MessageSigning',
            'Application': 'SecureMessaging'
        };
        
        const params = {
            KeyId: 'alias/signing-key',
            KeySpec: 'AES_256',
            EncryptionContext: encryptionContext
        };
        
        return kms.generateDataKey(params).promise();
    };
    
    // Use separate keys for separate purposes
    Promise.all([getEncryptionKey(), getSigningKey()])
        .then(([encryptionKeyData, signingKeyData]) => {
            try {
                const encryptionKey = encryptionKeyData.Plaintext;
                const signingKey = signingKeyData.Plaintext;
                
                // Use encryption key for encryption
                const encryptedData = encryptData(encryptionKey, 'secret message');
                
                // Use signing key for HMAC
                const hmac = crypto.createHmac('sha256', signingKey).update('message to authenticate').digest('hex');
                
                // Zero out plaintext keys
                if (encryptionKey instanceof Buffer) encryptionKey.fill(0);
                if (signingKey instanceof Buffer) signingKey.fill(0);
                
                return {
                    encryptedData,
                    hmac,
                    encryptedEncryptionKey: encryptionKeyData.CiphertextBlob,
                    encryptedSigningKey: signingKeyData.CiphertextBlob
                };
            } catch (error) {
                console.error('Error:', error);
                throw error;
            }
        })
        .catch(err => console.error('Error:', err));
}
// {/fact}

// Using KMS generateDataKey with proper key management
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
    const kms = new KMS({ region: 'eu-central-1' });
    
    // Using Secrets Manager for secure key storage
    const secretsManager = new SecretsManager({ region: 'eu-central-1' });
    
    const encryptionContext = {
        'Application': 'SecureDataProcessor',
        'Environment': 'Production'
    };
    
    const params = {
        KeyId: 'alias/app-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            try {
                const plaintextKey = data.Plaintext;
                
                // Use key for encryption
                const encryptedData = encryptSensitiveRecords(plaintextKey);
                
                // Store only the encrypted key in Secrets Manager
                return secretsManager.putSecretValue({
                    SecretId: 'app/encrypted-key',
                    SecretBinary: data.CiphertextBlob
                }).promise()
                    .then(() => {
                        // Zero out the plaintext key
                        if (plaintextKey instanceof Buffer) {
                            plaintextKey.fill(0);
                        }
                        
                        return encryptedData;
                    });
            } catch (error) {
                console.error('Encryption error:', error);
                throw error;
            }
        })
        .catch(err => console.error('Failed to generate key:', err));
}
// {/fact}

// Using KMS generateDataKey with strong cipher
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
    const kms = new KMS();
    
    const encryptionContext = {
        'Purpose': 'SecureStorage',
        'DataType': 'FinancialRecords'
    };
    
    const params = {
        KeyId: 'alias/encryption-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params, (err, data) => {
        if (err) {
            console.error('Error:', err);
            return;
        }
        
        try {
            const key = data.Plaintext;
            
            // Using key with strong cipher mode (GCM with authentication)
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
            const encrypted = Buffer.concat([cipher.update('sensitive data', 'utf8'), cipher.final()]);
            const authTag = cipher.getAuthTag();
            
            const encryptedPackage = {
                data: encrypted.toString('base64'),
                iv: iv.toString('base64'),
                authTag: authTag.toString('base64'),
                encryptedKey: data.CiphertextBlob.toString('base64'),
                context: encryptionContext
            };
            
            storeEncryptedData(encryptedPackage);
            
            // Zero out the plaintext key
            if (key instanceof Buffer) {
                key.fill(0);
            }
        } catch (error) {
            console.error('Encryption error:', error);
        }
    });
}
// {/fact}

// Using KMS generateDataKey with proper key destruction
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
    const kms = new KMS({ region: 'ap-southeast-2' });
    
    const encryptionContext = {
        'Purpose': 'OneTimeEncryption',
        'Requestor': 'AdminUser'
    };
    
    const params = {
        KeyId: 'alias/one-time-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            try {
                const plaintextKey = data.Plaintext;
                
                // Use the key
                const encryptedData = encryptWithKey(plaintextKey, 'confidential information');
                
                // Properly destroy key after use
                if (plaintextKey instanceof Buffer) {
                    plaintextKey.fill(0); // Zero out buffer
                }
                
                return { encryptedData, encryptedKey: data.CiphertextBlob };
            } catch (error) {
                console.error('Encryption error:', error);
                throw error;
            }
        })
        .catch(err => console.error('Error generating key:', err));
}
// {/fact}

// Using KMS generateDataKey with proper key storage
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
    const kms = new KMS();
    
    const encryptionContext = {
        'Purpose': 'DatabaseEncryption',
        'Database': 'CustomerRecords'
    };
    
    const params = {
        KeyId: 'alias/database-key',
        KeySpec: 'AES_256',
        EncryptionContext: encryptionContext
    };
    
    // ok: typescript-kms-generate-data-key
    kms.generateDataKey(params).promise()
        .then(data => {
            try {
                const plaintextKey = data.Plaintext;
                
                // Use key for encryption
                const encryptedCredentials = encryptDatabaseCredentials(plaintextKey);
                
                // Store only the encrypted key in a secure location
                const secureStorage = {
                    encryptedKey: data.CiphertextBlob.toString('base64'),
                    encryptionContext: encryptionContext,
                    encryptedData: encryptedCredentials.toString('base64')
                };
                
                // Write with secure permissions
                fs.writeFileSync('secure-storage.json', JSON.stringify(secureStorage), { mode: 0o600 });
                
                // Zero out the plaintext key
                if (plaintextKey instanceof Buffer) {
                    plaintextKey.fill(0);
                }
                
                return secureStorage;
            } catch (error) {
                console.error('Encryption error:', error);
                throw error;
            }
        })
        .catch(err => console.error('Failed to generate key:', err));
}
// {/fact}

// Using KMS generateDataKey with proper key rotation
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
    const kms = new KMS({ region: 'us-east-2' });
    
    // Key rotation logic
    const KEY_ROTATION_PERIOD = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
    
    // Get last rotation timestamp from secure storage
    const getLastKeyRotationTime = () => {
        try {
            const data = fs.readFileSync('key-metadata.json', 'utf8');
            const metadata = JSON.parse(data);
            return metadata.lastRotation || 0;
        } catch (err) {
            return 0; // If file doesn't exist or is invalid, force rotation
        }
    };
    
    const lastRotation = getLastKeyRotationTime();
    const currentTime = new Date().getTime();
    
    // Check if key rotation is needed
    if (currentTime - lastRotation > KEY_ROTATION_PERIOD) {
        const encryptionContext = {
            'Purpose': 'PeriodicEncryption',
            'RotationDate': new Date().toISOString()
        };
        
        const params = {
            KeyId: 'alias/rotating-key',
            KeySpec: 'AES_256',
            EncryptionContext: encryptionContext
        };
        
        // ok: typescript-kms-generate-data-key
        kms.generateDataKey(params).promise()
            .then(data => {
                try {
                    const plaintextKey = data.Plaintext;
                    
                    // Use the newly rotated key
                    const encryptedData = encryptSensitiveData(plaintextKey, 'confidential data');
                    
                    // Store rotation metadata
                    const metadata = {
                        lastRotation: currentTime,
                        keyId: params.KeyId,
                        encryptionContext: encryptionContext
                    };
                    
                    fs.writeFileSync('key-metadata.json', JSON.stringify(metadata), { mode: 0o600 });
                    
                    // Store encrypted key
                    fs.writeFileSync('current-encrypted-key.bin', data.CiphertextBlob, { mode: 0o600 });
                    
                    // Zero out the plaintext key
                    if (plaintextKey instanceof Buffer) {
                        plaintextKey.fill(0);
                    }
                    
                    return {
                        encryptedData,
                        keyMetadata: metadata
                    };
                } catch (error) {
                    console.error('Encryption error:', error);
                    throw error;
                }
            })
            .catch(err => console.error('Error:', err));
    } else {
        console.log('Key rotation not needed yet');
        // Use existing key
    }
}
// {/fact}

// Helper functions (implementations not shown for brevity)
function encryptSensitiveData(key: Buffer, data: string): Buffer {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([iv, cipher.update(data, 'utf8'), cipher.final()]);
}

function encryptWithKey(key: Buffer, data: string): Buffer {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([iv, cipher.update(data, 'utf8'), cipher.final()]);
}

function encryptFile(key: Buffer, filePath: string): Buffer {
    const fileData = fs.readFileSync(filePath, 'utf8');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([iv, cipher.update(fileData, 'utf8'), cipher.final()]);
}

function storeEncryptedKey(encryptedKey: Buffer, context: object): void {
    // Implementation for storing encrypted key securely
}

function saveEncryptedData(encryptedData: Buffer, encryptedKey: Buffer, context?: object): void {
    // Implementation for saving encrypted data
}

function storeKeyForLaterUse(encryptedKey: Buffer): void {
    // Implementation for storing encrypted key
}

function encryptUserData(key: Buffer, userData: any): Buffer {
    // Implementation for encrypting user data
    return Buffer.from('encrypted');
}

function getUserData(): any {
    // Implementation for getting user data
    return { userId: 123, name: 'User' };
}

function encryptData(key: Buffer, data: string, context?: object): Buffer {
    // Implementation for encrypting data
    return Buffer.from('encrypted');
}

function encryptSensitiveRecords(key: Buffer): Buffer {
    // Implementation for encrypting sensitive records
    return Buffer.from('encrypted records');
}

function encryptDatabaseCredentials(key: Buffer): Buffer {
    // Implementation for encrypting database credentials
    return Buffer.from('encrypted credentials');
}

function storeEncryptedData(data: any): void {
    // Implementation for storing encrypted data
}

// Global variable for demonstration purposes only (bad practice)
const globalKeyStore = {
    setKey: (name: string, key: Buffer) => {
        // Bad implementation that stores keys in memory
    }
};