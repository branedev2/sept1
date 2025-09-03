// Import necessary crypto libraries
import * as crypto from 'crypto';
import { KMS } from 'aws-sdk';
import { EncryptionSDK, ReEncryptionSDK } from 'encryption-sdk';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
    const encryptedData = fetchEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    // Decrypt and then encrypt again instead of using reEncrypt
    const decryptedData = crypto.privateDecrypt(sourceKey, encryptedData);
    // ruleid: typescript-reencrypt
    const reEncryptedData = crypto.publicEncrypt(targetKey, decryptedData);
    
    return reEncryptedData;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
    const kms = new KMS();
    const encryptedBlob = getEncryptedBlob();
    const sourceKeyId = 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';
    const targetKeyId = 'arn:aws:kms:us-west-2:111122223333:key/0987dcba-09fe-87dc-65ba-ab0987654321';
    
    // Decrypt and then encrypt again instead of using reEncrypt
    kms.decrypt({ CiphertextBlob: encryptedBlob, KeyId: sourceKeyId }, (err, data) => {
        if (err) throw err;
        // ruleid: typescript-reencrypt
        kms.encrypt({ 
            KeyId: targetKeyId, 
            Plaintext: data.Plaintext 
        }, (err, result) => {
            if (err) throw err;
            storeEncryptedData(result.CiphertextBlob);
        });
    });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
    const encryptionSdk = new EncryptionSDK();
    const ciphertext = getCiphertext();
    const sourceKeyring = getSourceKeyring();
    const targetKeyring = getTargetKeyring();
    
    // Decrypt and then encrypt again instead of using reEncrypt
    const { plaintext } = encryptionSdk.decrypt({
        ciphertext,
        keyring: sourceKeyring
    });
    
    // ruleid: typescript-reencrypt
    const result = encryptionSdk.encrypt({
        plaintext,
        keyring: targetKeyring
    });
    
    return result.ciphertext;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
    const encryptedMessage = getEncryptedMessage();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    // Using async/await but still decrypting and encrypting separately
    async function processData() {
        const decrypted = await decryptAsync(encryptedMessage, sourceKey);
        // ruleid: typescript-reencrypt
        const reEncrypted = await encryptAsync(decrypted, targetKey);
        return reEncrypted;
    }
    
    return processData();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
    const encryptedData = fetchEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    // Using a different pattern but still decrypting and encrypting separately
    function transformData() {
        const decrypted = crypto.createDecipheriv('aes-256-cbc', sourceKey, Buffer.alloc(16)).update(encryptedData);
        // ruleid: typescript-reencrypt
        return crypto.createCipheriv('aes-256-cbc', targetKey, Buffer.alloc(16)).update(decrypted);
    }
    
    return transformData();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
    class EncryptionManager {
        private sourceKey: Buffer;
        private targetKey: Buffer;
        
        constructor(sourceKey: Buffer, targetKey: Buffer) {
            this.sourceKey = sourceKey;
            this.targetKey = targetKey;
        }
        
        transformEncryptedData(encryptedData: Buffer): Buffer {
            const decrypted = crypto.privateDecrypt(this.sourceKey, encryptedData);
            // ruleid: typescript-reencrypt
            return crypto.publicEncrypt(this.targetKey, decrypted);
        }
    }
    
    const manager = new EncryptionManager(getSourceKey(), getTargetKey());
    return manager.transformEncryptedData(getEncryptedData());
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
    const kms = new KMS();
    const encryptedBlob = getEncryptedBlob();
    
    // Using promises but still decrypting and encrypting separately
    return kms.decrypt({ 
        CiphertextBlob: encryptedBlob, 
        KeyId: 'source-key-id' 
    }).promise()
      .then(data => {
          // ruleid: typescript-reencrypt
          return kms.encrypt({ 
              KeyId: 'target-key-id', 
              Plaintext: data.Plaintext 
          }).promise();
      })
      .then(result => {
          return result.CiphertextBlob;
      });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
    const encryptedData = getEncryptedData();
    const sourcePassword = 'source-password';
    const targetPassword = 'target-password';
    
    // Using different crypto algorithm but still decrypting and encrypting separately
    const decipher = crypto.createDecipher('aes192', sourcePassword);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    // ruleid: typescript-reencrypt
    const cipher = crypto.createCipher('aes192', targetPassword);
    let reEncrypted = cipher.update(decrypted, 'utf8', 'hex');
    reEncrypted += cipher.final('hex');
    
    return reEncrypted;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
    // Using a loop to process multiple encrypted items
    const encryptedItems = getEncryptedItems();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    const reEncryptedItems = encryptedItems.map(item => {
        const decrypted = crypto.privateDecrypt(sourceKey, item);
        // ruleid: typescript-reencrypt
        return crypto.publicEncrypt(targetKey, decrypted);
    });
    
    return reEncryptedItems;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
    // Using conditional logic but still decrypting and encrypting separately
    const encryptedData = getEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    let result;
    if (shouldProcess()) {
        const decrypted = crypto.privateDecrypt(sourceKey, encryptedData);
        // ruleid: typescript-reencrypt
        result = crypto.publicEncrypt(targetKey, decrypted);
    } else {
        result = encryptedData;
    }
    
    return result;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
    // Using a callback pattern
    const encryptedData = getEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    function processWithCallback(data: Buffer, callback: (result: Buffer) => void) {
        const decrypted = crypto.privateDecrypt(sourceKey, data);
        // ruleid: typescript-reencrypt
        const reEncrypted = crypto.publicEncrypt(targetKey, decrypted);
        callback(reEncrypted);
    }
    
    let result: Buffer;
    processWithCallback(encryptedData, (processed) => {
        result = processed;
    });
    
    return result;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
    // Using try-catch but still decrypting and encrypting separately
    const encryptedData = getEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    try {
        const decrypted = crypto.privateDecrypt(sourceKey, encryptedData);
        // ruleid: typescript-reencrypt
        return crypto.publicEncrypt(targetKey, decrypted);
    } catch (error) {
        console.error('Encryption error:', error);
        return null;
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
    // Using a different crypto library but same pattern
    const encryptionSdk = new EncryptionSDK();
    const data = {
        ciphertext: getCiphertext(),
        sourceKeyring: getSourceKeyring(),
        targetKeyring: getTargetKeyring()
    };
    
    function processEncryptedData(input: any) {
        const { plaintext } = encryptionSdk.decrypt({
            ciphertext: input.ciphertext,
            keyring: input.sourceKeyring
        });
        
        // ruleid: typescript-reencrypt
        return encryptionSdk.encrypt({
            plaintext,
            keyring: input.targetKeyring
        }).ciphertext;
    }
    
    return processEncryptedData(data);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
    // Using a higher-order function
    const encryptedData = getEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    const reEncryptFunction = (data: Buffer) => {
        const decrypted = crypto.privateDecrypt(sourceKey, data);
        // ruleid: typescript-reencrypt
        return crypto.publicEncrypt(targetKey, decrypted);
    };
    
    return reEncryptFunction(encryptedData);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
    // Using object destructuring
    const encryptedData = getEncryptedData();
    const { source: sourceKey, target: targetKey } = getKeys();
    
    const processData = ({ data, source, target }: { data: Buffer, source: any, target: any }) => {
        const decrypted = crypto.privateDecrypt(source, data);
        // ruleid: typescript-reencrypt
        return crypto.publicEncrypt(target, decrypted);
    };
    
    return processData({ data: encryptedData, source: sourceKey, target: targetKey });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
    const encryptedData = fetchEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    // ok: typescript-reencrypt
    const reEncryptedData = crypto.reEncrypt(encryptedData, sourceKey, targetKey);
    
    return reEncryptedData;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
    const kms = new KMS();
    const encryptedBlob = getEncryptedBlob();
    const sourceKeyId = 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';
    const targetKeyId = 'arn:aws:kms:us-west-2:111122223333:key/0987dcba-09fe-87dc-65ba-ab0987654321';
    
    // ok: typescript-reencrypt
    kms.reEncrypt({
        CiphertextBlob: encryptedBlob,
        SourceKeyId: sourceKeyId,
        DestinationKeyId: targetKeyId
    }, (err, result) => {
        if (err) throw err;
        storeEncryptedData(result.CiphertextBlob);
    });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
    const encryptionSdk = new ReEncryptionSDK();
    const ciphertext = getCiphertext();
    const sourceKeyring = getSourceKeyring();
    const targetKeyring = getTargetKeyring();
    
    // ok: typescript-reencrypt
    const result = encryptionSdk.reEncrypt({
        ciphertext,
        sourceKeyring,
        targetKeyring
    });
    
    return result.ciphertext;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
    const encryptedMessage = getEncryptedMessage();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    // Using async/await with proper reEncrypt
    async function processData() {
        // ok: typescript-reencrypt
        const reEncrypted = await reEncryptAsync(encryptedMessage, sourceKey, targetKey);
        return reEncrypted;
    }
    
    return processData();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
    // Not re-encrypting at all, just decrypting for use
    const encryptedData = fetchEncryptedData();
    const decryptionKey = getDecryptionKey();
    
    // ok: typescript-reencrypt
    const decryptedData = crypto.privateDecrypt(decryptionKey, encryptedData);
    
    // Use the decrypted data without re-encrypting
    processDecryptedData(decryptedData);
    
    return decryptedData;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
    // Not re-encrypting at all, just encrypting new data
    const rawData = getRawData();
    const encryptionKey = getEncryptionKey();
    
    // ok: typescript-reencrypt
    const encryptedData = crypto.publicEncrypt(encryptionKey, rawData);
    
    return encryptedData;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
    const kms = new KMS();
    const encryptedBlob = getEncryptedBlob();
    
    // Using promises with proper reEncrypt
    // ok: typescript-reencrypt
    return kms.reEncrypt({ 
        CiphertextBlob: encryptedBlob, 
        SourceKeyId: 'source-key-id',
        DestinationKeyId: 'target-key-id'
    }).promise()
    .then(result => {
        return result.CiphertextBlob;
    });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
    class SecureEncryptionManager {
        private sourceKey: Buffer;
        private targetKey: Buffer;
        
        constructor(sourceKey: Buffer, targetKey: Buffer) {
            this.sourceKey = sourceKey;
            this.targetKey = targetKey;
        }
        
        reEncryptData(encryptedData: Buffer): Buffer {
            // ok: typescript-reencrypt
            return crypto.reEncrypt(encryptedData, this.sourceKey, this.targetKey);
        }
    }
    
    const manager = new SecureEncryptionManager(getSourceKey(), getTargetKey());
    return manager.reEncryptData(getEncryptedData());
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
    // Using a loop with proper reEncrypt
    const encryptedItems = getEncryptedItems();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    // ok: typescript-reencrypt
    const reEncryptedItems = encryptedItems.map(item => 
        crypto.reEncrypt(item, sourceKey, targetKey)
    );
    
    return reEncryptedItems;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
    // Using conditional logic with proper reEncrypt
    const encryptedData = getEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    let result;
    if (shouldProcess()) {
        // ok: typescript-reencrypt
        result = crypto.reEncrypt(encryptedData, sourceKey, targetKey);
    } else {
        result = encryptedData;
    }
    
    return result;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
    // Decrypting and encrypting different data (not re-encrypting the same data)
    const encryptedData1 = getEncryptedData1();
    const encryptionKey = getEncryptionKey();
    const decryptionKey = getDecryptionKey();
    
    // ok: typescript-reencrypt
    const decryptedData = crypto.privateDecrypt(decryptionKey, encryptedData1);
    
    // This is different data, not re-encrypting the same data
    const newData = getNewData();
    const encryptedNewData = crypto.publicEncrypt(encryptionKey, newData);
    
    return { decryptedData, encryptedNewData };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
    // Using try-catch with proper reEncrypt
    const encryptedData = getEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    try {
        // ok: typescript-reencrypt
        return crypto.reEncrypt(encryptedData, sourceKey, targetKey);
    } catch (error) {
        console.error('Encryption error:', error);
        return null;
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
    // Using a higher-order function with proper reEncrypt
    const encryptedData = getEncryptedData();
    const sourceKey = getSourceKey();
    const targetKey = getTargetKey();
    
    // ok: typescript-reencrypt
    const reEncryptFunction = (data: Buffer) => 
        crypto.reEncrypt(data, sourceKey, targetKey);
    
    return reEncryptFunction(encryptedData);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
    // Decrypting and encrypting in separate operations with different purposes
    const encryptedUserData = getUserEncryptedData();
    const userDecryptionKey = getUserDecryptionKey();
    
    // Decrypt user data for processing
    // ok: typescript-reencrypt
    const userData = crypto.privateDecrypt(userDecryptionKey, encryptedUserData);
    processUserData(userData);
    
    // Encrypt a separate response
    const responseData = generateResponseData();
    const responseEncryptionKey = getResponseEncryptionKey();
    const encryptedResponse = crypto.publicEncrypt(responseEncryptionKey, responseData);
    
    return encryptedResponse;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
    // Using object destructuring with proper reEncrypt
    const encryptedData = getEncryptedData();
    const { source: sourceKey, target: targetKey } = getKeys();
    
    // ok: typescript-reencrypt
    const processData = ({ data, source, target }: { data: Buffer, source: any, target: any }) => 
        crypto.reEncrypt(data, source, target);
    
    return processData({ data: encryptedData, source: sourceKey, target: targetKey });
}
// {/fact}

// Helper functions (not part of the test cases)
function getEncryptedData(): Buffer { return Buffer.from('encrypted'); }
function getEncryptedData1(): Buffer { return Buffer.from('encrypted1'); }
function getNewData(): Buffer { return Buffer.from('new data'); }
function fetchEncryptedData(): Buffer { return Buffer.from('encrypted'); }
function getSourceKey(): any { return {}; }
function getTargetKey(): any { return {}; }
function getDecryptionKey(): any { return {}; }
function getEncryptionKey(): any { return {}; }
function getEncryptedBlob(): Buffer { return Buffer.from('encrypted'); }
function storeEncryptedData(data: any): void {}
function getCiphertext(): Buffer { return Buffer.from('ciphertext'); }
function getSourceKeyring(): any { return {}; }
function getTargetKeyring(): any { return {}; }
function getEncryptedMessage(): Buffer { return Buffer.from('message'); }
function decryptAsync(data: Buffer, key: any): Promise<Buffer> { return Promise.resolve(Buffer.from('decrypted')); }
function encryptAsync(data: Buffer, key: any): Promise<Buffer> { return Promise.resolve(Buffer.from('encrypted')); }
function reEncryptAsync(data: Buffer, sourceKey: any, targetKey: any): Promise<Buffer> { return Promise.resolve(Buffer.from('reencrypted')); }
function getEncryptedItems(): Buffer[] { return [Buffer.from('item1'), Buffer.from('item2')]; }
function shouldProcess(): boolean { return true; }
function processDecryptedData(data: Buffer): void {}
function getKeys(): { source: any, target: any } { return { source: {}, target: {} }; }
function getUserEncryptedData(): Buffer { return Buffer.from('user data'); }
function getUserDecryptionKey(): any { return {}; }
function processUserData(data: Buffer): void {}
function generateResponseData(): Buffer { return Buffer.from('response'); }
function getResponseEncryptionKey(): any { return {}; }