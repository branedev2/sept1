// File: pbkdf2_hash_algo_test_cases.js

const crypto = require('crypto');
const express = require('express');
const app = express();
app.use(express.json());

// TRUE POSITIVES - Vulnerable code examples

// Example 1: Using MD5 with PBKDF2 in a password hashing function
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_1() {
    app.post('/register', (req, res) => {
        const password = req.body.password;
        const salt = crypto.randomBytes(16);
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(password, salt, 10000, 64, 'md5', (err, derivedKey) => {
            if (err) throw err;
            const hashedPassword = derivedKey.toString('hex');
            // Store hashedPassword in database
            res.send('User registered successfully');
        });
    });
}
// {/fact}

// Example 2: Using SHA1 with PBKDF2 synchronously
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_2() {
    app.post('/create-account', (req, res) => {
        const userPassword = req.body.password;
        const salt = crypto.randomBytes(16).toString('hex');
        
        try {
            // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
            const key = crypto.pbkdf2Sync(userPassword, salt, 1000, 32, 'sha1');
            const hashedPassword = key.toString('hex');
            
            // Save user with hashedPassword
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ error: 'Failed to create account' });
        }
    });
}
// {/fact}

// Example 3: Using MD5 with PBKDF2 in a token generation function
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_3() {
    app.get('/generate-token', (req, res) => {
        const userId = req.query.id;
        const timestamp = Date.now().toString();
        const salt = crypto.randomBytes(8);
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(userId + timestamp, salt, 5000, 16, 'md5', (err, derivedKey) => {
            if (err) {
                return res.status(500).send('Error generating token');
            }
            const token = derivedKey.toString('base64');
            res.json({ token });
        });
    });
}
// {/fact}

// Example 4: Using RIPEMD160 with PBKDF2 for API key generation
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_4() {
    app.post('/api/generate-key', (req, res) => {
        const appId = req.body.appId;
        const secret = req.body.secret;
        const salt = appId + '_salt';
        
        try {
            // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
            const apiKey = crypto.pbkdf2Sync(secret, salt, 10000, 32, 'ripemd160');
            res.json({
                apiKey: apiKey.toString('hex'),
                expiresIn: '30 days'
            });
        } catch (error) {
            res.status(500).send('Failed to generate API key');
        }
    });
}
// {/fact}

// Example 5: Using SHA1 with PBKDF2 in a file encryption key derivation
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_5() {
    app.post('/encrypt-file', (req, res) => {
        const filePassword = req.body.password;
        const fileName = req.body.fileName;
        const salt = crypto.randomBytes(16);
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(filePassword, salt, 1000, 32, 'sha1', (err, encryptionKey) => {
            if (err) {
                return res.status(500).send('Encryption failed');
            }
            
            // Use encryptionKey to encrypt the file
            res.send('File encrypted successfully');
        });
    });
}
// {/fact}

// Example 6: Using MD5 with PBKDF2 in a JWT token signing function
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_6() {
    app.post('/login', (req, res) => {
        const username = req.body.username;
        const password = req.body.password;
        const salt = username + '_jwt_salt';
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        const signingKey = crypto.pbkdf2Sync(password, salt, 2000, 64, 'md5');
        
        // Use signingKey to sign JWT token
        const token = 'jwt_token_signed_with_derived_key';
        res.json({ token });
    });
}
// {/fact}

// Example 7: Using SHA1 with PBKDF2 in a cookie signing function
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_7() {
    app.get('/set-cookie', (req, res) => {
        const userId = req.query.id;
        const secret = 'app_secret';
        const salt = crypto.randomBytes(8);
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(secret, salt, 5000, 24, 'sha1', (err, cookieKey) => {
            if (err) {
                return res.status(500).send('Error setting cookie');
            }
            
            // Use cookieKey to sign cookie
            res.cookie('session', userId, { signed: true });
            res.send('Cookie set');
        });
    });
}
// {/fact}

// Example 8: Using RIPEMD160 with PBKDF2 for password reset token
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_8() {
    app.post('/request-password-reset', (req, res) => {
        const email = req.body.email;
        const timestamp = Date.now().toString();
        const salt = email + '_reset_salt';
        
        try {
            // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
            const resetToken = crypto.pbkdf2Sync(email + timestamp, salt, 1000, 16, 'ripemd160');
            
            // Send resetToken to user's email
            res.send('Password reset email sent');
        } catch (error) {
            res.status(500).send('Failed to process password reset');
        }
    });
}
// {/fact}

// Example 9: Using MD5 with PBKDF2 in a custom authentication middleware
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_9() {
    const authenticateUser = (req, res, next) => {
        const authToken = req.headers.authorization;
        const appSecret = 'app_secret_key';
        const salt = 'auth_salt';
        
        if (!authToken) {
            return res.status(401).send('Unauthorized');
        }
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(appSecret, salt, 10000, 32, 'md5', (err, derivedKey) => {
            if (err) {
                return res.status(500).send('Authentication error');
            }
            
            // Verify authToken using derivedKey
            req.authenticated = true;
            next();
        });
    };
    
    app.get('/protected-resource', authenticateUser, (req, res) => {
        res.send('Protected data');
    });
}
// {/fact}

// Example 10: Using SHA1 with PBKDF2 in a database encryption function
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_10() {
    app.post('/store-sensitive-data', (req, res) => {
        const userData = req.body.data;
        const encryptionPassword = req.body.encryptionKey;
        const salt = crypto.randomBytes(16);
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        const encryptionKey = crypto.pbkdf2Sync(encryptionPassword, salt, 5000, 32, 'sha1');
        
        // Encrypt userData with encryptionKey
        const encryptedData = 'encrypted_data_using_derived_key';
        
        // Store encryptedData in database
        res.send('Data stored securely');
    });
}
// {/fact}

// Example 11: Using MD5 with PBKDF2 for generating a cache key
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_11() {
    app.get('/cached-data', (req, res) => {
        const userId = req.query.userId;
        const dataId = req.query.dataId;
        const salt = 'cache_salt';
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(userId + dataId, salt, 1000, 16, 'md5', (err, derivedKey) => {
            if (err) {
                return res.status(500).send('Error generating cache key');
            }
            
            const cacheKey = derivedKey.toString('hex');
            // Use cacheKey to retrieve or store cached data
            res.json({ data: 'Cached data for ' + cacheKey });
        });
    });
}
// {/fact}

// Example 12: Using SHA1 with PBKDF2 in a webhook signature verification
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_12() {
    app.post('/webhook', (req, res) => {
        const payload = req.body;
        const signature = req.headers['x-signature'];
        const webhookSecret = 'webhook_secret_key';
        const salt = 'webhook_salt';
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        const signingKey = crypto.pbkdf2Sync(webhookSecret, salt, 2000, 32, 'sha1');
        
        // Verify webhook signature using signingKey
        const isValid = true; // Simplified for example
        
        if (isValid) {
            res.send('Webhook processed');
        } else {
            res.status(401).send('Invalid signature');
        }
    });
}
// {/fact}

// Example 13: Using RIPEMD160 with PBKDF2 in a session token generator
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_13() {
    app.post('/create-session', (req, res) => {
        const username = req.body.username;
        const sessionData = JSON.stringify({
            username,
            created: Date.now()
        });
        const salt = crypto.randomBytes(16);
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(sessionData, salt, 5000, 24, 'ripemd160', (err, sessionKey) => {
            if (err) {
                return res.status(500).send('Session creation failed');
            }
            
            const sessionToken = sessionKey.toString('base64');
            res.json({ sessionToken });
        });
    });
}
// {/fact}

// Example 14: Using MD5 with PBKDF2 for file checksum verification
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_14() {
    app.post('/verify-file', (req, res) => {
        const fileContent = req.body.content;
        const userProvidedChecksum = req.body.checksum;
        const salt = 'file_verification_salt';
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        const calculatedChecksum = crypto.pbkdf2Sync(fileContent, salt, 1000, 16, 'md5');
        
        if (calculatedChecksum.toString('hex') === userProvidedChecksum) {
            res.send('File verification successful');
        } else {
            res.status(400).send('File verification failed');
        }
    });
}
// {/fact}

// Example 15: Using SHA1 with PBKDF2 in a multi-factor authentication code generator
// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_15() {
    app.post('/generate-mfa-code', (req, res) => {
        const userId = req.body.userId;
        const timestamp = Math.floor(Date.now() / 30000); // 30-second window
        const salt = userId + '_mfa_salt';
        
        // ruleid: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(timestamp.toString(), salt, 1000, 6, 'sha1', (err, derivedKey) => {
            if (err) {
                return res.status(500).send('MFA code generation failed');
            }
            
            // Convert to 6-digit code
            const code = parseInt(derivedKey.toString('hex'), 16) % 1000000;
            res.json({ code: code.toString().padStart(6, '0') });
        });
    });
}
// {/fact}

// TRUE NEGATIVES - Secure code examples

// Example 1: Using SHA256 with PBKDF2 for password hashing
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_1() {
    app.post('/register', (req, res) => {
        const password = req.body.password;
        const salt = crypto.randomBytes(16);
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(password, salt, 10000, 64, 'sha256', (err, derivedKey) => {
            if (err) throw err;
            const hashedPassword = derivedKey.toString('hex');
            // Store hashedPassword in database
            res.send('User registered successfully');
        });
    });
}
// {/fact}

// Example 2: Using SHA512 with PBKDF2 synchronously
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_2() {
    app.post('/create-account', (req, res) => {
        const userPassword = req.body.password;
        const salt = crypto.randomBytes(16).toString('hex');
        
        try {
            // ok: javascript-hash-algo-compliance-check-for-pbkdf2
            const key = crypto.pbkdf2Sync(userPassword, salt, 10000, 64, 'sha512');
            const hashedPassword = key.toString('hex');
            
            // Save user with hashedPassword
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ error: 'Failed to create account' });
        }
    });
}
// {/fact}

// Example 3: Using SHA384 with PBKDF2 in a token generation function
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_3() {
    app.get('/generate-token', (req, res) => {
        const userId = req.query.id;
        const timestamp = Date.now().toString();
        const salt = crypto.randomBytes(16);
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(userId + timestamp, salt, 10000, 32, 'sha384', (err, derivedKey) => {
            if (err) {
                return res.status(500).send('Error generating token');
            }
            const token = derivedKey.toString('base64');
            res.json({ token });
        });
    });
}
// {/fact}

// Example 4: Using SHA256 with PBKDF2 for API key generation
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_4() {
    app.post('/api/generate-key', (req, res) => {
        const appId = req.body.appId;
        const secret = req.body.secret;
        const salt = appId + '_salt';
        
        try {
            // ok: javascript-hash-algo-compliance-check-for-pbkdf2
            const apiKey = crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha256');
            res.json({
                apiKey: apiKey.toString('hex'),
                expiresIn: '30 days'
            });
        } catch (error) {
            res.status(500).send('Failed to generate API key');
        }
    });
}
// {/fact}

// Example 5: Using SHA512 with PBKDF2 in a file encryption key derivation
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_5() {
    app.post('/encrypt-file', (req, res) => {
        const filePassword = req.body.password;
        const fileName = req.body.fileName;
        const salt = crypto.randomBytes(16);
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(filePassword, salt, 100000, 32, 'sha512', (err, encryptionKey) => {
            if (err) {
                return res.status(500).send('Encryption failed');
            }
            
            // Use encryptionKey to encrypt the file
            res.send('File encrypted successfully');
        });
    });
}
// {/fact}

// Example 6: Using SHA256 with PBKDF2 in a JWT token signing function
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_6() {
    app.post('/login', (req, res) => {
        const username = req.body.username;
        const password = req.body.password;
        const salt = username + '_jwt_salt';
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        const signingKey = crypto.pbkdf2Sync(password, salt, 50000, 64, 'sha256');
        
        // Use signingKey to sign JWT token
        const token = 'jwt_token_signed_with_derived_key';
        res.json({ token });
    });
}
// {/fact}

// Example 7: Using SHA384 with PBKDF2 in a cookie signing function
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_7() {
    app.get('/set-cookie', (req, res) => {
        const userId = req.query.id;
        const secret = 'app_secret';
        const salt = crypto.randomBytes(16);
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(secret, salt, 10000, 32, 'sha384', (err, cookieKey) => {
            if (err) {
                return res.status(500).send('Error setting cookie');
            }
            
            // Use cookieKey to sign cookie
            res.cookie('session', userId, { signed: true });
            res.send('Cookie set');
        });
    });
}
// {/fact}

// Example 8: Using SHA512 with PBKDF2 for password reset token
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_8() {
    app.post('/request-password-reset', (req, res) => {
        const email = req.body.email;
        const timestamp = Date.now().toString();
        const salt = email + '_reset_salt';
        
        try {
            // ok: javascript-hash-algo-compliance-check-for-pbkdf2
            const resetToken = crypto.pbkdf2Sync(email + timestamp, salt, 100000, 32, 'sha512');
            
            // Send resetToken to user's email
            res.send('Password reset email sent');
        } catch (error) {
            res.status(500).send('Failed to process password reset');
        }
    });
}
// {/fact}

// Example 9: Using SHA256 with PBKDF2 in a custom authentication middleware
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_9() {
    const authenticateUser = (req, res, next) => {
        const authToken = req.headers.authorization;
        const appSecret = 'app_secret_key';
        const salt = 'auth_salt';
        
        if (!authToken) {
            return res.status(401).send('Unauthorized');
        }
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(appSecret, salt, 100000, 32, 'sha256', (err, derivedKey) => {
            if (err) {
                return res.status(500).send('Authentication error');
            }
            
            // Verify authToken using derivedKey
            req.authenticated = true;
            next();
        });
    };
    
    app.get('/protected-resource', authenticateUser, (req, res) => {
        res.send('Protected data');
    });
}
// {/fact}

// Example 10: Using SHA512 with PBKDF2 in a database encryption function
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_10() {
    app.post('/store-sensitive-data', (req, res) => {
        const userData = req.body.data;
        const encryptionPassword = req.body.encryptionKey;
        const salt = crypto.randomBytes(16);
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        const encryptionKey = crypto.pbkdf2Sync(encryptionPassword, salt, 100000, 32, 'sha512');
        
        // Encrypt userData with encryptionKey
        const encryptedData = 'encrypted_data_using_derived_key';
        
        // Store encryptedData in database
        res.send('Data stored securely');
    });
}
// {/fact}

// Example 11: Using SHA256 with PBKDF2 for generating a cache key
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_11() {
    app.get('/cached-data', (req, res) => {
        const userId = req.query.userId;
        const dataId = req.query.dataId;
        const salt = 'cache_salt';
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(userId + dataId, salt, 10000, 16, 'sha256', (err, derivedKey) => {
            if (err) {
                return res.status(500).send('Error generating cache key');
            }
            
            const cacheKey = derivedKey.toString('hex');
            // Use cacheKey to retrieve or store cached data
            res.json({ data: 'Cached data for ' + cacheKey });
        });
    });
}
// {/fact}

// Example 12: Using SHA384 with PBKDF2 in a webhook signature verification
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_12() {
    app.post('/webhook', (req, res) => {
        const payload = req.body;
        const signature = req.headers['x-signature'];
        const webhookSecret = 'webhook_secret_key';
        const salt = 'webhook_salt';
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        const signingKey = crypto.pbkdf2Sync(webhookSecret, salt, 50000, 32, 'sha384');
        
        // Verify webhook signature using signingKey
        const isValid = true; // Simplified for example
        
        if (isValid) {
            res.send('Webhook processed');
        } else {
            res.status(401).send('Invalid signature');
        }
    });
}
// {/fact}

// Example 13: Using SHA512 with PBKDF2 in a session token generator
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_13() {
    app.post('/create-session', (req, res) => {
        const username = req.body.username;
        const sessionData = JSON.stringify({
            username,
            created: Date.now()
        });
        const salt = crypto.randomBytes(16);
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(sessionData, salt, 100000, 32, 'sha512', (err, sessionKey) => {
            if (err) {
                return res.status(500).send('Session creation failed');
            }
            
            const sessionToken = sessionKey.toString('base64');
            res.json({ sessionToken });
        });
    });
}
// {/fact}

// Example 14: Using SHA256 with PBKDF2 for file checksum verification
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_14() {
    app.post('/verify-file', (req, res) => {
        const fileContent = req.body.content;
        const userProvidedChecksum = req.body.checksum;
        const salt = 'file_verification_salt';
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        const calculatedChecksum = crypto.pbkdf2Sync(fileContent, salt, 10000, 32, 'sha256');
        
        if (calculatedChecksum.toString('hex') === userProvidedChecksum) {
            res.send('File verification successful');
        } else {
            res.status(400).send('File verification failed');
        }
    });
}
// {/fact}

// Example 15: Using SHA384 with PBKDF2 in a multi-factor authentication code generator
// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_15() {
    app.post('/generate-mfa-code', (req, res) => {
        const userId = req.body.userId;
        const timestamp = Math.floor(Date.now() / 30000); // 30-second window
        const salt = userId + '_mfa_salt';
        
        // ok: javascript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(timestamp.toString(), salt, 50000, 16, 'sha384', (err, derivedKey) => {
            if (err) {
                return res.status(500).send('MFA code generation failed');
            }
            
            // Convert to 6-digit code
            const code = parseInt(derivedKey.toString('hex'), 16) % 1000000;
            res.json({ code: code.toString().padStart(6, '0') });
        });
    });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});