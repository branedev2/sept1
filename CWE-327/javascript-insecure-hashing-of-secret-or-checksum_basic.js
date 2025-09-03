// Imports for crypto functionality
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const scrypt = require('scrypt-js');
const fs = require('fs');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Using MD5 to hash a password
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
    const password = "user_password";
    // ruleid: javascript-insecure-hashing-of-secret-or-checksum
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    console.log(`Hashed password: ${hashedPassword}`);
    return hashedPassword;
}
// {/fact}

// Example 2: Using SHA-1 for password storage
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
    app.post('/register', (req, res) => {
        const username = req.body.username;
        const password = req.body.password;
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');
        
        // Store username and hashedPassword in database
        saveUser(username, hashedPassword);
        res.send('User registered successfully');
    });
}
// {/fact}

// Example 3: Using MD5 for file checksum
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
    const fileBuffer = fs.readFileSync('important_file.pdf');
    
    // ruleid: javascript-insecure-hashing-of-secret-or-checksum
    const checksum = crypto.createHash('md5').update(fileBuffer).digest('hex');
    
    console.log(`File checksum: ${checksum}`);
    return checksum;
}
// {/fact}

// Example 4: Using SHA-1 in a verification function
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
    function verifyPassword(storedHash, inputPassword) {
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const inputHash = crypto.createHash('sha1')
                              .update(inputPassword)
                              .digest('hex');
        
        return storedHash === inputHash;
    }
    
    const isValid = verifyPassword('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'password123');
    return isValid;
}
// {/fact}

// Example 5: Using MD5 in an authentication system
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
    app.post('/login', (req, res) => {
        const username = req.body.username;
        const password = req.body.password;
        
        // Get stored hash from database
        const storedHash = getUserHash(username);
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const calculatedHash = crypto.createHash('md5')
                                  .update(password)
                                  .digest('hex');
        
        if (calculatedHash === storedHash) {
            res.send('Login successful');
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
}
// {/fact}

// Example 6: Using SHA-1 for API key verification
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
    function validateApiKey(apiKey, secret) {
        const timestamp = Date.now().toString();
        const dataToHash = apiKey + secret + timestamp;
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const signature = crypto.createHash('sha1')
                             .update(dataToHash)
                             .digest('hex');
        
        return { timestamp, signature };
    }
    
    const result = validateApiKey('api_123456', 'secret_key');
    return result;
}
// {/fact}

// Example 7: Using MD5 in a token generation system
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
    function generateToken(userId, role) {
        const tokenData = `${userId}:${role}:${Date.now()}`;
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const token = crypto.createHash('md5')
                         .update(tokenData)
                         .digest('hex');
        
        return token;
    }
    
    const userToken = generateToken(1001, 'admin');
    return userToken;
}
// {/fact}

// Example 8: Using SHA-1 for file integrity check
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
    app.post('/upload', (req, res) => {
        const fileData = req.body.fileData;
        const providedChecksum = req.body.checksum;
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const calculatedChecksum = crypto.createHash('sha1')
                                     .update(fileData)
                                     .digest('hex');
        
        if (calculatedChecksum === providedChecksum) {
            saveFile(fileData);
            res.send('File uploaded successfully');
        } else {
            res.status(400).send('File integrity check failed');
        }
    });
}
// {/fact}

// Example 9: Using MD5 with salt (still insecure)
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
    function hashPasswordWithSalt(password) {
        const salt = crypto.randomBytes(16).toString('hex');
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const hash = crypto.createHash('md5')
                        .update(password + salt)
                        .digest('hex');
        
        return { salt, hash };
    }
    
    const credentials = hashPasswordWithSalt('user_password');
    return credentials;
}
// {/fact}

// Example 10: Using SHA-1 for password reset token
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
    app.post('/reset-password', (req, res) => {
        const email = req.body.email;
        const user = findUserByEmail(email);
        
        if (user) {
            const timestamp = Date.now();
            const tokenData = `${user.id}:${timestamp}:reset`;
            
            // ruleid: javascript-insecure-hashing-of-secret-or-checksum
            const resetToken = crypto.createHash('sha1')
                                  .update(tokenData)
                                  .digest('hex');
            
            // Send reset token to user's email
            sendResetEmail(email, resetToken);
            res.send('Password reset email sent');
        } else {
            res.status(404).send('User not found');
        }
    });
}
// {/fact}

// Example 11: Using MD5 in a custom authentication middleware
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
    function authMiddleware(req, res, next) {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).send('Authorization required');
        }
        
        const [username, password] = Buffer.from(authHeader.split(' ')[1], 'base64')
                                         .toString()
                                         .split(':');
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const hashedPassword = crypto.createHash('md5')
                                  .update(password)
                                  .digest('hex');
        
        const user = authenticateUser(username, hashedPassword);
        if (user) {
            req.user = user;
            next();
        } else {
            res.status(401).send('Invalid credentials');
        }
    }
    
    app.use('/secure', authMiddleware);
}
// {/fact}

// Example 12: Using SHA-1 for session token generation
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
    function createSession(userId) {
        const sessionData = `${userId}:${Date.now()}:${Math.random()}`;
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const sessionToken = crypto.createHash('sha1')
                                .update(sessionData)
                                .digest('hex');
        
        // Store session in database
        saveSession(sessionToken, userId);
        return sessionToken;
    }
    
    const token = createSession(1234);
    return token;
}
// {/fact}

// Example 13: Using MD5 for data integrity verification
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
    function verifyDataIntegrity(data, providedHash) {
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const calculatedHash = crypto.createHash('md5')
                                  .update(JSON.stringify(data))
                                  .digest('hex');
        
        return calculatedHash === providedHash;
    }
    
    const data = { id: 123, name: 'John Doe', role: 'user' };
    const isValid = verifyDataIntegrity(data, '5d41402abc4b2a76b9719d911017c592');
    return isValid;
}
// {/fact}

// Example 14: Using SHA-1 for webhook signature verification
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
    app.post('/webhook', (req, res) => {
        const payload = req.body;
        const signature = req.headers['x-signature'];
        const webhookSecret = getWebhookSecret();
        
        // ruleid: javascript-insecure-hashing-of-secret-or-checksum
        const expectedSignature = crypto.createHash('sha1')
                                     .update(JSON.stringify(payload) + webhookSecret)
                                     .digest('hex');
        
        if (signature === expectedSignature) {
            processWebhook(payload);
            res.send('Webhook processed');
        } else {
            res.status(401).send('Invalid signature');
        }
    });
}
// {/fact}

// Example 15: Using MD5 for generating download links
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
    app.get('/download/:fileId', (req, res) => {
        const fileId = req.params.fileId;
        const file = getFileById(fileId);
        
        if (file) {
            const timestamp = Date.now();
            const expiryTime = timestamp + 3600000; // 1 hour
            
            // ruleid: javascript-insecure-hashing-of-secret-or-checksum
            const downloadToken = crypto.createHash('md5')
                                     .update(`${fileId}:${expiryTime}:${file.secretKey}`)
                                     .digest('hex');
            
            const downloadUrl = `/download-file?file=${fileId}&token=${downloadToken}&expires=${expiryTime}`;
            res.json({ downloadUrl });
        } else {
            res.status(404).send('File not found');
        }
    });
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// Example 1: Using SHA-256 for password hashing
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
    const password = "user_password";
    // ok: javascript-insecure-hashing-of-secret-or-checksum
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    console.log(`Hashed password: ${hashedPassword}`);
    return hashedPassword;
}
// {/fact}

// Example 2: Using bcrypt for password storage
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
    app.post('/register', async (req, res) => {
        const username = req.body.username;
        const password = req.body.password;
        
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Store username and hashedPassword in database
        saveUser(username, hashedPassword);
        res.send('User registered successfully');
    });
}
// {/fact}

// Example 3: Using SHA-512 for file checksum
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
    const fileBuffer = fs.readFileSync('important_file.pdf');
    
    // ok: javascript-insecure-hashing-of-secret-or-checksum
    const checksum = crypto.createHash('sha512').update(fileBuffer).digest('hex');
    
    console.log(`File checksum: ${checksum}`);
    return checksum;
}
// {/fact}

// Example 4: Using bcrypt for password verification
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
    async function verifyPassword(storedHash, inputPassword) {
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const isMatch = await bcrypt.compare(inputPassword, storedHash);
        return isMatch;
    }
    
    const isValid = verifyPassword('$2b$10$X/aEr7Brp5AYMdj5/lmtZ.UOHVzH6WjA9xOK9paL4Uq7JDIXb3ifi', 'password123');
    return isValid;
}
// {/fact}

// Example 5: Using SHA-384 in an authentication system
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
    app.post('/login', (req, res) => {
        const username = req.body.username;
        const password = req.body.password;
        
        // Get stored hash from database
        const storedHash = getUserHash(username);
        
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const calculatedHash = crypto.createHash('sha384')
                                  .update(password)
                                  .digest('hex');
        
        if (calculatedHash === storedHash) {
            res.send('Login successful');
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
}
// {/fact}

// Example 6: Using HMAC-SHA256 for API key verification
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
    function validateApiKey(apiKey, secret) {
        const timestamp = Date.now().toString();
        
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const signature = crypto.createHmac('sha256', secret)
                             .update(apiKey + timestamp)
                             .digest('hex');
        
        return { timestamp, signature };
    }
    
    const result = validateApiKey('api_123456', 'secret_key');
    return result;
}
// {/fact}

// Example 7: Using scrypt for token generation
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
    async function generateToken(userId, role) {
        const tokenData = `${userId}:${role}:${Date.now()}`;
        const salt = crypto.randomBytes(16);
        const keyLen = 64;
        
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const N = 16384, r = 8, p = 1;
        const tokenBuffer = Buffer.from(tokenData);
        const derivedKey = await new Promise((resolve, reject) => {
            crypto.scrypt(tokenBuffer, salt, keyLen, { N, r, p }, (err, key) => {
                if (err) reject(err);
                else resolve(key);
            });
        });
        
        return derivedKey.toString('hex');
    }
    
    const userToken = generateToken(1001, 'admin');
    return userToken;
}
// {/fact}

// Example 8: Using SHA-256 for file integrity check
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
    app.post('/upload', (req, res) => {
        const fileData = req.body.fileData;
        const providedChecksum = req.body.checksum;
        
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const calculatedChecksum = crypto.createHash('sha256')
                                     .update(fileData)
                                     .digest('hex');
        
        if (calculatedChecksum === providedChecksum) {
            saveFile(fileData);
            res.send('File uploaded successfully');
        } else {
            res.status(400).send('File integrity check failed');
        }
    });
}
// {/fact}

// Example 9: Using PBKDF2 for password hashing
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
    function hashPasswordWithPBKDF2(password) {
        const salt = crypto.randomBytes(16);
        
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const derivedKey = crypto.pbkdf2Sync(
            password,
            salt,
            100000, // iterations
            64,     // key length
            'sha512'
        );
        
        return {
            salt: salt.toString('hex'),
            hash: derivedKey.toString('hex')
        };
    }
    
    const credentials = hashPasswordWithPBKDF2('user_password');
    return credentials;
}
// {/fact}

// Example 10: Using SHA-512 for password reset token
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
    app.post('/reset-password', (req, res) => {
        const email = req.body.email;
        const user = findUserByEmail(email);
        
        if (user) {
            const timestamp = Date.now();
            const tokenData = `${user.id}:${timestamp}:reset`;
            
            // ok: javascript-insecure-hashing-of-secret-or-checksum
            const resetToken = crypto.createHash('sha512')
                                  .update(tokenData)
                                  .digest('hex');
            
            // Send reset token to user's email
            sendResetEmail(email, resetToken);
            res.send('Password reset email sent');
        } else {
            res.status(404).send('User not found');
        }
    });
}
// {/fact}

// Example 11: Using bcrypt in a custom authentication middleware
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
    async function authMiddleware(req, res, next) {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).send('Authorization required');
        }
        
        const [username, password] = Buffer.from(authHeader.split(' ')[1], 'base64')
                                         .toString()
                                         .split(':');
        
        const user = await getUserByUsername(username);
        if (user) {
            // ok: javascript-insecure-hashing-of-secret-or-checksum
            const passwordMatch = await bcrypt.compare(password, user.passwordHash);
            
            if (passwordMatch) {
                req.user = user;
                next();
            } else {
                res.status(401).send('Invalid credentials');
            }
        } else {
            res.status(401).send('Invalid credentials');
        }
    }
    
    app.use('/secure', authMiddleware);
}
// {/fact}

// Example 12: Using SHA-256 for session token generation
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
    function createSession(userId) {
        const sessionData = `${userId}:${Date.now()}:${Math.random()}`;
        
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const sessionToken = crypto.createHash('sha256')
                                .update(sessionData)
                                .digest('hex');
        
        // Store session in database
        saveSession(sessionToken, userId);
        return sessionToken;
    }
    
    const token = createSession(1234);
    return token;
}
// {/fact}

// Example 13: Using SHA-512 for data integrity verification
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
    function verifyDataIntegrity(data, providedHash) {
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const calculatedHash = crypto.createHash('sha512')
                                  .update(JSON.stringify(data))
                                  .digest('hex');
        
        return calculatedHash === providedHash;
    }
    
    const data = { id: 123, name: 'John Doe', role: 'user' };
    const isValid = verifyDataIntegrity(data, '5d41402abc4b2a76b9719d911017c592');
    return isValid;
}
// {/fact}

// Example 14: Using HMAC-SHA256 for webhook signature verification
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
    app.post('/webhook', (req, res) => {
        const payload = req.body;
        const signature = req.headers['x-signature'];
        const webhookSecret = getWebhookSecret();
        
        // ok: javascript-insecure-hashing-of-secret-or-checksum
        const expectedSignature = crypto.createHmac('sha256', webhookSecret)
                                     .update(JSON.stringify(payload))
                                     .digest('hex');
        
        if (signature === expectedSignature) {
            processWebhook(payload);
            res.send('Webhook processed');
        } else {
            res.status(401).send('Invalid signature');
        }
    });
}
// {/fact}

// Example 15: Using SHA-256 for generating download links
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
    app.get('/download/:fileId', (req, res) => {
        const fileId = req.params.fileId;
        const file = getFileById(fileId);
        
        if (file) {
            const timestamp = Date.now();
            const expiryTime = timestamp + 3600000; // 1 hour
            
            // ok: javascript-insecure-hashing-of-secret-or-checksum
            const downloadToken = crypto.createHash('sha256')
                                     .update(`${fileId}:${expiryTime}:${file.secretKey}`)
                                     .digest('hex');
            
            const downloadUrl = `/download-file?file=${fileId}&token=${downloadToken}&expires=${expiryTime}`;
            res.json({ downloadUrl });
        } else {
            res.status(404).send('File not found');
        }
    });
}
// {/fact}

// Helper functions to make the examples work
function saveUser(username, password) {
    // Mock function to save user to database
}

function getUserHash(username) {
    // Mock function to get user hash from database
    return 'mock_hash';
}

function saveFile(fileData) {
    // Mock function to save file
}

function getFileById(fileId) {
    // Mock function to get file by ID
    return { id: fileId, name: 'test.pdf', secretKey: 'file_secret' };
}

function findUserByEmail(email) {
    // Mock function to find user by email
    return { id: 123, email: email };
}

function sendResetEmail(email, token) {
    // Mock function to send reset email
}

function getWebhookSecret() {
    // Mock function to get webhook secret
    return 'webhook_secret_key';
}

function processWebhook(payload) {
    // Mock function to process webhook
}

function getUserByUsername(username) {
    // Mock function to get user by username
    return { id: 123, username: username, passwordHash: '$2b$10$X/aEr7Brp5AYMdj5/lmtZ.UOHVzH6WjA9xOK9paL4Uq7JDIXb3ifi' };
}

function authenticateUser(username, hashedPassword) {
    // Mock function to authenticate user
    return { id: 123, username: username };
}

function saveSession(token, userId) {
    // Mock function to save session
}