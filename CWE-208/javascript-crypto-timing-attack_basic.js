// File: timing_attack_test_cases.js

const crypto = require('crypto');
const express = require('express');
const secureCompare = require('secure-compare');
const app = express();
app.use(express.json());

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
    const storedPassword = 'supersecretpassword123';
    app.post('/login', (req, res) => {
        const userPassword = req.body.password;
        
        // ruleid: javascript-crypto-timing-attack
        if (userPassword === storedPassword) {
            res.json({ success: true });
        } else {
            res.status(401).json({ success: false });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
    const apiKey = process.env.API_KEY || 'default-key-12345';
    app.get('/api/data', (req, res) => {
        const providedKey = req.headers['x-api-key'];
        
        // ruleid: javascript-crypto-timing-attack
        if (providedKey == apiKey) {
            return res.json({ data: 'sensitive data' });
        }
        res.status(403).json({ error: 'Unauthorized' });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
    const tokens = new Map();
    tokens.set('user1', 'token123456789');
    
    app.get('/verify', (req, res) => {
        const userId = req.query.user;
        const userToken = req.query.token;
        const storedToken = tokens.get(userId);
        
        // ruleid: javascript-crypto-timing-attack
        const isValid = userToken === storedToken;
        
        if (isValid) {
            res.json({ verified: true });
        } else {
            res.status(401).json({ verified: false });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
    const secretHash = 'a1b2c3d4e5f6g7h8i9j0';
    
    app.post('/verify-hash', (req, res) => {
        const clientHash = req.body.hash;
        let isValid = true;
        
        // ruleid: javascript-crypto-timing-attack
        if (clientHash !== secretHash) {
            isValid = false;
        }
        
        res.json({ valid: isValid });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
    const sessionSecrets = ['abc123', 'def456', 'ghi789'];
    
    app.get('/session', (req, res) => {
        const sessionToken = req.headers.authorization;
        let validSession = false;
        
        for (const secret of sessionSecrets) {
            // ruleid: javascript-crypto-timing-attack
            if (sessionToken === secret) {
                validSession = true;
                break;
            }
        }
        
        res.json({ valid: validSession });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
    const dbCredentials = {
        username: 'admin',
        password: 'db_password_123'
    };
    
    app.post('/database-login', (req, res) => {
        const { username, password } = req.body;
        
        // ruleid: javascript-crypto-timing-attack
        if (username === dbCredentials.username && password === dbCredentials.password) {
            res.json({ access: 'granted' });
        } else {
            res.status(401).json({ access: 'denied' });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
    const encryptionKey = 'encryption_key_12345';
    
    function verifyKey(providedKey) {
        // ruleid: javascript-crypto-timing-attack
        return providedKey == encryptionKey;
    }
    
    app.post('/encrypt', (req, res) => {
        if (verifyKey(req.body.key)) {
            res.json({ result: 'encrypted_data' });
        } else {
            res.status(403).json({ error: 'Invalid key' });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
    const oauthTokens = new Map();
    oauthTokens.set('client1', 'oauth_token_abc123');
    
    app.get('/oauth/validate', (req, res) => {
        const clientId = req.query.client_id;
        const token = req.query.token;
        
        // ruleid: javascript-crypto-timing-attack
        const isValidToken = token === oauthTokens.get(clientId);
        
        res.json({ valid: isValidToken });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
    const webhookSecret = 'webhook_secret_key_789';
    
    app.post('/webhook', (req, res) => {
        const signature = req.headers['x-signature'];
        
        // ruleid: javascript-crypto-timing-attack
        if (signature !== webhookSecret) {
            return res.status(403).json({ error: 'Invalid signature' });
        }
        
        // Process webhook
        res.json({ status: 'processed' });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
    const twoFactorSecrets = {
        'user123': 'totp_seed_456',
        'user456': 'totp_seed_789'
    };
    
    app.post('/verify-2fa', (req, res) => {
        const { userId, totpCode } = req.body;
        const expectedCode = generateTOTP(twoFactorSecrets[userId]);
        
        // ruleid: javascript-crypto-timing-attack
        if (totpCode === expectedCode) {
            res.json({ verified: true });
        } else {
            res.status(401).json({ verified: false });
        }
    });
    
    function generateTOTP(seed) {
        // Simplified TOTP generation for example
        return seed.substring(0, 6);
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
    const jwtSecret = 'jwt_signing_secret_key';
    
    app.get('/jwt/verify', (req, res) => {
        const token = req.headers.authorization?.split(' ')[1];
        const decodedToken = decodeJWT(token);
        
        // ruleid: javascript-crypto-timing-attack
        if (decodedToken.signature == calculateSignature(decodedToken.payload, jwtSecret)) {
            res.json({ valid: true, payload: decodedToken.payload });
        } else {
            res.status(401).json({ valid: false });
        }
    });
    
    function decodeJWT(token) {
        // Simplified JWT decoding for example
        return { payload: {}, signature: 'signature' };
    }
    
    function calculateSignature(payload, secret) {
        // Simplified signature calculation
        return 'calculated_signature';
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
    const recoveryTokens = new Map();
    recoveryTokens.set('user@example.com', 'recovery_token_12345');
    
    app.post('/password-reset', (req, res) => {
        const { email, token, newPassword } = req.body;
        const storedToken = recoveryTokens.get(email);
        
        // ruleid: javascript-crypto-timing-attack
        if (token !== storedToken) {
            return res.status(400).json({ error: 'Invalid token' });
        }
        
        // Reset password logic would go here
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
    const apiSecrets = {
        'service1': 'api_secret_abc',
        'service2': 'api_secret_def'
    };
    
    app.post('/internal-api', (req, res) => {
        const { service, secret } = req.body;
        
        // ruleid: javascript-crypto-timing-attack
        const isAuthorized = apiSecrets[service] === secret;
        
        if (isAuthorized) {
            res.json({ data: 'internal api data' });
        } else {
            res.status(403).json({ error: 'Unauthorized' });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
    const hmacKey = 'hmac_key_for_verification';
    
    app.post('/verify-signature', (req, res) => {
        const { data, signature } = req.body;
        const calculatedSignature = calculateHMAC(data, hmacKey);
        
        // ruleid: javascript-crypto-timing-attack
        if (signature === calculatedSignature) {
            res.json({ verified: true });
        } else {
            res.status(400).json({ verified: false });
        }
    });
    
    function calculateHMAC(data, key) {
        // Simplified HMAC calculation for example
        return 'calculated_hmac_signature';
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
    const encryptedCredentials = {
        'user1': { salt: 'salt1', hash: 'hashed_password_1' },
        'user2': { salt: 'salt2', hash: 'hashed_password_2' }
    };
    
    app.post('/authenticate', (req, res) => {
        const { username, password } = req.body;
        const userCreds = encryptedCredentials[username];
        
        if (!userCreds) {
            return res.status(401).json({ authenticated: false });
        }
        
        const hashedPassword = hashPassword(password, userCreds.salt);
        
        // ruleid: javascript-crypto-timing-attack
        if (hashedPassword === userCreds.hash) {
            res.json({ authenticated: true });
        } else {
            res.status(401).json({ authenticated: false });
        }
    });
    
    function hashPassword(password, salt) {
        // Simplified password hashing for example
        return 'hashed_' + password + '_' + salt;
    }
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
    const storedPassword = 'supersecretpassword123';
    app.post('/login', (req, res) => {
        const userPassword = req.body.password;
        
        // ok: javascript-crypto-timing-attack
        if (crypto.timingSafeEqual(Buffer.from(userPassword), Buffer.from(storedPassword))) {
            res.json({ success: true });
        } else {
            res.status(401).json({ success: false });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
    const apiKey = process.env.API_KEY || 'default-key-12345';
    app.get('/api/data', (req, res) => {
        const providedKey = req.headers['x-api-key'];
        
        // ok: javascript-crypto-timing-attack
        try {
            const areEqual = crypto.timingSafeEqual(
                Buffer.from(providedKey || ''),
                Buffer.from(apiKey)
            );
            if (areEqual) {
                return res.json({ data: 'sensitive data' });
            }
        } catch (err) {
            // Handle potential errors from timingSafeEqual
        }
        
        res.status(403).json({ error: 'Unauthorized' });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
    const tokens = new Map();
    tokens.set('user1', 'token123456789');
    const secureCompare = require('secure-compare');
    
    app.get('/verify', (req, res) => {
        const userId = req.query.user;
        const userToken = req.query.token;
        const storedToken = tokens.get(userId);
        
        // ok: javascript-crypto-timing-attack
        const isValid = secureCompare(userToken, storedToken);
        
        if (isValid) {
            res.json({ verified: true });
        } else {
            res.status(401).json({ verified: false });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
    const secretHash = 'a1b2c3d4e5f6g7h8i9j0';
    
    app.post('/verify-hash', (req, res) => {
        const clientHash = req.body.hash;
        
        // ok: javascript-crypto-timing-attack
        const isValid = crypto.timingSafeEqual(
            Buffer.from(clientHash || ''),
            Buffer.from(secretHash)
        );
        
        res.json({ valid: isValid });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
    const sessionSecrets = ['abc123', 'def456', 'ghi789'];
    
    app.get('/session', (req, res) => {
        const sessionToken = req.headers.authorization;
        let validSession = false;
        
        for (const secret of sessionSecrets) {
            // ok: javascript-crypto-timing-attack
            try {
                if (crypto.timingSafeEqual(
                    Buffer.from(sessionToken || ''),
                    Buffer.from(secret)
                )) {
                    validSession = true;
                    break;
                }
            } catch (err) {
                // Handle potential errors
            }
        }
        
        res.json({ valid: validSession });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
    const dbCredentials = {
        username: 'admin',
        password: 'db_password_123'
    };
    
    app.post('/database-login', (req, res) => {
        const { username, password } = req.body;
        
        // First check if username matches (username is not timing-sensitive)
        if (username !== dbCredentials.username) {
            return res.status(401).json({ access: 'denied' });
        }
        
        // ok: javascript-crypto-timing-attack
        try {
            const passwordsMatch = crypto.timingSafeEqual(
                Buffer.from(password || ''),
                Buffer.from(dbCredentials.password)
            );
            
            if (passwordsMatch) {
                res.json({ access: 'granted' });
            } else {
                res.status(401).json({ access: 'denied' });
            }
        } catch (err) {
            res.status(401).json({ access: 'denied' });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
    const encryptionKey = 'encryption_key_12345';
    
    function verifyKey(providedKey) {
        // ok: javascript-crypto-timing-attack
        try {
            return crypto.timingSafeEqual(
                Buffer.from(providedKey || ''),
                Buffer.from(encryptionKey)
            );
        } catch (err) {
            return false;
        }
    }
    
    app.post('/encrypt', (req, res) => {
        if (verifyKey(req.body.key)) {
            res.json({ result: 'encrypted_data' });
        } else {
            res.status(403).json({ error: 'Invalid key' });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
    const oauthTokens = new Map();
    oauthTokens.set('client1', 'oauth_token_abc123');
    
    app.get('/oauth/validate', (req, res) => {
        const clientId = req.query.client_id;
        const token = req.query.token;
        const storedToken = oauthTokens.get(clientId);
        
        if (!storedToken) {
            return res.json({ valid: false });
        }
        
        // ok: javascript-crypto-timing-attack
        let isValidToken = false;
        try {
            isValidToken = crypto.timingSafeEqual(
                Buffer.from(token || ''),
                Buffer.from(storedToken)
            );
        } catch (err) {
            // Handle potential errors
        }
        
        res.json({ valid: isValidToken });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
    const webhookSecret = 'webhook_secret_key_789';
    
    app.post('/webhook', (req, res) => {
        const signature = req.headers['x-signature'];
        
        // ok: javascript-crypto-timing-attack
        let isValid = false;
        try {
            isValid = crypto.timingSafeEqual(
                Buffer.from(signature || ''),
                Buffer.from(webhookSecret)
            );
        } catch (err) {
            return res.status(403).json({ error: 'Invalid signature' });
        }
        
        if (!isValid) {
            return res.status(403).json({ error: 'Invalid signature' });
        }
        
        // Process webhook
        res.json({ status: 'processed' });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
    const twoFactorSecrets = {
        'user123': 'totp_seed_456',
        'user456': 'totp_seed_789'
    };
    
    app.post('/verify-2fa', (req, res) => {
        const { userId, totpCode } = req.body;
        const expectedCode = generateTOTP(twoFactorSecrets[userId]);
        
        // ok: javascript-crypto-timing-attack
        let verified = false;
        try {
            verified = crypto.timingSafeEqual(
                Buffer.from(totpCode || ''),
                Buffer.from(expectedCode)
            );
        } catch (err) {
            // Handle potential errors
        }
        
        if (verified) {
            res.json({ verified: true });
        } else {
            res.status(401).json({ verified: false });
        }
    });
    
    function generateTOTP(seed) {
        // Simplified TOTP generation for example
        return seed.substring(0, 6);
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
    const jwtSecret = 'jwt_signing_secret_key';
    
    app.get('/jwt/verify', (req, res) => {
        const token = req.headers.authorization?.split(' ')[1];
        const decodedToken = decodeJWT(token);
        const calculatedSignature = calculateSignature(decodedToken.payload, jwtSecret);
        
        // ok: javascript-crypto-timing-attack
        let isValid = false;
        try {
            isValid = crypto.timingSafeEqual(
                Buffer.from(decodedToken.signature || ''),
                Buffer.from(calculatedSignature)
            );
        } catch (err) {
            return res.status(401).json({ valid: false });
        }
        
        if (isValid) {
            res.json({ valid: true, payload: decodedToken.payload });
        } else {
            res.status(401).json({ valid: false });
        }
    });
    
    function decodeJWT(token) {
        // Simplified JWT decoding for example
        return { payload: {}, signature: 'signature' };
    }
    
    function calculateSignature(payload, secret) {
        // Simplified signature calculation
        return 'calculated_signature';
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
    const recoveryTokens = new Map();
    recoveryTokens.set('user@example.com', 'recovery_token_12345');
    
    app.post('/password-reset', (req, res) => {
        const { email, token, newPassword } = req.body;
        const storedToken = recoveryTokens.get(email);
        
        if (!storedToken) {
            return res.status(400).json({ error: 'Invalid token' });
        }
        
        // ok: javascript-crypto-timing-attack
        let isValid = false;
        try {
            isValid = crypto.timingSafeEqual(
                Buffer.from(token || ''),
                Buffer.from(storedToken)
            );
        } catch (err) {
            return res.status(400).json({ error: 'Invalid token' });
        }
        
        if (!isValid) {
            return res.status(400).json({ error: 'Invalid token' });
        }
        
        // Reset password logic would go here
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
    const apiSecrets = {
        'service1': 'api_secret_abc',
        'service2': 'api_secret_def'
    };
    
    app.post('/internal-api', (req, res) => {
        const { service, secret } = req.body;
        const storedSecret = apiSecrets[service];
        
        if (!storedSecret) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        // ok: javascript-crypto-timing-attack
        let isAuthorized = false;
        try {
            isAuthorized = secureCompare(secret, storedSecret);
        } catch (err) {
            // Handle potential errors
        }
        
        if (isAuthorized) {
            res.json({ data: 'internal api data' });
        } else {
            res.status(403).json({ error: 'Unauthorized' });
        }
    });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
    const hmacKey = 'hmac_key_for_verification';
    
    app.post('/verify-signature', (req, res) => {
        const { data, signature } = req.body;
        const calculatedSignature = calculateHMAC(data, hmacKey);
        
        // ok: javascript-crypto-timing-attack
        let verified = false;
        try {
            verified = crypto.timingSafeEqual(
                Buffer.from(signature || ''),
                Buffer.from(calculatedSignature)
            );
        } catch (err) {
            return res.status(400).json({ verified: false });
        }
        
        res.json({ verified });
    });
    
    function calculateHMAC(data, key) {
        // Simplified HMAC calculation for example
        return 'calculated_hmac_signature';
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
    const encryptedCredentials = {
        'user1': { salt: 'salt1', hash: 'hashed_password_1' },
        'user2': { salt: 'salt2', hash: 'hashed_password_2' }
    };
    
    app.post('/authenticate', (req, res) => {
        const { username, password } = req.body;
        const userCreds = encryptedCredentials[username];
        
        if (!userCreds) {
            return res.status(401).json({ authenticated: false });
        }
        
        const hashedPassword = hashPassword(password, userCreds.salt);
        
        // ok: javascript-crypto-timing-attack
        let authenticated = false;
        try {
            authenticated = crypto.timingSafeEqual(
                Buffer.from(hashedPassword),
                Buffer.from(userCreds.hash)
            );
        } catch (err) {
            // Handle potential errors
        }
        
        if (authenticated) {
            res.json({ authenticated: true });
        } else {
            res.status(401).json({ authenticated: false });
        }
    });
    
    function hashPassword(password, salt) {
        // Simplified password hashing for example
        return 'hashed_' + password + '_' + salt;
    }
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});