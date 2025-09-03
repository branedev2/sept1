// Imports for JWT functionality
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();
require('dotenv').config();

// TRUE POSITIVES - Vulnerable code that should be detected

// Bad case 1: Simple hardcoded JWT secret in token generation
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_1() {
  const payload = { userId: 123, role: 'admin' };
  // ruleid: javascript-jwt-secret-hardcoded
  const token = jwt.sign(payload, 'my_super_secret_key_123', { expiresIn: '1h' });
  return token;
}
// {/fact}

// Bad case 2: Hardcoded JWT secret in token verification
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_2(req, res) {
  const token = req.headers.authorization.split(' ')[1];
  try {
    // ruleid: javascript-jwt-secret-hardcoded
    const decoded = jwt.verify(token, 'secret_jwt_key_for_auth');
    res.json({ success: true, data: decoded });
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
}
// {/fact}

// Bad case 3: Hardcoded JWT secret in a constant variable
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_3() {
  const SECRET_KEY = 'hardcoded_jwt_secret_key_12345';
  const userData = { id: 456, username: 'user123' };
  
  // ruleid: javascript-jwt-secret-hardcoded
  const token = jwt.sign(userData, SECRET_KEY, { algorithm: 'HS256' });
  return { token };
}
// {/fact}

// Bad case 4: Hardcoded JWT secret in an object configuration
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_4() {
  const config = {
    database: 'userdb',
    port: 5432,
    jwtSecret: 'jwt_secret_key_in_config_object'
  };
  
  const userInfo = { id: 789, permissions: ['read', 'write'] };
  // ruleid: javascript-jwt-secret-hardcoded
  return jwt.sign(userInfo, config.jwtSecret, { expiresIn: '2h' });
}
// {/fact}

// Bad case 5: Hardcoded JWT secret in token refresh function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_5(oldToken) {
  try {
    // ruleid: javascript-jwt-secret-hardcoded
    const decoded = jwt.verify(oldToken, 'refresh_jwt_secret_key');
    const newToken = jwt.sign(
      { userId: decoded.userId },
      'refresh_jwt_secret_key',
      { expiresIn: '1h' }
    );
    return { token: newToken };
  } catch (error) {
    throw new Error('Invalid token');
  }
}
// {/fact}

// Bad case 6: Hardcoded JWT secret with string concatenation
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_6() {
  const part1 = 'secret';
  const part2 = '_key_';
  const part3 = 'for_jwt';
  
  const payload = { userId: 101, email: 'user@example.com' };
  // ruleid: javascript-jwt-secret-hardcoded
  const token = jwt.sign(payload, part1 + part2 + part3);
  return token;
}
// {/fact}

// Bad case 7: Hardcoded JWT secret in middleware function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_7() {
  return function(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      // ruleid: javascript-jwt-secret-hardcoded
      const decoded = jwt.verify(token, 'middleware_jwt_secret_key');
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  };
}
// {/fact}

// Bad case 8: Hardcoded JWT secret with template literals
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_8() {
  const secretPrefix = 'jwt';
  const secretSuffix = '2023';
  
  const userData = { id: 202, role: 'editor' };
  // ruleid: javascript-jwt-secret-hardcoded
  const token = jwt.sign(userData, `${secretPrefix}_secret_key_${secretSuffix}`);
  return token;
}
// {/fact}

// Bad case 9: Hardcoded JWT secret in class method
class AuthService {
  generateToken(user) {
    // ruleid: javascript-jwt-secret-hardcoded
    return jwt.sign(user, 'class_method_jwt_secret', { expiresIn: '24h' });
  }
}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_9() {
  const authService = new AuthService();
  return authService.generateToken({ id: 303, name: 'John Doe' });
}
// {/fact}

// Bad case 10: Hardcoded JWT secret in an arrow function
const bad_case_10 = () => {
  const userPayload = { id: 404, permissions: ['admin'] };
  // ruleid: javascript-jwt-secret-hardcoded
  const token = jwt.sign(userPayload, 'arrow_function_jwt_secret');
  return { token, expiresIn: 3600 };
};

// Bad case 11: Hardcoded JWT secret in a switch statement
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_11(tokenType) {
  const payload = { userId: 505, timestamp: Date.now() };
  let token;
  
  switch(tokenType) {
    case 'access':
      // ruleid: javascript-jwt-secret-hardcoded
      token = jwt.sign(payload, 'access_token_secret_key', { expiresIn: '15m' });
      break;
    case 'refresh':
      // ruleid: javascript-jwt-secret-hardcoded
      token = jwt.sign(payload, 'refresh_token_secret_key', { expiresIn: '7d' });
      break;
    default:
      // ruleid: javascript-jwt-secret-hardcoded
      token = jwt.sign(payload, 'default_token_secret_key', { expiresIn: '1h' });
  }
  
  return token;
}
// {/fact}

// Bad case 12: Hardcoded JWT secret with conditional logic
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_12(isAdmin) {
  const payload = { userId: 606, timestamp: Date.now() };
  let secretKey;
  
  if (isAdmin) {
    secretKey = 'admin_jwt_secret_key';
  } else {
    secretKey = 'user_jwt_secret_key';
  }
  
  // ruleid: javascript-jwt-secret-hardcoded
  return jwt.sign(payload, secretKey, { expiresIn: '2h' });
}
// {/fact}

// Bad case 13: Hardcoded JWT secret in async function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
async function bad_case_13() {
  const userData = await fetchUserData(); // Assume this function exists
  
  // ruleid: javascript-jwt-secret-hardcoded
  const token = jwt.sign(userData, 'async_function_jwt_secret');
  return token;
}
// {/fact}

// Bad case 14: Hardcoded JWT secret in a function that handles API authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_14(apiKey) {
  if (!validateApiKey(apiKey)) { // Assume this function exists
    throw new Error('Invalid API key');
  }
  
  const payload = { apiAccess: true, timestamp: Date.now() };
  // ruleid: javascript-jwt-secret-hardcoded
  const token = jwt.sign(payload, 'api_authentication_secret');
  return token;
}
// {/fact}

// Bad case 15: Hardcoded JWT secret in a function with multiple secrets
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_15(tokenPurpose) {
  const secrets = {
    auth: 'auth_secret_key_123',
    payment: 'payment_secret_key_456',
    notification: 'notification_secret_key_789'
  };
  
  const payload = { purpose: tokenPurpose, timestamp: Date.now() };
  // ruleid: javascript-jwt-secret-hardcoded
  return jwt.sign(payload, secrets[tokenPurpose] || 'default_secret_key');
}
// {/fact}

// TRUE NEGATIVES - Secure code that should not be detected

// Good case 1: JWT secret loaded from environment variable
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_1() {
  const payload = { userId: 123, role: 'admin' };
  // ok: javascript-jwt-secret-hardcoded
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
  return token;
}
// {/fact}

// Good case 2: JWT secret from environment variable in token verification
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_2(req, res) {
  const token = req.headers.authorization.split(' ')[1];
  try {
    // ok: javascript-jwt-secret-hardcoded
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    res.json({ success: true, data: decoded });
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
}
// {/fact}

// Good case 3: JWT secret from environment variable stored in a constant
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_3() {
  // ok: javascript-jwt-secret-hardcoded
  const SECRET_KEY = process.env.JWT_SECRET_KEY;
  const userData = { id: 456, username: 'user123' };
  
  const token = jwt.sign(userData, SECRET_KEY, { algorithm: 'HS256' });
  return { token };
}
// {/fact}

// Good case 4: JWT secret from environment variable in an object configuration
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_4() {
  const config = {
    database: 'userdb',
    port: 5432,
    // ok: javascript-jwt-secret-hardcoded
    jwtSecret: process.env.JWT_CONFIG_SECRET
  };
  
  const userInfo = { id: 789, permissions: ['read', 'write'] };
  return jwt.sign(userInfo, config.jwtSecret, { expiresIn: '2h' });
}
// {/fact}

// Good case 5: JWT secret from environment variable in token refresh function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_5(oldToken) {
  try {
    // ok: javascript-jwt-secret-hardcoded
    const refreshSecret = process.env.JWT_REFRESH_SECRET;
    const decoded = jwt.verify(oldToken, refreshSecret);
    const newToken = jwt.sign(
      { userId: decoded.userId },
      refreshSecret,
      { expiresIn: '1h' }
    );
    return { token: newToken };
  } catch (error) {
    throw new Error('Invalid token');
  }
}
// {/fact}

// Good case 6: JWT secret from a secure key management service
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_6() {
  // ok: javascript-jwt-secret-hardcoded
  const secretKey = getSecretFromKeyVault('jwt-signing-key'); // Assume this function securely retrieves the key
  const payload = { userId: 101, email: 'user@example.com' };
  
  const token = jwt.sign(payload, secretKey);
  return token;
}
// {/fact}

// Good case 7: JWT secret from environment variable in middleware function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_7() {
  return function(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      // ok: javascript-jwt-secret-hardcoded
      const decoded = jwt.verify(token, process.env.JWT_MIDDLEWARE_SECRET);
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  };
}
// {/fact}

// Good case 8: JWT secret from configuration file that loads from environment
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_8() {
  // Assume this imports a config that loads secrets from environment variables
  const config = require('../config/auth.config');
  
  const userData = { id: 202, role: 'editor' };
  // ok: javascript-jwt-secret-hardcoded
  const token = jwt.sign(userData, config.jwtSecret);
  return token;
}
// {/fact}

// Good case 9: JWT secret from environment variable in class method
class SecureAuthService {
  generateToken(user) {
    // ok: javascript-jwt-secret-hardcoded
    return jwt.sign(user, process.env.JWT_CLASS_SECRET, { expiresIn: '24h' });
  }
}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_9() {
  const authService = new SecureAuthService();
  return authService.generateToken({ id: 303, name: 'John Doe' });
}
// {/fact}

// Good case 10: JWT secret from environment variable in an arrow function
const good_case_10 = () => {
  const userPayload = { id: 404, permissions: ['admin'] };
  // ok: javascript-jwt-secret-hardcoded
  const token = jwt.sign(userPayload, process.env.JWT_ARROW_SECRET);
  return { token, expiresIn: 3600 };
};

// Good case 11: JWT secret from environment variable in a switch statement
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_11(tokenType) {
  const payload = { userId: 505, timestamp: Date.now() };
  let token;
  
  switch(tokenType) {
    case 'access':
      // ok: javascript-jwt-secret-hardcoded
      token = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
      break;
    case 'refresh':
      // ok: javascript-jwt-secret-hardcoded
      token = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
      break;
    default:
      // ok: javascript-jwt-secret-hardcoded
      token = jwt.sign(payload, process.env.JWT_DEFAULT_SECRET, { expiresIn: '1h' });
  }
  
  return token;
}
// {/fact}

// Good case 12: JWT secret from environment variable with conditional logic
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_12(isAdmin) {
  const payload = { userId: 606, timestamp: Date.now() };
  let secretKey;
  
  if (isAdmin) {
    // ok: javascript-jwt-secret-hardcoded
    secretKey = process.env.JWT_ADMIN_SECRET;
  } else {
    // ok: javascript-jwt-secret-hardcoded
    secretKey = process.env.JWT_USER_SECRET;
  }
  
  return jwt.sign(payload, secretKey, { expiresIn: '2h' });
}
// {/fact}

// Good case 13: JWT secret from environment variable in async function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
async function good_case_13() {
  const userData = await fetchUserData(); // Assume this function exists
  
  // ok: javascript-jwt-secret-hardcoded
  const secret = await loadSecretFromSecureStore(); // Assume this securely loads the secret
  const token = jwt.sign(userData, secret);
  return token;
}
// {/fact}

// Good case 14: JWT secret from environment variable for API authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_14(apiKey) {
  if (!validateApiKey(apiKey)) { // Assume this function exists
    throw new Error('Invalid API key');
  }
  
  const payload = { apiAccess: true, timestamp: Date.now() };
  // ok: javascript-jwt-secret-hardcoded
  const token = jwt.sign(payload, process.env.API_JWT_SECRET);
  return token;
}
// {/fact}

// Good case 15: JWT secret from environment variables in a function with multiple secrets
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_15(tokenPurpose) {
  // ok: javascript-jwt-secret-hardcoded
  const secrets = {
    auth: process.env.AUTH_JWT_SECRET,
    payment: process.env.PAYMENT_JWT_SECRET,
    notification: process.env.NOTIFICATION_JWT_SECRET
  };
  
  const payload = { purpose: tokenPurpose, timestamp: Date.now() };
  return jwt.sign(payload, secrets[tokenPurpose] || process.env.DEFAULT_JWT_SECRET);
}
// {/fact}

// Helper functions to make the examples work
function validateApiKey(key) {
  return key === 'valid-api-key';
}

async function fetchUserData() {
  return { id: 707, name: 'Test User' };
}

async function loadSecretFromSecureStore() {
  return process.env.SECURE_JWT_SECRET;
}

function getSecretFromKeyVault(keyName) {
  // In a real application, this would interact with a secure key vault service
  return process.env[keyName.toUpperCase().replace(/-/g, '_')];
}

// Express server setup
app.use(express.json());

// Example endpoint using JWT
app.post('/login', (req, res) => {
  // Authentication logic would go here
  const token = good_case_1();
  res.json({ token });
});

// Start server if this is the main module
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};