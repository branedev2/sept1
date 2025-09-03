// File: timing_attack_test_cases.ts
import * as crypto from 'crypto';
import * as express from 'express';
import * as secureCompare from 'secure-compare';

// True Positive Examples (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.post('/login', (req, res) => {
    const storedPassword = 'super_secret_password123';
    const userPassword = req.body.password;
    
    // ruleid: typescript-crypto-timing-attack
    if (userPassword === storedPassword) {
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/verify-api-key', (req, res) => {
    const apiKey = 'api_key_12345';
    const userApiKey = req.headers['x-api-key'] as string;
    
    // ruleid: typescript-crypto-timing-attack
    if (apiKey == userApiKey) {
      res.json({ valid: true });
    } else {
      res.status(403).json({ valid: false });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.post('/verify-token', (req, res) => {
    const secretToken = fetchTokenFromDatabase();
    const userToken = req.body.token;
    
    // ruleid: typescript-crypto-timing-attack
    const isValid = secretToken === userToken;
    
    if (isValid) {
      res.json({ success: true });
    } else {
      res.status(401).json({ success: false });
    }
  });
  
  function fetchTokenFromDatabase(): string {
    return 'secure_token_from_db';
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.post('/reset-password', (req, res) => {
    const resetToken = 'reset_token_abc123';
    const userProvidedToken = req.body.token;
    
    // ruleid: typescript-crypto-timing-attack
    if (resetToken.toLowerCase() == userProvidedToken.toLowerCase()) {
      res.json({ success: true });
    } else {
      res.status(403).json({ success: false });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/admin', (req, res) => {
    const sessionToken = req.cookies.sessionToken;
    const validToken = 'admin_session_token_xyz';
    
    // ruleid: typescript-crypto-timing-attack
    const isAdmin = sessionToken === validToken;
    
    if (isAdmin) {
      res.send('Admin dashboard');
    } else {
      res.status(403).send('Access denied');
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
  class AuthService {
    private readonly secretKey = 'my_secret_key_123';
    
    verifyKey(userKey: string): boolean {
      // ruleid: typescript-crypto-timing-attack
      return this.secretKey === userKey;
    }
  }
  
  const auth = new AuthService();
  const userInput = getUserInput();
  const isValid = auth.verifyKey(userInput);
  
  function getUserInput(): string {
    return 'user_provided_key';
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.post('/webhook', (req, res) => {
    const webhookSecret = process.env.WEBHOOK_SECRET || 'default_webhook_secret';
    const signature = req.headers['x-signature'] as string;
    
    // ruleid: typescript-crypto-timing-attack
    if (webhookSecret == signature) {
      processWebhook(req.body);
      res.status(200).send('Webhook processed');
    } else {
      res.status(403).send('Invalid signature');
    }
  });
  
  function processWebhook(data: any): void {
    console.log('Processing webhook:', data);
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.post('/two-factor', (req, res) => {
    const storedOtp = generateOtp();
    const userOtp = req.body.otp;
    
    // ruleid: typescript-crypto-timing-attack
    const isValidOtp = storedOtp === userOtp;
    
    if (isValidOtp) {
      res.json({ success: true });
    } else {
      res.status(401).json({ success: false });
    }
  });
  
  function generateOtp(): string {
    return '123456'; // In a real app, this would be dynamically generated
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
  interface User {
    id: number;
    password: string;
  }
  
  const users: User[] = [
    { id: 1, password: 'password123' }
  ];
  
  function authenticateUser(userId: number, password: string): boolean {
    const user = users.find(u => u.id === userId);
    if (!user) return false;
    
    // ruleid: typescript-crypto-timing-attack
    return user.password === password;
  }
  
  const isAuthenticated = authenticateUser(1, 'user_input_password');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/verify-hmac', (req, res) => {
    const expectedHmac = 'abcdef123456';
    const providedHmac = req.body.hmac;
    
    // ruleid: typescript-crypto-timing-attack
    if (expectedHmac == providedHmac) {
      res.json({ verified: true });
    } else {
      res.status(403).json({ verified: false });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
  class TokenValidator {
    private readonly tokens: Map<string, string> = new Map([
      ['user1', 'token_abc'],
      ['user2', 'token_xyz']
    ]);
    
    isValidToken(username: string, token: string): boolean {
      const storedToken = this.tokens.get(username);
      if (!storedToken) return false;
      
      // ruleid: typescript-crypto-timing-attack
      return storedToken === token;
    }
  }
  
  const validator = new TokenValidator();
  const isValid = validator.isValidToken('user1', 'user_provided_token');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.post('/api/access', (req, res) => {
    const accessCode = 'secret_access_code_123';
    let userCode = req.body.code;
    
    // Transformation doesn't make it secure
    userCode = userCode.trim();
    
    // ruleid: typescript-crypto-timing-attack
    if (accessCode == userCode) {
      res.json({ granted: true });
    } else {
      res.status(403).json({ granted: false });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
  function verifyJwtSignature(token: string): boolean {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    
    const signature = parts[2];
    const expectedSignature = computeSignature(parts[0], parts[1]);
    
    // ruleid: typescript-crypto-timing-attack
    return signature === expectedSignature;
  }
  
  function computeSignature(header: string, payload: string): string {
    // Simplified for example
    return 'computed_signature';
  }
  
  const isValid = verifyJwtSignature('header.payload.signature');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/api/document/:id', (req, res) => {
    const documentId = req.params.id;
    const accessKey = req.query.key as string;
    const documentSecretKey = getDocumentKey(documentId);
    
    // ruleid: typescript-crypto-timing-attack
    if (accessKey === documentSecretKey) {
      res.json(getDocument(documentId));
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  });
  
  function getDocumentKey(id: string): string {
    return `doc_key_${id}`;
  }
  
  function getDocument(id: string): object {
    return { id, content: 'Document content' };
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
  class EncryptionService {
    private readonly encryptionKey = 'encryption_key_12345';
    
    validateKey(providedKey: string): boolean {
      // ruleid: typescript-crypto-timing-attack
      return this.encryptionKey == providedKey;
    }
    
    encrypt(data: string): string {
      // Encryption logic
      return `encrypted_${data}`;
    }
  }
  
  const service = new EncryptionService();
  const isKeyValid = service.validateKey('user_provided_key');
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.post('/login', (req, res) => {
    const storedPassword = 'super_secret_password123';
    const userPassword = req.body.password;
    
    // ok: typescript-crypto-timing-attack
    if (crypto.timingSafeEqual(Buffer.from(storedPassword), Buffer.from(userPassword))) {
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/verify-api-key', (req, res) => {
    const apiKey = 'api_key_12345';
    const userApiKey = req.headers['x-api-key'] as string;
    
    try {
      // ok: typescript-crypto-timing-attack
      const isValid = crypto.timingSafeEqual(
        Buffer.from(apiKey, 'utf8'),
        Buffer.from(userApiKey || '', 'utf8')
      );
      
      if (isValid) {
        res.json({ valid: true });
      } else {
        res.status(403).json({ valid: false });
      }
    } catch (error) {
      res.status(403).json({ valid: false });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.post('/verify-token', (req, res) => {
    const secretToken = fetchTokenFromDatabase();
    const userToken = req.body.token || '';
    
    try {
      // ok: typescript-crypto-timing-attack
      const isValid = secureCompare(secretToken, userToken);
      
      if (isValid) {
        res.json({ success: true });
      } else {
        res.status(401).json({ success: false });
      }
    } catch (error) {
      res.status(401).json({ success: false });
    }
  });
  
  function fetchTokenFromDatabase(): string {
    return 'secure_token_from_db';
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.post('/reset-password', (req, res) => {
    const resetToken = 'reset_token_abc123';
    const userProvidedToken = req.body.token || '';
    
    // Case-insensitive comparison done safely
    const normalizedResetToken = resetToken.toLowerCase();
    const normalizedUserToken = userProvidedToken.toLowerCase();
    
    try {
      // ok: typescript-crypto-timing-attack
      const isValid = crypto.timingSafeEqual(
        Buffer.from(normalizedResetToken),
        Buffer.from(normalizedUserToken)
      );
      
      if (isValid) {
        res.json({ success: true });
      } else {
        res.status(403).json({ success: false });
      }
    } catch (error) {
      res.status(403).json({ success: false });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/admin', (req, res) => {
    const sessionToken = req.cookies.sessionToken || '';
    const validToken = 'admin_session_token_xyz';
    
    try {
      // ok: typescript-crypto-timing-attack
      const isAdmin = crypto.timingSafeEqual(
        Buffer.from(validToken),
        Buffer.from(sessionToken)
      );
      
      if (isAdmin) {
        res.send('Admin dashboard');
      } else {
        res.status(403).send('Access denied');
      }
    } catch (error) {
      res.status(403).send('Access denied');
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
  class AuthService {
    private readonly secretKey = 'my_secret_key_123';
    
    verifyKey(userKey: string): boolean {
      try {
        // ok: typescript-crypto-timing-attack
        return crypto.timingSafeEqual(
          Buffer.from(this.secretKey),
          Buffer.from(userKey || '')
        );
      } catch (error) {
        return false;
      }
    }
  }
  
  const auth = new AuthService();
  const userInput = getUserInput();
  const isValid = auth.verifyKey(userInput);
  
  function getUserInput(): string {
    return 'user_provided_key';
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.post('/webhook', (req, res) => {
    const webhookSecret = process.env.WEBHOOK_SECRET || 'default_webhook_secret';
    const signature = req.headers['x-signature'] as string || '';
    
    try {
      // ok: typescript-crypto-timing-attack
      const isValid = secureCompare(webhookSecret, signature);
      
      if (isValid) {
        processWebhook(req.body);
        res.status(200).send('Webhook processed');
      } else {
        res.status(403).send('Invalid signature');
      }
    } catch (error) {
      res.status(403).send('Invalid signature');
    }
  });
  
  function processWebhook(data: any): void {
    console.log('Processing webhook:', data);
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.post('/two-factor', (req, res) => {
    const storedOtp = generateOtp();
    const userOtp = req.body.otp || '';
    
    try {
      // ok: typescript-crypto-timing-attack
      const isValidOtp = crypto.timingSafeEqual(
        Buffer.from(storedOtp),
        Buffer.from(userOtp)
      );
      
      if (isValidOtp) {
        res.json({ success: true });
      } else {
        res.status(401).json({ success: false });
      }
    } catch (error) {
      res.status(401).json({ success: false });
    }
  });
  
  function generateOtp(): string {
    return '123456'; // In a real app, this would be dynamically generated
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
  interface User {
    id: number;
    password: string;
  }
  
  const users: User[] = [
    { id: 1, password: 'password123' }
  ];
  
  function authenticateUser(userId: number, password: string): boolean {
    const user = users.find(u => u.id === userId);
    if (!user) return false;
    
    try {
      // ok: typescript-crypto-timing-attack
      return crypto.timingSafeEqual(
        Buffer.from(user.password),
        Buffer.from(password || '')
      );
    } catch (error) {
      return false;
    }
  }
  
  const isAuthenticated = authenticateUser(1, 'user_input_password');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/verify-hmac', (req, res) => {
    const expectedHmac = 'abcdef123456';
    const providedHmac = req.body.hmac || '';
    
    try {
      // ok: typescript-crypto-timing-attack
      const isValid = crypto.timingSafeEqual(
        Buffer.from(expectedHmac),
        Buffer.from(providedHmac)
      );
      
      if (isValid) {
        res.json({ verified: true });
      } else {
        res.status(403).json({ verified: false });
      }
    } catch (error) {
      res.status(403).json({ verified: false });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
  class TokenValidator {
    private readonly tokens: Map<string, string> = new Map([
      ['user1', 'token_abc'],
      ['user2', 'token_xyz']
    ]);
    
    isValidToken(username: string, token: string): boolean {
      const storedToken = this.tokens.get(username);
      if (!storedToken) return false;
      
      try {
        // ok: typescript-crypto-timing-attack
        return crypto.timingSafeEqual(
          Buffer.from(storedToken),
          Buffer.from(token || '')
        );
      } catch (error) {
        return false;
      }
    }
  }
  
  const validator = new TokenValidator();
  const isValid = validator.isValidToken('user1', 'user_provided_token');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.post('/api/access', (req, res) => {
    const accessCode = 'secret_access_code_123';
    let userCode = req.body.code || '';
    
    // Transformation before secure comparison
    userCode = userCode.trim();
    
    try {
      // ok: typescript-crypto-timing-attack
      const isValid = secureCompare(accessCode, userCode);
      
      if (isValid) {
        res.json({ granted: true });
      } else {
        res.status(403).json({ granted: false });
      }
    } catch (error) {
      res.status(403).json({ granted: false });
    }
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
  function verifyJwtSignature(token: string): boolean {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    
    const signature = parts[2];
    const expectedSignature = computeSignature(parts[0], parts[1]);
    
    try {
      // ok: typescript-crypto-timing-attack
      return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      );
    } catch (error) {
      return false;
    }
  }
  
  function computeSignature(header: string, payload: string): string {
    // Simplified for example
    return 'computed_signature';
  }
  
  const isValid = verifyJwtSignature('header.payload.signature');
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/api/document/:id', (req, res) => {
    const documentId = req.params.id;
    const accessKey = req.query.key as string || '';
    const documentSecretKey = getDocumentKey(documentId);
    
    try {
      // ok: typescript-crypto-timing-attack
      const isValid = crypto.timingSafeEqual(
        Buffer.from(documentSecretKey),
        Buffer.from(accessKey)
      );
      
      if (isValid) {
        res.json(getDocument(documentId));
      } else {
        res.status(403).json({ error: 'Access denied' });
      }
    } catch (error) {
      res.status(403).json({ error: 'Access denied' });
    }
  });
  
  function getDocumentKey(id: string): string {
    return `doc_key_${id}`;
  }
  
  function getDocument(id: string): object {
    return { id, content: 'Document content' };
  }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
  class EncryptionService {
    private readonly encryptionKey = 'encryption_key_12345';
    
    validateKey(providedKey: string): boolean {
      try {
        // ok: typescript-crypto-timing-attack
        return secureCompare(this.encryptionKey, providedKey || '');
      } catch (error) {
        return false;
      }
    }
    
    encrypt(data: string): string {
      // Encryption logic
      return `encrypted_${data}`;
    }
  }
  
  const service = new EncryptionService();
  const isKeyValid = service.validateKey('user_provided_key');
}
// {/fact}