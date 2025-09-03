import * as jwt from 'jsonwebtoken';
import express from 'express';
import dotenv from 'dotenv';
import fs from 'fs';
import { SecretsManager } from 'aws-sdk';
import { KeyVaultClient } from '@azure/keyvault';
import { Config } from 'node-config-ts';

// Initialize environment variables
dotenv.config();

// True Positives (Vulnerable Code)

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_1() {
  // Simple hardcoded JWT secret in a token generation function
  const payload = { userId: 123, role: 'admin' };
  // ruleid: typescript-jwt-secret-hardcoded
  const token = jwt.sign(payload, 'my_super_secret_key_123');
  return token;
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_2() {
  // Hardcoded JWT secret with algorithm specification
  const userData = { username: 'john_doe', isAdmin: true };
  // ruleid: typescript-jwt-secret-hardcoded
  return jwt.sign(userData, 'secret_jwt_key_for_auth', { algorithm: 'HS256', expiresIn: '1h' });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_3() {
  // JWT verification with hardcoded secret
  const authHeader = getAuthHeader();
  const token = authHeader.split(' ')[1];
  try {
    // ruleid: typescript-jwt-secret-hardcoded
    const decoded = jwt.verify(token, 'hardcoded_verification_key');
    return decoded;
  } catch (err) {
    throw new Error('Invalid token');
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_4() {
  // Hardcoded secret in an Express middleware
  const app = express();
  
  app.use((req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).send('Access denied');
    
    try {
      // ruleid: typescript-jwt-secret-hardcoded
      req.user = jwt.verify(token, 'express_middleware_secret_key');
      next();
    } catch (err) {
      res.status(400).send('Invalid token');
    }
  });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_5() {
  // Hardcoded secret in a class property
  class AuthService {
    private readonly jwtSecret = 'auth_service_secret_key_123';
    
    generateToken(userId: number): string {
      // ruleid: typescript-jwt-secret-hardcoded
      return jwt.sign({ userId }, this.jwtSecret, { expiresIn: '2h' });
    }
  }
  
  const authService = new AuthService();
  return authService.generateToken(42);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_6() {
  // Hardcoded secret in an object configuration
  const authConfig = {
    secret: 'config_object_secret_key',
    expiresIn: '24h',
    algorithm: 'HS256'
  };
  
  const userData = { id: 789, permissions: ['read', 'write'] };
  // ruleid: typescript-jwt-secret-hardcoded
  return jwt.sign(userData, authConfig.secret, { 
    expiresIn: authConfig.expiresIn,
    algorithm: authConfig.algorithm
  });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_7() {
  // Hardcoded secret with conditional logic
  const isProduction = process.env.NODE_ENV === 'production';
  const payload = { userId: 555, timestamp: Date.now() };
  
  // ruleid: typescript-jwt-secret-hardcoded
  const secret = isProduction ? 'production_secret_key_very_secure' : 'development_secret_key';
  return jwt.sign(payload, secret);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_8() {
  // Hardcoded secret in a function with error handling
  function createUserToken(user: any): string {
    try {
      // ruleid: typescript-jwt-secret-hardcoded
      return jwt.sign(user, 'user_token_secret_key_456', { expiresIn: '4h' });
    } catch (error) {
      console.error('Token generation failed:', error);
      throw new Error('Authentication failed');
    }
  }
  
  return createUserToken({ id: 42, email: 'user@example.com' });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_9() {
  // Hardcoded secret with template literals
  const keyPrefix = 'jwt_key';
  const keySuffix = 'for_api_auth';
  
  // ruleid: typescript-jwt-secret-hardcoded
  const secret = `${keyPrefix}_secret_${keySuffix}`;
  return jwt.sign({ apiAccess: true }, secret);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_10() {
  // Hardcoded secret with string concatenation
  const part1 = 'very';
  const part2 = 'secret';
  const part3 = 'jwt_key';
  
  // ruleid: typescript-jwt-secret-hardcoded
  const secretKey = part1 + '_' + part2 + '_' + part3;
  return jwt.sign({ data: 'sensitive' }, secretKey);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_11() {
  // Hardcoded secret in an async function
  async function generateAuthToken(userId: number): Promise<string> {
    const userData = await fetchUserData(userId);
    // ruleid: typescript-jwt-secret-hardcoded
    return jwt.sign(userData, 'async_function_secret_key');
  }
  
  return generateAuthToken(123);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_12() {
  // Hardcoded secret in a switch statement
  const tokenType = 'access';
  let secret: string;
  
  switch (tokenType) {
    case 'access':
      secret = 'access_token_secret_key';
      break;
    case 'refresh':
      secret = 'refresh_token_secret_key';
      break;
    default:
      secret = 'default_token_secret_key';
  }
  
  // ruleid: typescript-jwt-secret-hardcoded
  return jwt.sign({ type: tokenType }, secret);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_13() {
  // Hardcoded secret with Base64 encoding (still hardcoded)
  const encodedSecret = Buffer.from('super_secret_jwt_key').toString('base64');
  
  // ruleid: typescript-jwt-secret-hardcoded
  return jwt.sign({ timestamp: Date.now() }, encodedSecret);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_14() {
  // Hardcoded secret in a higher-order function
  const withAuth = (handler: Function) => {
    return (req: any, res: any) => {
      const token = req.headers.authorization?.split(' ')[1];
      try {
        // ruleid: typescript-jwt-secret-hardcoded
        const decoded = jwt.verify(token, 'higher_order_function_secret');
        req.user = decoded;
        return handler(req, res);
      } catch (error) {
        res.status(401).json({ error: 'Authentication failed' });
      }
    };
  };
  
  const protectedHandler = withAuth((req: any, res: any) => {
    res.json({ data: 'protected data' });
  });
  
  return protectedHandler;
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_15() {
  // Hardcoded secret in a callback function
  const authenticateUser = (userId: number, callback: Function) => {
    const userData = { id: userId, timestamp: Date.now() };
    // ruleid: typescript-jwt-secret-hardcoded
    const token = jwt.sign(userData, 'callback_function_secret_key');
    callback(null, token);
  };
  
  authenticateUser(42, (err: Error | null, token: string) => {
    if (err) {
      console.error('Authentication failed:', err);
      return;
    }
    console.log('Authentication successful:', token);
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_1() {
  // Using environment variable for JWT secret
  const payload = { userId: 123, role: 'admin' };
  // ok: typescript-jwt-secret-hardcoded
  const token = jwt.sign(payload, process.env.JWT_SECRET || '');
  return token;
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_2() {
  // Using environment variable with default (for development only)
  const userData = { username: 'john_doe', isAdmin: true };
  // ok: typescript-jwt-secret-hardcoded
  return jwt.sign(userData, process.env.JWT_SECRET || 'dev_only_key', { algorithm: 'HS256', expiresIn: '1h' });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_3() {
  // JWT verification with environment variable
  const authHeader = getAuthHeader();
  const token = authHeader.split(' ')[1];
  try {
    // ok: typescript-jwt-secret-hardcoded
    const decoded = jwt.verify(token, process.env.JWT_VERIFICATION_KEY || '');
    return decoded;
  } catch (err) {
    throw new Error('Invalid token');
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_4() {
  // Environment variable in an Express middleware
  const app = express();
  
  app.use((req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).send('Access denied');
    
    try {
      // ok: typescript-jwt-secret-hardcoded
      req.user = jwt.verify(token, process.env.JWT_SECRET || '');
      next();
    } catch (err) {
      res.status(400).send('Invalid token');
    }
  });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_5() {
  // Using secret from a configuration file loaded at runtime
  class AuthService {
    private readonly jwtSecret: string;
    
    constructor() {
      // ok: typescript-jwt-secret-hardcoded
      this.jwtSecret = process.env.JWT_SECRET || '';
    }
    
    generateToken(userId: number): string {
      return jwt.sign({ userId }, this.jwtSecret, { expiresIn: '2h' });
    }
  }
  
  const authService = new AuthService();
  return authService.generateToken(42);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_6() {
  // Using environment variables in an object configuration
  const authConfig = {
    // ok: typescript-jwt-secret-hardcoded
    secret: process.env.JWT_SECRET || '',
    expiresIn: '24h',
    algorithm: 'HS256'
  };
  
  const userData = { id: 789, permissions: ['read', 'write'] };
  return jwt.sign(userData, authConfig.secret, { 
    expiresIn: authConfig.expiresIn,
    algorithm: authConfig.algorithm
  });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_7() {
  // Loading secret from AWS Secrets Manager
  async function getSecretFromAWS(): Promise<string> {
    const secretsManager = new SecretsManager();
    const data = await secretsManager.getSecretValue({ SecretId: 'jwt/secret' }).promise();
    // ok: typescript-jwt-secret-hardcoded
    return data.SecretString || '';
  }
  
  async function signToken(payload: any): Promise<string> {
    const secret = await getSecretFromAWS();
    return jwt.sign(payload, secret);
  }
  
  return signToken({ userId: 555, timestamp: Date.now() });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_8() {
  // Loading secret from Azure Key Vault
  async function getSecretFromAzure(): Promise<string> {
    const keyVaultClient = new KeyVaultClient();
    const secretBundle = await keyVaultClient.getSecret('https://myvault.vault.azure.net', 'jwt-secret');
    // ok: typescript-jwt-secret-hardcoded
    return secretBundle.value || '';
  }
  
  async function createUserToken(user: any): Promise<string> {
    try {
      const secret = await getSecretFromAzure();
      return jwt.sign(user, secret, { expiresIn: '4h' });
    } catch (error) {
      console.error('Token generation failed:', error);
      throw new Error('Authentication failed');
    }
  }
  
  return createUserToken({ id: 42, email: 'user@example.com' });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_9() {
  // Loading secret from a secure file with restricted permissions
  function loadSecretFromFile(): string {
    try {
      // ok: typescript-jwt-secret-hardcoded
      return fs.readFileSync('/etc/secrets/jwt_key', 'utf8').trim();
    } catch (error) {
      console.error('Failed to load secret from file:', error);
      throw new Error('Secret configuration error');
    }
  }
  
  const secret = loadSecretFromFile();
  return jwt.sign({ apiAccess: true }, secret);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_10() {
  // Using a configuration management library
  function getConfigSecret(): string {
    const config = new Config();
    // ok: typescript-jwt-secret-hardcoded
    return config.jwt.secret;
  }
  
  const secretKey = getConfigSecret();
  return jwt.sign({ data: 'sensitive' }, secretKey);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_11() {
  // Using environment variables in an async function
  async function generateAuthToken(userId: number): Promise<string> {
    const userData = await fetchUserData(userId);
    // ok: typescript-jwt-secret-hardcoded
    return jwt.sign(userData, process.env.JWT_SECRET || '');
  }
  
  return generateAuthToken(123);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_12() {
  // Using different environment variables based on token type
  const tokenType = 'access';
  let secret: string;
  
  switch (tokenType) {
    case 'access':
      // ok: typescript-jwt-secret-hardcoded
      secret = process.env.ACCESS_TOKEN_SECRET || '';
      break;
    case 'refresh':
      secret = process.env.REFRESH_TOKEN_SECRET || '';
      break;
    default:
      secret = process.env.DEFAULT_TOKEN_SECRET || '';
  }
  
  return jwt.sign({ type: tokenType }, secret);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_13() {
  // Using a secret rotation mechanism
  class SecretRotator {
    private currentSecret: string;
    
    constructor() {
      // ok: typescript-jwt-secret-hardcoded
      this.currentSecret = process.env.JWT_SECRET || '';
      this.setupRotation();
    }
    
    private setupRotation(): void {
      // Set up periodic rotation of the secret
      setInterval(() => {
        this.rotateSecret();
      }, 24 * 60 * 60 * 1000); // Every 24 hours
    }
    
    private async rotateSecret(): Promise<void> {
      try {
        // Fetch new secret from a secure source
        const newSecret = await fetchNewSecretFromSecureSource();
        this.currentSecret = newSecret;
      } catch (error) {
        console.error('Secret rotation failed:', error);
      }
    }
    
    getSecret(): string {
      return this.currentSecret;
    }
  }
  
  const secretRotator = new SecretRotator();
  return jwt.sign({ timestamp: Date.now() }, secretRotator.getSecret());
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_14() {
  // Using environment variable in a higher-order function
  const withAuth = (handler: Function) => {
    return (req: any, res: any) => {
      const token = req.headers.authorization?.split(' ')[1];
      try {
        // ok: typescript-jwt-secret-hardcoded
        const decoded = jwt.verify(token, process.env.JWT_SECRET || '');
        req.user = decoded;
        return handler(req, res);
      } catch (error) {
        res.status(401).json({ error: 'Authentication failed' });
      }
    };
  };
  
  const protectedHandler = withAuth((req: any, res: any) => {
    res.json({ data: 'protected data' });
  });
  
  return protectedHandler;
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_15() {
  // Using environment variable in a callback function
  const authenticateUser = (userId: number, callback: Function) => {
    const userData = { id: userId, timestamp: Date.now() };
    // ok: typescript-jwt-secret-hardcoded
    const token = jwt.sign(userData, process.env.JWT_SECRET || '');
    callback(null, token);
  };
  
  authenticateUser(42, (err: Error | null, token: string) => {
    if (err) {
      console.error('Authentication failed:', err);
      return;
    }
    console.log('Authentication successful:', token);
  });
}
// {/fact}

// Helper functions (not part of the test cases)
function getAuthHeader(): string {
  return 'Bearer some.jwt.token';
}

async function fetchUserData(userId: number): Promise<any> {
  return { id: userId, name: 'User Name' };
}

async function fetchNewSecretFromSecureSource(): Promise<string> {
  // This would connect to a secure service to get a new secret
  return 'new-secure-secret-from-service';
}