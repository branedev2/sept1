import express from 'express';
import jwt from 'express-jwt';
import jwksRsa from 'jwks-rsa';
import { Request, Response, NextFunction } from 'express';

// TRUE POSITIVES (Vulnerable code examples)

// Example 1: Basic JWT middleware without isRevoked parameter
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // ruleid: typescript-express-jwt-not-revoked
  const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: 'https://dev-123456.auth0.com/.well-known/jwks.json'
    }),
    audience: 'https://api.example.com',
    issuer: 'https://dev-123456.auth0.com/',
    algorithms: ['RS256']
  });
  
  app.get('/api/protected', checkJwt, (req: Request, res: Response) => {
    res.json({ message: 'This is a protected endpoint' });
  });
}
// {/fact}

// Example 2: JWT middleware with multiple options but missing isRevoked
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  // ruleid: typescript-express-jwt-not-revoked
  const authMiddleware = jwt({
    secret: 'your-secret-key',
    algorithms: ['HS256'],
    credentialsRequired: true,
    requestProperty: 'auth',
    getToken: function fromHeaderOrQuerystring(req: Request) {
      if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
      } else if (req.query && req.query.token) {
        return req.query.token as string;
      }
      return null;
    }
  });
  
  app.use('/api', authMiddleware);
}
// {/fact}

// Example 3: JWT middleware in an authentication service
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_3() {
  class AuthService {
    setupJwtMiddleware() {
      // ruleid: typescript-express-jwt-not-revoked
      return jwt({
        secret: process.env.JWT_SECRET || 'default-secret-key',
        algorithms: ['HS256', 'RS256'],
        audience: 'client-id',
        issuer: 'https://issuer.example.com/'
      });
    }
  }
  
  const app = express();
  const authService = new AuthService();
  app.use('/api', authService.setupJwtMiddleware());
}
// {/fact}

// Example 4: JWT middleware with async secret function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  const getSecret = async (req: Request, payload: any) => {
    // Fetch secret from database or key management service
    return 'fetched-secret-key';
  };
  
  // ruleid: typescript-express-jwt-not-revoked
  const jwtCheck = jwt({
    secret: getSecret,
    algorithms: ['HS256'],
    audience: 'https://api.myservice.com'
  });
  
  app.use(jwtCheck);
}
// {/fact}

// Example 5: JWT middleware with custom error handling
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // ruleid: typescript-express-jwt-not-revoked
  const authMiddleware = jwt({
    secret: 'my-secret-key',
    algorithms: ['HS256']
  }).unless({ path: ['/public', '/login'] });
  
  app.use(authMiddleware);
  
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err.name === 'UnauthorizedError') {
      res.status(401).send('Invalid token');
    }
  });
}
// {/fact}

// Example 6: JWT middleware in a route-specific context
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_6() {
  const router = express.Router();
  
  // ruleid: typescript-express-jwt-not-revoked
  const validateJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
    }),
    audience: process.env.AUTH0_AUDIENCE,
    issuer: `https://${process.env.AUTH0_DOMAIN}/`,
    algorithms: ['RS256']
  });
  
  router.get('/users', validateJwt, (req: Request, res: Response) => {
    res.json({ users: [] });
  });
}
// {/fact}

// Example 7: JWT middleware with custom token extraction
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  function extractTokenFromCookie(req: Request) {
    if (req.cookies && req.cookies.access_token) {
      return req.cookies.access_token;
    }
    return null;
  }
  
  // ruleid: typescript-express-jwt-not-revoked
  const jwtAuth = jwt({
    secret: 'cookie-secret-key',
    algorithms: ['HS256'],
    getToken: extractTokenFromCookie
  });
  
  app.use('/api/profile', jwtAuth, (req: Request, res: Response) => {
    res.json({ profile: req.user });
  });
}
// {/fact}

// Example 8: JWT middleware with multiple algorithms
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  // ruleid: typescript-express-jwt-not-revoked
  const authCheck = jwt({
    secret: 'multi-algo-secret',
    algorithms: ['HS256', 'HS384', 'HS512', 'RS256'],
    credentialsRequired: true
  });
  
  app.get('/api/data', authCheck, (req: Request, res: Response) => {
    res.json({ data: 'sensitive data' });
  });
}
// {/fact}

// Example 9: JWT middleware with requestProperty customization
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // ruleid: typescript-express-jwt-not-revoked
  const jwtMiddleware = jwt({
    secret: 'custom-property-secret',
    algorithms: ['HS256'],
    requestProperty: 'userAuth'
  });
  
  app.get('/api/user-data', jwtMiddleware, (req: any, res: Response) => {
    const userId = req.userAuth.sub;
    res.json({ userId });
  });
}
// {/fact}

// Example 10: JWT middleware with complex configuration
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  const jwtConfig = {
    secret: process.env.JWT_SECRET || 'fallback-secret',
    algorithms: ['RS256'],
    audience: 'api://default',
    issuer: 'https://issuer.example.com/'
  };
  
  // ruleid: typescript-express-jwt-not-revoked
  app.use(jwt(jwtConfig));
  
  app.get('/api/protected-resource', (req: Request, res: Response) => {
    res.json({ message: 'Access granted' });
  });
}
// {/fact}

// Example 11: JWT middleware in an API gateway pattern
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_11() {
  const apiGateway = express();
  
  // ruleid: typescript-express-jwt-not-revoked
  const verifyToken = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 10,
      jwksUri: 'https://auth.example.com/.well-known/jwks.json'
    }),
    audience: 'gateway',
    issuer: 'https://auth.example.com/',
    algorithms: ['RS256']
  });
  
  apiGateway.use('/services/*', verifyToken);
}
// {/fact}

// Example 12: JWT middleware with conditional application
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  // ruleid: typescript-express-jwt-not-revoked
  const tokenValidator = jwt({
    secret: 'conditional-secret',
    algorithms: ['HS256']
  });
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api/')) {
      return tokenValidator(req, res, next);
    }
    next();
  });
}
// {/fact}

// Example 13: JWT middleware with destructured options
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  const jwtOptions = {
    secret: 'destructured-secret',
    algorithms: ['HS256'],
    audience: 'web-client'
  };
  
  // ruleid: typescript-express-jwt-not-revoked
  app.use(jwt({ ...jwtOptions }));
}
// {/fact}

// Example 14: JWT middleware with variable options
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  function getJwtOptions() {
    return {
      secret: process.env.JWT_SECRET || 'dynamic-secret',
      algorithms: ['HS256']
    };
  }
  
  // ruleid: typescript-express-jwt-not-revoked
  const authMiddleware = jwt(getJwtOptions());
  
  app.use('/api', authMiddleware);
}
// {/fact}

// Example 15: JWT middleware with nested configuration
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  const config = {
    auth: {
      jwt: {
        secret: 'nested-config-secret',
        algorithms: ['HS256']
      }
    }
  };
  
  // ruleid: typescript-express-jwt-not-revoked
  app.use(jwt(config.auth.jwt));
}
// {/fact}

// TRUE NEGATIVES (Secure code examples)

// Example 1: JWT middleware with isRevoked parameter
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  const isTokenRevoked = async (req: Request, payload: any) => {
    // Check if token is in revocation list
    const tokenId = payload.jti;
    const isRevoked = await checkRevocationDatabase(tokenId);
    return isRevoked;
  };
  
  // ok: typescript-express-jwt-not-revoked
  const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: 'https://dev-123456.auth0.com/.well-known/jwks.json'
    }),
    audience: 'https://api.example.com',
    issuer: 'https://dev-123456.auth0.com/',
    algorithms: ['RS256'],
    isRevoked: isTokenRevoked
  });
  
  app.get('/api/protected', checkJwt, (req: Request, res: Response) => {
    res.json({ message: 'This is a protected endpoint' });
  });
  
  async function checkRevocationDatabase(tokenId: string): Promise<boolean> {
    // Implementation to check if token is revoked
    return false;
  }
}
// {/fact}

// Example 2: JWT middleware with inline isRevoked function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // ok: typescript-express-jwt-not-revoked
  const authMiddleware = jwt({
    secret: 'your-secret-key',
    algorithms: ['HS256'],
    isRevoked: async (req: Request, payload: any) => {
      // Check token against a blacklist or revocation database
      const isBlacklisted = await checkBlacklist(payload.sub, payload.jti);
      return isBlacklisted;
    }
  });
  
  app.use('/api', authMiddleware);
  
  async function checkBlacklist(userId: string, tokenId: string): Promise<boolean> {
    // Implementation to check if token is blacklisted
    return false;
  }
}
// {/fact}

// Example 3: JWT middleware with isRevoked in an authentication service
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_3() {
  class AuthService {
    setupJwtMiddleware() {
      // ok: typescript-express-jwt-not-revoked
      return jwt({
        secret: process.env.JWT_SECRET || 'default-secret-key',
        algorithms: ['HS256', 'RS256'],
        audience: 'client-id',
        issuer: 'https://issuer.example.com/',
        isRevoked: this.checkTokenRevocation
      });
    }
    
    async checkTokenRevocation(req: Request, payload: any): Promise<boolean> {
      // Check if token has been revoked
      const tokenId = payload.jti;
      // Implementation to check token revocation status
      return false;
    }
  }
  
  const app = express();
  const authService = new AuthService();
  app.use('/api', authService.setupJwtMiddleware());
}
// {/fact}

// Example 4: JWT middleware with isRevoked and async secret function
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  const getSecret = async (req: Request, payload: any) => {
    // Fetch secret from database or key management service
    return 'fetched-secret-key';
  };
  
  // ok: typescript-express-jwt-not-revoked
  const jwtCheck = jwt({
    secret: getSecret,
    algorithms: ['HS256'],
    audience: 'https://api.myservice.com',
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is in revocation list
      return await isTokenInRevocationList(payload.jti);
    }
  });
  
  app.use(jwtCheck);
  
  async function isTokenInRevocationList(tokenId: string): Promise<boolean> {
    // Implementation to check if token is in revocation list
    return false;
  }
}
// {/fact}

// Example 5: JWT middleware with isRevoked and custom error handling
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // ok: typescript-express-jwt-not-revoked
  const authMiddleware = jwt({
    secret: 'my-secret-key',
    algorithms: ['HS256'],
    isRevoked: async (req: Request, payload: any) => {
      // Check if user has logged out or token has been revoked
      return await hasUserLoggedOut(payload.sub);
    }
  }).unless({ path: ['/public', '/login'] });
  
  app.use(authMiddleware);
  
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err.name === 'UnauthorizedError') {
      res.status(401).send('Invalid token');
    }
  });
  
  async function hasUserLoggedOut(userId: string): Promise<boolean> {
    // Implementation to check if user has logged out
    return false;
  }
}
// {/fact}

// Example 6: JWT middleware with isRevoked in a route-specific context
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_6() {
  const router = express.Router();
  
  // ok: typescript-express-jwt-not-revoked
  const validateJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
    }),
    audience: process.env.AUTH0_AUDIENCE,
    issuer: `https://${process.env.AUTH0_DOMAIN}/`,
    algorithms: ['RS256'],
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is revoked
      return await checkTokenRevocationStatus(payload);
    }
  });
  
  router.get('/users', validateJwt, (req: Request, res: Response) => {
    res.json({ users: [] });
  });
  
  async function checkTokenRevocationStatus(payload: any): Promise<boolean> {
    // Implementation to check token revocation status
    return false;
  }
}
// {/fact}

// Example 7: JWT middleware with isRevoked and custom token extraction
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  function extractTokenFromCookie(req: Request) {
    if (req.cookies && req.cookies.access_token) {
      return req.cookies.access_token;
    }
    return null;
  }
  
  // ok: typescript-express-jwt-not-revoked
  const jwtAuth = jwt({
    secret: 'cookie-secret-key',
    algorithms: ['HS256'],
    getToken: extractTokenFromCookie,
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is revoked in Redis
      return await checkRedisForRevokedToken(payload.jti);
    }
  });
  
  app.use('/api/profile', jwtAuth, (req: Request, res: Response) => {
    res.json({ profile: req.user });
  });
  
  async function checkRedisForRevokedToken(tokenId: string): Promise<boolean> {
    // Implementation to check if token is revoked in Redis
    return false;
  }
}
// {/fact}

// Example 8: JWT middleware with isRevoked and multiple algorithms
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // ok: typescript-express-jwt-not-revoked
  const authCheck = jwt({
    secret: 'multi-algo-secret',
    algorithms: ['HS256', 'HS384', 'HS512', 'RS256'],
    credentialsRequired: true,
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is revoked
      const isRevoked = await checkRevocationStatus(payload.jti, payload.iat);
      return isRevoked;
    }
  });
  
  app.get('/api/data', authCheck, (req: Request, res: Response) => {
    res.json({ data: 'sensitive data' });
  });
  
  async function checkRevocationStatus(tokenId: string, issuedAt: number): Promise<boolean> {
    // Implementation to check if token is revoked
    return false;
  }
}
// {/fact}

// Example 9: JWT middleware with isRevoked and requestProperty customization
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // ok: typescript-express-jwt-not-revoked
  const jwtMiddleware = jwt({
    secret: 'custom-property-secret',
    algorithms: ['HS256'],
    requestProperty: 'userAuth',
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is revoked
      return await isTokenRevoked(payload.sub, payload.jti);
    }
  });
  
  app.get('/api/user-data', jwtMiddleware, (req: any, res: Response) => {
    const userId = req.userAuth.sub;
    res.json({ userId });
  });
  
  async function isTokenRevoked(userId: string, tokenId: string): Promise<boolean> {
    // Implementation to check if token is revoked
    return false;
  }
}
// {/fact}

// Example 10: JWT middleware with isRevoked and complex configuration
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  const jwtConfig = {
    secret: process.env.JWT_SECRET || 'fallback-secret',
    algorithms: ['RS256'],
    audience: 'api://default',
    issuer: 'https://issuer.example.com/',
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is revoked
      return await checkTokenRevocationStatus(payload);
    }
  };
  
  // ok: typescript-express-jwt-not-revoked
  app.use(jwt(jwtConfig));
  
  app.get('/api/protected-resource', (req: Request, res: Response) => {
    res.json({ message: 'Access granted' });
  });
  
  async function checkTokenRevocationStatus(payload: any): Promise<boolean> {
    // Implementation to check if token is revoked
    return false;
  }
}
// {/fact}

// Example 11: JWT middleware with isRevoked in an API gateway pattern
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_11() {
  const apiGateway = express();
  
  // ok: typescript-express-jwt-not-revoked
  const verifyToken = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 10,
      jwksUri: 'https://auth.example.com/.well-known/jwks.json'
    }),
    audience: 'gateway',
    issuer: 'https://auth.example.com/',
    algorithms: ['RS256'],
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is revoked
      return await checkTokenInBlacklist(payload.jti);
    }
  });
  
  apiGateway.use('/services/*', verifyToken);
  
  async function checkTokenInBlacklist(tokenId: string): Promise<boolean> {
    // Implementation to check if token is in blacklist
    return false;
  }
}
// {/fact}

// Example 12: JWT middleware with isRevoked and conditional application
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // ok: typescript-express-jwt-not-revoked
  const tokenValidator = jwt({
    secret: 'conditional-secret',
    algorithms: ['HS256'],
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is revoked
      return await isTokenRevoked(payload);
    }
  });
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api/')) {
      return tokenValidator(req, res, next);
    }
    next();
  });
  
  async function isTokenRevoked(payload: any): Promise<boolean> {
    // Implementation to check if token is revoked
    return false;
  }
}
// {/fact}

// Example 13: JWT middleware with isRevoked and destructured options
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  const jwtOptions = {
    secret: 'destructured-secret',
    algorithms: ['HS256'],
    audience: 'web-client',
    isRevoked: async (req: Request, payload: any) => {
      // Check if token is revoked
      return await checkRevocationDatabase(payload.jti);
    }
  };
  
  // ok: typescript-express-jwt-not-revoked
  app.use(jwt({ ...jwtOptions }));
  
  async function checkRevocationDatabase(tokenId: string): Promise<boolean> {
    // Implementation to check if token is revoked
    return false;
  }
}
// {/fact}

// Example 14: JWT middleware with isRevoked and variable options
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  function getJwtOptions() {
    return {
      secret: process.env.JWT_SECRET || 'dynamic-secret',
      algorithms: ['HS256'],
      isRevoked: async (req: Request, payload: any) => {
        // Check if token is revoked
        return await isTokenInRevocationList(payload.jti);
      }
    };
  }
  
  // ok: typescript-express-jwt-not-revoked
  const authMiddleware = jwt(getJwtOptions());
  
  app.use('/api', authMiddleware);
  
  async function isTokenInRevocationList(tokenId: string): Promise<boolean> {
    // Implementation to check if token is in revocation list
    return false;
  }
}
// {/fact}

// Example 15: JWT middleware with isRevoked and nested configuration
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  const config = {
    auth: {
      jwt: {
        secret: 'nested-config-secret',
        algorithms: ['HS256'],
        isRevoked: async (req: Request, payload: any) => {
          // Check if token is revoked
          return await checkIfTokenIsRevoked(payload);
        }
      }
    }
  };
  
  // ok: typescript-express-jwt-not-revoked
  app.use(jwt(config.auth.jwt));
  
  async function checkIfTokenIsRevoked(payload: any): Promise<boolean> {
    // Implementation to check if token is revoked
    return false;
  }
}
// {/fact}