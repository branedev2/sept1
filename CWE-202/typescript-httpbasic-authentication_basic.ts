// Import necessary modules
import * as express from 'express';
import * as passport from 'passport';
import { BasicStrategy } from 'passport-http';
import { Strategy as BearerStrategy } from 'passport-http-bearer';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import * as https from 'https';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as oauth2orize from 'oauth2orize';
import * as session from 'express-session';
import * as cookieParser from 'cookie-parser';
import * as bodyParser from 'body-parser';
import * as helmet from 'helmet';
import * as expressBasicAuth from 'express-basic-auth';
import * as basicAuth from 'basic-auth';
import * as auth from 'http-auth';
import * as httpAuthConnect from 'http-auth-connect';
import * as axios from 'axios';

// True Positive Examples (Vulnerable Code)

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // ruleid: typescript-httpbasic-authentication
  app.use((req, res, next) => {
    const user = basicAuth(req);
    
    if (!user || user.name !== 'admin' || user.pass !== 'password') {
      res.set('WWW-Authenticate', 'Basic realm="example"');
      return res.status(401).send('Authentication required');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  // ruleid: typescript-httpbasic-authentication
  app.use(expressBasicAuth({
    users: { 'admin': 'supersecret' },
    challenge: true,
    realm: 'example'
  }));
  
  app.get('/', (req, res) => {
    res.send('Authenticated!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  passport.use(new BasicStrategy(
    function(username, password, done) {
      if (username === 'admin' && password === 'password') {
        return done(null, { name: 'admin' });
      } else {
        return done(null, false);
      }
    }
  ));
  
  // ruleid: typescript-httpbasic-authentication
  app.get('/api/data', 
    passport.authenticate('basic', { session: false }),
    (req, res) => {
      res.json({ message: 'Secret data' });
    }
  );
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_4() {
  const basic = auth.basic({
    realm: "Private Area"
  }, (username, password, callback) => {
    callback(username === 'admin' && password === 'password');
  });
  
  const app = express();
  // ruleid: typescript-httpbasic-authentication
  app.use(httpAuthConnect(basic));
  
  app.get('/', (req, res) => {
    res.send('Welcome to private area');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // ruleid: typescript-httpbasic-authentication
  app.use((req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      res.setHeader('WWW-Authenticate', 'Basic realm="example"');
      return res.status(401).send('Authentication required');
    }
    
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    
    if (username === 'admin' && password === 'password') {
      next();
    } else {
      res.setHeader('WWW-Authenticate', 'Basic realm="example"');
      return res.status(401).send('Invalid credentials');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_6() {
  class AuthService {
    // ruleid: typescript-httpbasic-authentication
    setupBasicAuth(app: express.Application) {
      app.use((req, res, next) => {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Basic ')) {
          res.setHeader('WWW-Authenticate', 'Basic');
          return res.status(401).send('Unauthorized');
        }
        
        const credentials = Buffer.from(authHeader.substring(6), 'base64').toString();
        const [username, password] = credentials.split(':');
        
        if (this.validateCredentials(username, password)) {
          next();
        } else {
          res.status(401).send('Invalid credentials');
        }
      });
    }
    
    private validateCredentials(username: string, password: string): boolean {
      return username === 'admin' && password === 'secret';
    }
  }
  
  const app = express();
  const authService = new AuthService();
  authService.setupBasicAuth(app);
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_7() {
  // ruleid: typescript-httpbasic-authentication
  const makeApiRequest = async () => {
    const username = 'apiuser';
    const password = 'apipassword';
    const auth = 'Basic ' + Buffer.from(username + ':' + password).toString('base64');
    
    try {
      const response = await axios.default.get('https://api.example.com/data', {
        headers: {
          'Authorization': auth
        }
      });
      return response.data;
    } catch (error) {
      console.error('API request failed:', error);
      return null;
    }
  };
  
  makeApiRequest();
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  // ruleid: typescript-httpbasic-authentication
  const authenticateUser = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const credentials = basicAuth(req);
    
    if (!credentials) {
      res.set('WWW-Authenticate', 'Basic realm="Secure Area"');
      return res.status(401).send('Please provide credentials');
    }
    
    const validUser = credentials.name === 'user' && credentials.pass === 'pass';
    
    if (!validUser) {
      res.set('WWW-Authenticate', 'Basic realm="Secure Area"');
      return res.status(401).send('Invalid credentials');
    }
    
    next();
  };
  
  app.get('/protected', authenticateUser, (req, res) => {
    res.send('Welcome to protected resource');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_9() {
  // ruleid: typescript-httpbasic-authentication
  class BasicAuthMiddleware {
    authenticate(req: express.Request, res: express.Response, next: express.NextFunction) {
      const authHeader = req.headers.authorization;
      
      if (!authHeader) {
        res.setHeader('WWW-Authenticate', 'Basic');
        return res.status(401).send('Authentication required');
      }
      
      const [type, credentials] = authHeader.split(' ');
      
      if (type !== 'Basic') {
        return res.status(401).send('Invalid authentication type');
      }
      
      const decodedCredentials = Buffer.from(credentials, 'base64').toString();
      const [username, password] = decodedCredentials.split(':');
      
      if (username === 'admin' && password === 'adminpass') {
        req.user = { username };
        next();
      } else {
        res.setHeader('WWW-Authenticate', 'Basic');
        return res.status(401).send('Invalid credentials');
      }
    }
  }
  
  const app = express();
  const authMiddleware = new BasicAuthMiddleware();
  app.use(authMiddleware.authenticate.bind(authMiddleware));
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_10() {
  // ruleid: typescript-httpbasic-authentication
  function createBasicAuthClient() {
    return {
      request: async (url: string) => {
        const username = 'client';
        const password = 'secret';
        const authHeader = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');
        
        try {
          const response = await axios.default.get(url, {
            headers: {
              'Authorization': authHeader
            }
          });
          return response.data;
        } catch (error) {
          console.error('Request failed:', error);
          throw error;
        }
      }
    };
  }
  
  const client = createBasicAuthClient();
  client.request('https://api.example.com/resource');
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  // ruleid: typescript-httpbasic-authentication
  app.get('/api/v1/users', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      res.set('WWW-Authenticate', 'Basic realm="User API"');
      return res.status(401).send('Authentication required');
    }
    
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    
    if (username === 'apiuser' && password === 'apipass') {
      return res.json({ users: ['user1', 'user2', 'user3'] });
    } else {
      res.set('WWW-Authenticate', 'Basic realm="User API"');
      return res.status(401).send('Invalid credentials');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_12() {
  // ruleid: typescript-httpbasic-authentication
  const fetchWithBasicAuth = async (url: string, username: string, password: string) => {
    const headers = new Headers();
    headers.set('Authorization', 'Basic ' + Buffer.from(username + ':' + password).toString('base64'));
    
    try {
      const response = await fetch(url, { headers });
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error('Fetch error:', error);
      throw error;
    }
  };
  
  fetchWithBasicAuth('https://api.example.com/data', 'user', 'password')
    .then(data => console.log(data))
    .catch(error => console.error(error));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // ruleid: typescript-httpbasic-authentication
  const basicAuthRouter = express.Router();
  
  basicAuthRouter.use((req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      res.set('WWW-Authenticate', 'Basic realm="Admin Area"');
      return res.status(401).send('Authentication required');
    }
    
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    
    if (username === 'admin' && password === 'adminpass') {
      next();
    } else {
      res.set('WWW-Authenticate', 'Basic realm="Admin Area"');
      return res.status(401).send('Invalid credentials');
    }
  });
  
  basicAuthRouter.get('/dashboard', (req, res) => {
    res.send('Admin Dashboard');
  });
  
  app.use('/admin', basicAuthRouter);
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_14() {
  // ruleid: typescript-httpbasic-authentication
  class ApiClient {
    private baseUrl: string;
    private username: string;
    private password: string;
    
    constructor(baseUrl: string, username: string, password: string) {
      this.baseUrl = baseUrl;
      this.username = username;
      this.password = password;
    }
    
    async getData() {
      const authHeader = 'Basic ' + Buffer.from(`${this.username}:${this.password}`).toString('base64');
      
      try {
        const response = await axios.default.get(`${this.baseUrl}/data`, {
          headers: {
            'Authorization': authHeader
          }
        });
        return response.data;
      } catch (error) {
        console.error('API request failed:', error);
        throw error;
      }
    }
  }
  
  const client = new ApiClient('https://api.example.com', 'user', 'pass');
  client.getData().then(console.log).catch(console.error);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_15() {
  // ruleid: typescript-httpbasic-authentication
  function configureBasicAuth(app: express.Application) {
    app.use((req, res, next) => {
      // Check for Basic auth header
      if (!req.headers.authorization || req.headers.authorization.indexOf('Basic ') === -1) {
        res.setHeader('WWW-Authenticate', 'Basic');
        return res.status(401).json({ message: 'Missing Authorization Header' });
      }
      
      // Verify auth credentials
      const base64Credentials = req.headers.authorization.split(' ')[1];
      const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
      const [username, password] = credentials.split(':');
      
      const isValid = username === 'service_account' && password === 'service_password';
      
      if (!isValid) {
        return res.status(401).json({ message: 'Invalid Authentication Credentials' });
      }
      
      // Attach user to request object
      req.user = { username };
      next();
    });
  }
  
  const app = express();
  configureBasicAuth(app);
  app.listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // Set up HTTPS server with SSL/TLS
  const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert'),
    requestCert: true,
    rejectUnauthorized: true,
    ca: [fs.readFileSync('client-ca.crt')]
  };
  
  // ok: typescript-httpbasic-authentication
  const server = https.createServer(options, app);
  
  app.get('/', (req, res) => {
    const clientCert = req.socket.getPeerCertificate();
    
    if (req.client.authorized) {
      res.send(`Hello ${clientCert.subject.CN}, your certificate was issued by ${clientCert.issuer.CN}!`);
    } else {
      res.status(401).send('Sorry, but you need to provide a client certificate to continue.');
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // JWT authentication strategy
  const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'your_jwt_secret'
  };
  
  passport.use(new JwtStrategy(jwtOptions, (payload, done) => {
    // Find user by payload.sub
    const user = { id: payload.sub, name: payload.name };
    if (user) {
      return done(null, user);
    } else {
      return done(null, false);
    }
  }));
  
  // ok: typescript-httpbasic-authentication
  app.get('/api/data', 
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
      res.json({ message: 'Secret data' });
    }
  );
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // Set up OAuth 2.0 server
  const server = oauth2orize.createServer();
  
  // ok: typescript-httpbasic-authentication
  app.use(session({
    secret: 'oauth2 secret',
    saveUninitialized: true,
    resave: true
  }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());
  
  // Exchange username & password for access token
  server.exchange(oauth2orize.exchange.password((client, username, password, scope, done) => {
    if (username === 'user' && password === 'pass') {
      const token = crypto.randomBytes(32).toString('hex');
      return done(null, token);
    }
    return done(null, false);
  }));
  
  // Token endpoint
  app.post('/oauth/token',
    passport.authenticate(['oauth2-client-password'], { session: false }),
    server.token(),
    server.errorHandler()
  );
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  // ok: typescript-httpbasic-authentication
  app.use(helmet());
  
  // Bearer token authentication
  app.use((req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).send('Authentication required');
    }
    
    const token = authHeader.split(' ')[1];
    
    try {
      // Verify JWT token
      const decoded = require('jsonwebtoken').verify(token, 'your_secret_key');
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).send('Invalid token');
    }
  });
  
  app.get('/api/protected', (req, res) => {
    res.json({ message: 'Protected data', user: req.user });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // ok: typescript-httpbasic-authentication
  passport.use(new BearerStrategy(
    (token, done) => {
      // Verify token
      if (token === 'valid-token') {
        return done(null, { id: '123', name: 'User' }, { scope: 'read' });
      }
      return done(null, false);
    }
  ));
  
  app.get('/api/resource',
    passport.authenticate('bearer', { session: false }),
    (req, res) => {
      res.json({ message: 'Secure resource' });
    }
  );
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_6() {
  // ok: typescript-httpbasic-authentication
  class SecureApiClient {
    private baseUrl: string;
    private apiKey: string;
    
    constructor(baseUrl: string, apiKey: string) {
      this.baseUrl = baseUrl;
      this.apiKey = apiKey;
    }
    
    async getData() {
      try {
        const response = await axios.default.get(`${this.baseUrl}/data`, {
          headers: {
            'X-API-Key': this.apiKey
          }
        });
        return response.data;
      } catch (error) {
        console.error('API request failed:', error);
        throw error;
      }
    }
  }
  
  const client = new SecureApiClient('https://api.example.com', 'api_key_123');
  client.getData().then(console.log).catch(console.error);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: typescript-httpbasic-authentication
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: true,
      httpOnly: true,
      maxAge: 3600000
    }
  }));
  
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (username === 'user' && password === 'pass') {
      req.session.authenticated = true;
      req.session.user = { id: '123', username };
      res.redirect('/dashboard');
    } else {
      res.status(401).send('Invalid credentials');
    }
  });
  
  app.get('/dashboard', (req, res) => {
    if (req.session.authenticated) {
      res.send(`Welcome ${req.session.user.username}`);
    } else {
      res.redirect('/login');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_8() {
  // ok: typescript-httpbasic-authentication
  const fetchWithToken = async (url: string, token: string) => {
    const headers = new Headers();
    headers.set('Authorization', `Bearer ${token}`);
    
    try {
      const response = await fetch(url, { headers });
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error('Fetch error:', error);
      throw error;
    }
  };
  
  // Get token from secure storage or authentication service
  const getAuthToken = () => {
    return 'jwt_token_from_secure_storage';
  };
  
  fetchWithToken('https://api.example.com/data', getAuthToken())
    .then(data => console.log(data))
    .catch(error => console.error(error));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // ok: typescript-httpbasic-authentication
  const apiKeyAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({ message: 'API key is required' });
    }
    
    // Validate API key (in a real app, check against database or secure storage)
    if (apiKey === 'valid_api_key_123') {
      next();
    } else {
      return res.status(401).json({ message: 'Invalid API key' });
    }
  };
  
  app.get('/api/data', apiKeyAuth, (req, res) => {
    res.json({ message: 'Secure data accessed with API key' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_10() {
  // ok: typescript-httpbasic-authentication
  class AuthService {
    private jwtSecret: string;
    
    constructor(jwtSecret: string) {
      this.jwtSecret = jwtSecret;
    }
    
    generateToken(userId: string, username: string): string {
      return require('jsonwebtoken').sign(
        { sub: userId, username, iat: Date.now() / 1000 },
        this.jwtSecret,
        { expiresIn: '1h' }
      );
    }
    
    verifyToken(token: string): any {
      try {
        return require('jsonwebtoken').verify(token, this.jwtSecret);
      } catch (error) {
        return null;
      }
    }
    
    setupJwtAuth(app: express.Application) {
      app.use((req, res, next) => {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).send('Authentication required');
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = this.verifyToken(token);
        
        if (!decoded) {
          return res.status(401).send('Invalid token');
        }
        
        req.user = decoded;
        next();
      });
    }
  }
  
  const app = express();
  const authService = new AuthService('secure_jwt_secret');
  authService.setupJwtAuth(app);
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_11() {
  // ok: typescript-httpbasic-authentication
  const setupTwoFactorAuth = (app: express.Application) => {
    // First factor: JWT token validation
    app.use((req, res, next) => {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(401).send('Authentication required');
      }
      
      try {
        const decoded = require('jsonwebtoken').verify(token, 'jwt_secret');
        req.user = decoded;
        next();
      } catch (error) {
        return res.status(401).send('Invalid token');
      }
    });
    
    // Second factor: TOTP verification for sensitive operations
    app.post('/api/sensitive-action', (req, res, next) => {
      const { totpCode } = req.body;
      
      if (!totpCode) {
        return res.status(401).send('TOTP code required for this action');
      }
      
      // Verify TOTP code against user's secret
      const isValidTotp = verifyTotp(req.user.id, totpCode);
      
      if (!isValidTotp) {
        return res.status(401).send('Invalid TOTP code');
      }
      
      next();
    }, (req, res) => {
      res.json({ message: 'Sensitive action completed successfully' });
    });
  };
  
  function verifyTotp(userId: string, code: string): boolean {
    // In a real app, retrieve user's TOTP secret and verify code
    return code === '123456'; // Simplified for example
  }
  
  const app = express();
  setupTwoFactorAuth(app);
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_12() {
  // ok: typescript-httpbasic-authentication
  class OAuthClient {
    private clientId: string;
    private clientSecret: string;
    private tokenEndpoint: string;
    private accessToken: string | null = null;
    private tokenExpiry: number = 0;
    
    constructor(clientId: string, clientSecret: string, tokenEndpoint: string) {
      this.clientId = clientId;
      this.clientSecret = clientSecret;
      this.tokenEndpoint = tokenEndpoint;
    }
    
    async getAccessToken(): Promise<string> {
      if (this.accessToken && Date.now() < this.tokenExpiry) {
        return this.accessToken;
      }
      
      const params = new URLSearchParams();
      params.append('grant_type', 'client_credentials');
      params.append('client_id', this.clientId);
      params.append('client_secret', this.clientSecret);
      
      try {
        const response = await axios.default.post(this.tokenEndpoint, params);
        this.accessToken = response.data.access_token;
        this.tokenExpiry = Date.now() + (response.data.expires_in * 1000);
        return this.accessToken;
      } catch (error) {
        console.error('Failed to obtain access token:', error);
        throw error;
      }
    }
    
    async makeRequest(url: string): Promise<any> {
      const token = await this.getAccessToken();
      
      try {
        const response = await axios.default.get(url, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        return response.data;
      } catch (error) {
        console.error('Request failed:', error);
        throw error;
      }
    }
  }
  
  const client = new OAuthClient('client_id', 'client_secret', 'https://auth.example.com/token');
  client.makeRequest('https://api.example.com/data').then(console.log).catch(console.error);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_13() {
  // ok: typescript-httpbasic-authentication
  const setupMutualTLS = () => {
    const options = {
      key: fs.readFileSync('server.key'),
      cert: fs.readFileSync('server.cert'),
      ca: [fs.readFileSync('ca.cert')],
      requestCert: true,
      rejectUnauthorized: true
    };
    
    const app = express();
    
    app.use((req, res, next) => {
      const clientCert = req.socket.getPeerCertificate();
      
      if (!req.client.authorized) {
        return res.status(401).send('Invalid client certificate');
      }
      
      // Extract client identity from certificate
      req.clientId = clientCert.subject.CN;
      next();
    });
    
    app.get('/api/secure-data', (req, res) => {
      res.json({
        message: `Hello ${req.clientId}, here's your secure data`,
        data: { key: 'value' }
      });
    });
    
    const server = https.createServer(options, app);
    server.listen(3000);
  };
  
  setupMutualTLS();
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_14() {
  // ok: typescript-httpbasic-authentication
  const setupApiKeyRotation = (app: express.Application) => {
    // In-memory store of valid API keys (in production, use a database)
    const apiKeys = new Map<string, { userId: string, expires: number }>();
    
    // Add initial API key
    apiKeys.set('current_api_key_123', {
      userId: 'user1',
      expires: Date.now() + (30 * 24 * 60 * 60 * 1000) // 30 days
    });
    
    // API key authentication middleware
    app.use((req, res, next) => {
      const apiKey = req.headers['x-api-key'] as string;
      
      if (!apiKey) {
        return res.status(401).send('API key required');
      }
      
      const keyData = apiKeys.get(apiKey);
      
      if (!keyData) {
        return res.status(401).send('Invalid API key');
      }
      
      if (Date.now() > keyData.expires) {
        return res.status(401).send('Expired API key');
      }
      
      req.userId = keyData.userId;
      next();
    });
    
    // Endpoint to rotate API key
    app.post('/api/rotate-key', (req, res) => {
      const currentKey = req.headers['x-api-key'] as string;
      const keyData = apiKeys.get(currentKey);
      
      if (!keyData) {
        return res.status(401).send('Invalid API key');
      }
      
      // Generate new API key
      const newKey = crypto.randomBytes(32).toString('hex');
      
      // Store new key with same user ID
      apiKeys.set(newKey, {
        userId: keyData.userId,
        expires: Date.now() + (30 * 24 * 60 * 60 * 1000) // 30 days
      });
      
      // Invalidate old key after a grace period (e.g., 24 hours)
      setTimeout(() => {
        apiKeys.delete(currentKey);
      }, 24 * 60 * 60 * 1000);
      
      res.json({ newApiKey: newKey });
    });
  };
  
  const app = express();
  setupApiKeyRotation(app);
  app.listen(3000);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_15() {
  // ok: typescript-httpbasic-authentication
  const setupSAMLAuth = (app: express.Application) => {
    const passport = require('passport');
    const SamlStrategy = require('passport-saml').Strategy;
    
    passport.use(new SamlStrategy(
      {
        path: '/login/callback',
        entryPoint: 'https://idp.example.com/saml2/sso',
        issuer: 'passport-saml',
        cert: fs.readFileSync('idp-cert.pem', 'utf8')
      },
      (profile: any, done: any) => {
        // In a real app, find or create user based on profile
        return done(null, {
          id: profile.nameID,
          email: profile.email,
          name: profile.displayName
        });
      }
    ));
    
    passport.serializeUser((user: any, done: any) => {
      done(null, user);
    });
    
    passport.deserializeUser((user: any, done: any) => {
      done(null, user);
    });
    
    app.use(passport.initialize());
    app.use(passport.session());
    
    app.get('/login',
      passport.authenticate('saml', { failureRedirect: '/login', failureFlash: true }),
      (req, res) => {
        res.redirect('/');
      }
    );
    
    app.post('/login/callback',
      passport.authenticate('saml', { failureRedirect: '/login', failureFlash: true }),
      (req, res) => {
        res.redirect('/');
      }
    );
    
    app.get('/secure',
      ensureAuthenticated,
      (req, res) => {
        res.json({ user: req.user });
      }
    );
    
    function ensureAuthenticated(req: express.Request, res: express.Response, next: express.NextFunction) {
      if (req.isAuthenticated()) {
        return next();
      }
      res.redirect('/login');
    }
  };
  
  const app = express();
  setupSAMLAuth(app);
  app.listen(3000);
}
// {/fact}