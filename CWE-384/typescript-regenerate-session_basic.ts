// Import necessary modules
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Request, Response, NextFunction } from 'express';
import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import { SessionData } from 'express-session';
import { User } from './types'; // Assumed type definition

// TRUE POSITIVES (Vulnerable code examples)

// Example 1: Basic login without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
  }));
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    // Authenticate user (simplified)
    if (username === 'admin' && password === 'password') {
      // ruleid: typescript-regenerate-session
      req.session.userId = 123;
      req.session.authenticated = true;
      res.redirect('/dashboard');
    } else {
      res.redirect('/login');
    }
  });
}
// {/fact}

// Example 2: Using passport.js without regenerating session
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  app.use(passport.initialize());
  app.use(passport.session());
  
  passport.use(new LocalStrategy((username, password, done) => {
    // Simplified authentication
    if (username === 'admin' && password === 'password') {
      return done(null, { id: 123, username: 'admin' });
    }
    return done(null, false);
  }));
  
  app.post('/login', passport.authenticate('local'), (req: Request, res: Response) => {
    // ruleid: typescript-regenerate-session
    req.session.lastLogin = new Date();
    res.redirect('/dashboard');
  });
}
// {/fact}

// Example 3: Custom authentication with session modification
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.post('/api/authenticate', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    authenticateUser(username, password)
      .then(user => {
        if (user) {
          // ruleid: typescript-regenerate-session
          req.session.user = user;
          req.session.isLoggedIn = true;
          req.session.permissions = getUserPermissions(user.id);
          res.json({ success: true });
        } else {
          res.status(401).json({ success: false });
        }
      });
  });
  
  function authenticateUser(username: string, password: string): Promise<User | null> {
    // Simplified authentication logic
    return Promise.resolve({ id: 123, username: 'admin' });
  }
  
  function getUserPermissions(userId: number): string[] {
    return ['read', 'write'];
  }
}
// {/fact}

// Example 4: OAuth callback without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.get('/auth/oauth/callback', (req: Request, res: Response) => {
    const { code } = req.query;
    
    // Exchange code for token (simplified)
    const token = exchangeCodeForToken(code as string);
    
    if (token) {
      // Get user info using token
      getUserInfo(token).then(user => {
        // ruleid: typescript-regenerate-session
        req.session.token = token;
        req.session.user = user;
        req.session.authenticated = true;
        res.redirect('/home');
      });
    } else {
      res.redirect('/login');
    }
  });
  
  function exchangeCodeForToken(code: string): string {
    return 'sample-token';
  }
  
  function getUserInfo(token: string): Promise<any> {
    return Promise.resolve({ id: 123, name: 'John Doe' });
  }
}
// {/fact}

// Example 5: Two-factor authentication without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/verify-2fa', (req: Request, res: Response) => {
    const { code } = req.body;
    const userId = req.session.tempUserId;
    
    if (verifyTwoFactorCode(userId, code)) {
      // ruleid: typescript-regenerate-session
      req.session.userId = userId;
      req.session.authenticated = true;
      delete req.session.tempUserId;
      res.redirect('/dashboard');
    } else {
      res.redirect('/login');
    }
  });
  
  function verifyTwoFactorCode(userId: number, code: string): boolean {
    return code === '123456'; // Simplified verification
  }
}
// {/fact}

// Example 6: Login with remember-me functionality without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password, rememberMe } = req.body;
    
    if (validateCredentials(username, password)) {
      const user = findUserByUsername(username);
      
      // ruleid: typescript-regenerate-session
      req.session.userId = user.id;
      req.session.username = user.username;
      
      if (rememberMe) {
        const token = generateRememberMeToken();
        req.session.rememberMeToken = token;
        res.cookie('remember_me', token, { maxAge: 30 * 24 * 60 * 60 * 1000 });
      }
      
      res.redirect('/dashboard');
    } else {
      res.redirect('/login');
    }
  });
  
  function validateCredentials(username: string, password: string): boolean {
    return username === 'admin' && password === 'password';
  }
  
  function findUserByUsername(username: string): any {
    return { id: 123, username: 'admin' };
  }
  
  function generateRememberMeToken(): string {
    return crypto.randomBytes(64).toString('hex');
  }
}
// {/fact}

// Example 7: Role-based login without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.post('/admin/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (isAdminUser(username, password)) {
      // ruleid: typescript-regenerate-session
      req.session.user = { username, role: 'admin' };
      req.session.isAdmin = true;
      req.session.adminLoginTime = new Date();
      
      res.redirect('/admin/dashboard');
    } else {
      res.redirect('/admin/login');
    }
  });
  
  function isAdminUser(username: string, password: string): boolean {
    return username === 'admin' && password === 'adminpass';
  }
}
// {/fact}

// Example 8: API token-based authentication without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.post('/api/token', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (authenticateUser(username, password)) {
      const token = generateApiToken(username);
      
      // ruleid: typescript-regenerate-session
      req.session.apiToken = token;
      req.session.authenticated = true;
      req.session.username = username;
      
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
  
  function authenticateUser(username: string, password: string): boolean {
    return username === 'user' && password === 'pass';
  }
  
  function generateApiToken(username: string): string {
    return `token_${username}_${Date.now()}`;
  }
}
// {/fact}

// Example 9: Social login integration without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/auth/facebook/callback', (req: Request, res: Response) => {
    const { code } = req.query;
    
    // Exchange code for user data (simplified)
    getFacebookUserData(code as string).then(userData => {
      // ruleid: typescript-regenerate-session
      req.session.user = userData;
      req.session.loginProvider = 'facebook';
      req.session.authenticated = true;
      
      res.redirect('/dashboard');
    });
  });
  
  function getFacebookUserData(code: string): Promise<any> {
    return Promise.resolve({
      id: '12345',
      name: 'John Doe',
      email: 'john@example.com'
    });
  }
}
// {/fact}

// Example 10: Password reset flow without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/reset-password', (req: Request, res: Response) => {
    const { token, newPassword } = req.body;
    
    if (validateResetToken(token)) {
      const userId = getUserIdFromToken(token);
      updateUserPassword(userId, newPassword);
      
      // ruleid: typescript-regenerate-session
      req.session.userId = userId;
      req.session.passwordResetTime = new Date();
      req.session.authenticated = true;
      
      res.redirect('/dashboard');
    } else {
      res.redirect('/forgot-password');
    }
  });
  
  function validateResetToken(token: string): boolean {
    return token === 'valid-token';
  }
  
  function getUserIdFromToken(token: string): number {
    return 123;
  }
  
  function updateUserPassword(userId: number, newPassword: string): void {
    // Update password in database
  }
}
// {/fact}

// Example 11: Login with custom session store without regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const RedisStore = require('connect-redis')(session);
  
  app.use(session({
    store: new RedisStore({ host: 'localhost', port: 6379 }),
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
  }));
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      // ruleid: typescript-regenerate-session
      req.session.user = { id: 123, username };
      req.session.authenticated = true;
      req.session.loginTime = new Date();
      
      res.redirect('/dashboard');
    } else {
      res.redirect('/login');
    }
  });
}
// {/fact}

// Example 12: Login with JWT and session without regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  const jwt = require('jsonwebtoken');
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      const token = jwt.sign({ username }, 'secret', { expiresIn: '1h' });
      
      // ruleid: typescript-regenerate-session
      req.session.jwtToken = token;
      req.session.authenticated = true;
      
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
}
// {/fact}

// Example 13: Login with multiple authentication factors without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/complete-auth', (req: Request, res: Response) => {
    const { emailCode, smsCode } = req.body;
    const userId = req.session.pendingUserId;
    
    if (verifyEmailCode(userId, emailCode) && verifySmsCode(userId, smsCode)) {
      // ruleid: typescript-regenerate-session
      req.session.userId = userId;
      req.session.authenticated = true;
      req.session.authMethod = 'multi-factor';
      delete req.session.pendingUserId;
      
      res.redirect('/dashboard');
    } else {
      res.redirect('/login');
    }
  });
  
  function verifyEmailCode(userId: number, code: string): boolean {
    return code === '123456';
  }
  
  function verifySmsCode(userId: number, code: string): boolean {
    return code === '654321';
  }
}
// {/fact}

// Example 14: Login with privilege escalation without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.post('/escalate-privileges', (req: Request, res: Response) => {
    const { adminPassword } = req.body;
    const userId = req.session.userId;
    
    if (verifyAdminPassword(adminPassword)) {
      // ruleid: typescript-regenerate-session
      req.session.isAdmin = true;
      req.session.privileges = ['read', 'write', 'delete', 'admin'];
      req.session.escalationTime = new Date();
      
      res.redirect('/admin/dashboard');
    } else {
      res.redirect('/dashboard');
    }
  });
  
  function verifyAdminPassword(password: string): boolean {
    return password === 'admin123';
  }
}
// {/fact}

// Example 15: Custom authentication middleware without session regeneration
// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      // ruleid: typescript-regenerate-session
      req.session.user = { username };
      req.session.authenticated = true;
      next();
    } else {
      res.status(401).send('Unauthorized');
    }
  };
  
  app.post('/login', authMiddleware, (req: Request, res: Response) => {
    res.redirect('/dashboard');
  });
}
// {/fact}

// TRUE NEGATIVES (Secure code examples)

// Example 1: Basic login with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
  }));
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    // Authenticate user (simplified)
    if (username === 'admin' && password === 'password') {
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.userId = 123;
        req.session.authenticated = true;
        res.redirect('/dashboard');
      });
    } else {
      res.redirect('/login');
    }
  });
}
// {/fact}

// Example 2: Using passport.js with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_2() {
  const app = express();
  app.use(passport.initialize());
  app.use(passport.session());
  
  passport.use(new LocalStrategy((username, password, done) => {
    // Simplified authentication
    if (username === 'admin' && password === 'password') {
      return done(null, { id: 123, username: 'admin' });
    }
    return done(null, false);
  }));
  
  app.post('/login', passport.authenticate('local'), (req: Request, res: Response) => {
    // ok: typescript-regenerate-session
    req.session.regenerate((err) => {
      if (err) {
        res.status(500).send('Error regenerating session');
        return;
      }
      
      req.session.lastLogin = new Date();
      res.redirect('/dashboard');
    });
  });
}
// {/fact}

// Example 3: Custom authentication with proper session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.post('/api/authenticate', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    authenticateUser(username, password)
      .then(user => {
        if (user) {
          // ok: typescript-regenerate-session
          req.session.regenerate((err) => {
            if (err) {
              res.status(500).json({ success: false, error: 'Session regeneration failed' });
              return;
            }
            
            req.session.user = user;
            req.session.isLoggedIn = true;
            req.session.permissions = getUserPermissions(user.id);
            res.json({ success: true });
          });
        } else {
          res.status(401).json({ success: false });
        }
      });
  });
  
  function authenticateUser(username: string, password: string): Promise<User | null> {
    // Simplified authentication logic
    return Promise.resolve({ id: 123, username: 'admin' });
  }
  
  function getUserPermissions(userId: number): string[] {
    return ['read', 'write'];
  }
}
// {/fact}

// Example 4: OAuth callback with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.get('/auth/oauth/callback', (req: Request, res: Response) => {
    const { code } = req.query;
    
    // Exchange code for token (simplified)
    const token = exchangeCodeForToken(code as string);
    
    if (token) {
      // Get user info using token
      getUserInfo(token).then(user => {
        // ok: typescript-regenerate-session
        req.session.regenerate((err) => {
          if (err) {
            res.status(500).send('Error regenerating session');
            return;
          }
          
          req.session.token = token;
          req.session.user = user;
          req.session.authenticated = true;
          res.redirect('/home');
        });
      });
    } else {
      res.redirect('/login');
    }
  });
  
  function exchangeCodeForToken(code: string): string {
    return 'sample-token';
  }
  
  function getUserInfo(token: string): Promise<any> {
    return Promise.resolve({ id: 123, name: 'John Doe' });
  }
}
// {/fact}

// Example 5: Two-factor authentication with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/verify-2fa', (req: Request, res: Response) => {
    const { code } = req.body;
    const userId = req.session.tempUserId;
    
    if (verifyTwoFactorCode(userId, code)) {
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.userId = userId;
        req.session.authenticated = true;
        res.redirect('/dashboard');
      });
    } else {
      res.redirect('/login');
    }
  });
  
  function verifyTwoFactorCode(userId: number, code: string): boolean {
    return code === '123456'; // Simplified verification
  }
}
// {/fact}

// Example 6: Login with remember-me functionality and session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password, rememberMe } = req.body;
    
    if (validateCredentials(username, password)) {
      const user = findUserByUsername(username);
      
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.userId = user.id;
        req.session.username = user.username;
        
        if (rememberMe) {
          const token = generateRememberMeToken();
          req.session.rememberMeToken = token;
          res.cookie('remember_me', token, { maxAge: 30 * 24 * 60 * 60 * 1000 });
        }
        
        res.redirect('/dashboard');
      });
    } else {
      res.redirect('/login');
    }
  });
  
  function validateCredentials(username: string, password: string): boolean {
    return username === 'admin' && password === 'password';
  }
  
  function findUserByUsername(username: string): any {
    return { id: 123, username: 'admin' };
  }
  
  function generateRememberMeToken(): string {
    return crypto.randomBytes(64).toString('hex');
  }
}
// {/fact}

// Example 7: Role-based login with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.post('/admin/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (isAdminUser(username, password)) {
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.user = { username, role: 'admin' };
        req.session.isAdmin = true;
        req.session.adminLoginTime = new Date();
        
        res.redirect('/admin/dashboard');
      });
    } else {
      res.redirect('/admin/login');
    }
  });
  
  function isAdminUser(username: string, password: string): boolean {
    return username === 'admin' && password === 'adminpass';
  }
}
// {/fact}

// Example 8: API token-based authentication with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.post('/api/token', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (authenticateUser(username, password)) {
      const token = generateApiToken(username);
      
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).json({ error: 'Session regeneration failed' });
          return;
        }
        
        req.session.apiToken = token;
        req.session.authenticated = true;
        req.session.username = username;
        
        res.json({ token });
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
  
  function authenticateUser(username: string, password: string): boolean {
    return username === 'user' && password === 'pass';
  }
  
  function generateApiToken(username: string): string {
    return `token_${username}_${Date.now()}`;
  }
}
// {/fact}

// Example 9: Social login integration with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/auth/facebook/callback', (req: Request, res: Response) => {
    const { code } = req.query;
    
    // Exchange code for user data (simplified)
    getFacebookUserData(code as string).then(userData => {
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.user = userData;
        req.session.loginProvider = 'facebook';
        req.session.authenticated = true;
        
        res.redirect('/dashboard');
      });
    });
  });
  
  function getFacebookUserData(code: string): Promise<any> {
    return Promise.resolve({
      id: '12345',
      name: 'John Doe',
      email: 'john@example.com'
    });
  }
}
// {/fact}

// Example 10: Password reset flow with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/reset-password', (req: Request, res: Response) => {
    const { token, newPassword } = req.body;
    
    if (validateResetToken(token)) {
      const userId = getUserIdFromToken(token);
      updateUserPassword(userId, newPassword);
      
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.userId = userId;
        req.session.passwordResetTime = new Date();
        req.session.authenticated = true;
        
        res.redirect('/dashboard');
      });
    } else {
      res.redirect('/forgot-password');
    }
  });
  
  function validateResetToken(token: string): boolean {
    return token === 'valid-token';
  }
  
  function getUserIdFromToken(token: string): number {
    return 123;
  }
  
  function updateUserPassword(userId: number, newPassword: string): void {
    // Update password in database
  }
}
// {/fact}

// Example 11: Login with custom session store and regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const RedisStore = require('connect-redis')(session);
  
  app.use(session({
    store: new RedisStore({ host: 'localhost', port: 6379 }),
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
  }));
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.user = { id: 123, username };
        req.session.authenticated = true;
        req.session.loginTime = new Date();
        
        res.redirect('/dashboard');
      });
    } else {
      res.redirect('/login');
    }
  });
}
// {/fact}

// Example 12: Login with JWT and session with regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_12() {
  const app = express();
  const jwt = require('jsonwebtoken');
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      const token = jwt.sign({ username }, 'secret', { expiresIn: '1h' });
      
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).json({ error: 'Session regeneration failed' });
          return;
        }
        
        req.session.jwtToken = token;
        req.session.authenticated = true;
        
        res.json({ token });
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
}
// {/fact}

// Example 13: Login with multiple authentication factors and session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/complete-auth', (req: Request, res: Response) => {
    const { emailCode, smsCode } = req.body;
    const userId = req.session.pendingUserId;
    
    if (verifyEmailCode(userId, emailCode) && verifySmsCode(userId, smsCode)) {
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.userId = userId;
        req.session.authenticated = true;
        req.session.authMethod = 'multi-factor';
        
        res.redirect('/dashboard');
      });
    } else {
      res.redirect('/login');
    }
  });
  
  function verifyEmailCode(userId: number, code: string): boolean {
    return code === '123456';
  }
  
  function verifySmsCode(userId: number, code: string): boolean {
    return code === '654321';
  }
}
// {/fact}

// Example 14: Login with privilege escalation and session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.post('/escalate-privileges', (req: Request, res: Response) => {
    const { adminPassword } = req.body;
    const userId = req.session.userId;
    
    if (verifyAdminPassword(adminPassword)) {
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.userId = userId; // Preserve the user ID
        req.session.isAdmin = true;
        req.session.privileges = ['read', 'write', 'delete', 'admin'];
        req.session.escalationTime = new Date();
        
        res.redirect('/admin/dashboard');
      });
    } else {
      res.redirect('/dashboard');
    }
  });
  
  function verifyAdminPassword(password: string): boolean {
    return password === 'admin123';
  }
}
// {/fact}

// Example 15: Custom authentication middleware with session regeneration
// {fact rule=session-fixation@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      // ok: typescript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).send('Error regenerating session');
          return;
        }
        
        req.session.user = { username };
        req.session.authenticated = true;
        next();
      });
    } else {
      res.status(401).send('Unauthorized');
    }
  };
  
  app.post('/login', authMiddleware, (req: Request, res: Response) => {
    res.redirect('/dashboard');
  });
}
// {/fact}