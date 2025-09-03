// Common imports for examples
const express = require('express');
const csrf = require('csurf');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const axios = require('axios');
const { NextApiRequest, NextApiResponse } from 'next';
const { withIronSession } = require('next-iron-session');
const { ApolloServer } = require('apollo-server-express');
const helmet = require('helmet');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const { buildSchema } = require('graphql');
const multer = require('multer');
const jwt = require('jsonwebtoken');

// TRUE POSITIVES - Vulnerable code examples that should be detected

// Example 1: Express app with CSRF protection explicitly disabled
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true
  }));
  
  // CSRF protection initialized but disabled
  const csrfProtection = csrf({ 
    // ruleid: javascript-csrf-disabled
    ignoreMethods: ['POST', 'PUT', 'DELETE'] // Disables CSRF for all important methods
  });
  
  app.post('/submit-form', csrfProtection, (req, res) => {
    res.send('Form submitted successfully');
  });
}
// {/fact}

// Example 2: Next.js API route with CSRF check disabled
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_2() {
  export default async function handler(req, res) {
    // ruleid: javascript-csrf-disabled
    const config = { csrf: false }; // Explicitly disabling CSRF protection
    
    if (req.method === 'POST') {
      // Process form submission without CSRF validation
      const { username, password } = req.body;
      // Process user data
      res.status(200).json({ success: true });
    } else {
      res.status(405).end();
    }
  }
}
// {/fact}

// Example 3: Express app with disabled CSRF middleware
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true
  }));
  
  // CSRF middleware is created but never used
  const csrfMiddleware = csrf({ cookie: true });
  
  app.post('/api/update-profile', (req, res) => {
    // ruleid: javascript-csrf-disabled
    const skipCSRF = true; // Flag to skip CSRF validation
    
    if (skipCSRF) {
      // Process the request without CSRF validation
      const { name, email } = req.body;
      // Update user profile
      res.json({ success: true });
    }
  });
}
// {/fact}

// Example 4: Apollo GraphQL server with CSRF protection disabled
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_4() {
  const typeDefs = buildSchema(`
    type Query {
      hello: String
    }
    type Mutation {
      updateUser(id: ID!, name: String!): Boolean
    }
  `);
  
  const resolvers = {
    Mutation: {
      updateUser: (parent, args) => {
        // Update user logic
        return true;
      }
    }
  };
  
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    // ruleid: javascript-csrf-disabled
    csrfPrevention: false, // Explicitly disabling CSRF protection
    context: ({ req }) => {
      // Context setup
      return { user: req.user };
    }
  });
}
// {/fact}

// Example 5: Express app with custom CSRF middleware that's disabled
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // Custom CSRF middleware
  function customCSRFMiddleware(req, res, next) {
    // ruleid: javascript-csrf-disabled
    const disableCSRF = true; // Flag to disable CSRF checks
    
    if (disableCSRF || req.path.startsWith('/api/public/')) {
      return next(); // Skip CSRF validation
    }
    
    // CSRF validation logic (never reached when disabled)
    if (!req.headers['x-csrf-token'] || req.headers['x-csrf-token'] !== req.session.csrfToken) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    next();
  }
  
  app.use(customCSRFMiddleware);
  
  app.post('/api/update-settings', (req, res) => {
    // Process request
    res.json({ success: true });
  });
}
// {/fact}

// Example 6: Express app with CSRF disabled for specific routes
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
  
  const csrfProtection = csrf({ cookie: true });
  
  // Apply CSRF protection to all routes
  app.use(csrfProtection);
  
  app.post('/api/sensitive-operation', (req, res, next) => {
    // ruleid: javascript-csrf-disabled
    req.csrfToken = () => ''; // Overriding CSRF token function to bypass protection
    next();
  }, (req, res) => {
    // Process sensitive operation without proper CSRF validation
    res.json({ success: true });
  });
}
// {/fact}

// Example 7: Next.js API with Iron Session but CSRF disabled
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_7() {
  export default withIronSession(
    async (req, res) => {
      if (req.method === 'POST') {
        // ruleid: javascript-csrf-disabled
        const csrfProtectionDisabled = true; // Flag to disable CSRF checks
        
        // Process form submission without CSRF validation
        const { username, password } = req.body;
        // Process user data
        res.status(200).json({ success: true });
      }
    },
    {
      cookieName: "session",
      password: "complex_password_at_least_32_characters",
      cookieOptions: {
        secure: process.env.NODE_ENV === "production",
      },
    }
  );
}
// {/fact}

// Example 8: Express app with cookie settings that make CSRF protection ineffective
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  app.use(cookieParser());
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
      // ruleid: javascript-csrf-disabled
      sameSite: 'none', // Setting sameSite to none without secure flag can lead to CSRF
      secure: false     // Missing secure flag with sameSite=none
    }
  }));
  
  app.post('/api/transfer-money', (req, res) => {
    // Process money transfer without proper CSRF protection
    const { amount, recipient } = req.body;
    // Transfer money logic
    res.json({ success: true });
  });
}
// {/fact}

// Example 9: Express app with CSRF token validation but implementation bypassed
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  app.post('/api/update-account', (req, res) => {
    // ruleid: javascript-csrf-disabled
    const bypassCSRFCheck = req.query.admin === 'true'; // Backdoor to bypass CSRF check
    
    if (!bypassCSRFCheck && (!req.body._csrf || req.body._csrf !== req.session.csrfToken)) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    // Process account update
    res.json({ success: true });
  });
}
// {/fact}

// Example 10: Express app with CSRF disabled in development mode
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ruleid: javascript-csrf-disabled
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  if (!isDevelopment) {
    app.use(csrf({ cookie: true }));
  }
  
  app.post('/api/update-profile', (req, res) => {
    // In development mode, this route has no CSRF protection
    const { name, email } = req.body;
    // Update profile logic
    res.json({ success: true });
  });
}
// {/fact}

// Example 11: Express app with conditional CSRF middleware that can be bypassed
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.use((req, res, next) => {
    // ruleid: javascript-csrf-disabled
    if (req.headers['x-bypass-csrf'] === 'true') {
      // Skip CSRF check based on a header that can be easily set by attackers
      req.skipCSRF = true;
    }
    next();
  });
  
  app.use((req, res, next) => {
    if (!req.skipCSRF) {
      csrf({ cookie: true })(req, res, next);
    } else {
      next();
    }
  });
  
  app.post('/api/admin/action', (req, res) => {
    // Process admin action
    res.json({ success: true });
  });
}
// {/fact}

// Example 12: Express app with CSRF protection removed for API endpoints
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // Apply CSRF protection to all routes
  app.use((req, res, next) => {
    // ruleid: javascript-csrf-disabled
    if (req.path.startsWith('/api/')) {
      // Disable CSRF for all API routes
      return next();
    }
    
    csrf({ cookie: true })(req, res, next);
  });
  
  app.post('/api/user/settings', (req, res) => {
    // Process user settings update without CSRF protection
    res.json({ success: true });
  });
}
// {/fact}

// Example 13: Express app with CSRF token validation but with a bypass
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  app.post('/api/change-password', (req, res) => {
    // ruleid: javascript-csrf-disabled
    if (req.body.internal_request === true) {
      // Skip CSRF validation for "internal" requests
      // This can be exploited if an attacker can set this field
      const { oldPassword, newPassword } = req.body;
      // Change password logic
      return res.json({ success: true });
    }
    
    // CSRF validation for "external" requests
    if (req.body._csrf !== req.session.csrfToken) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    // Process password change
    res.json({ success: true });
  });
}
// {/fact}

// Example 14: Express app with CSRF disabled for specific HTTP methods
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  app.use((req, res, next) => {
    // ruleid: javascript-csrf-disabled
    if (req.method === 'PUT' || req.method === 'DELETE') {
      // Skip CSRF protection for PUT and DELETE methods
      return next();
    }
    
    csrf({ cookie: true })(req, res, next);
  });
  
  app.put('/api/user/:id', (req, res) => {
    // Update user without CSRF protection
    const userId = req.params.id;
    const userData = req.body;
    // Update user logic
    res.json({ success: true });
  });
}
// {/fact}

// Example 15: Express app with CSRF token check but implementation is flawed
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  app.post('/api/submit-form', (req, res) => {
    // ruleid: javascript-csrf-disabled
    const csrfToken = req.cookies.csrf_token; // Getting CSRF token from a cookie
    
    // This is vulnerable because the attacker can read and submit the cookie value
    if (req.body._csrf !== csrfToken) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    // Process form submission
    res.json({ success: true });
  });
}
// {/fact}

// TRUE NEGATIVES - Secure code examples that should not be detected

// Example 1: Express app with proper CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true
  }));
  
  // ok: javascript-csrf-disabled
  const csrfProtection = csrf({ cookie: true });
  
  app.get('/form', csrfProtection, (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
  });
  
  app.post('/submit-form', csrfProtection, (req, res) => {
    res.send('Form submitted successfully');
  });
}
// {/fact}

// Example 2: Next.js API route with CSRF protection enabled
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_2() {
  export default async function handler(req, res) {
    // ok: javascript-csrf-disabled
    const config = { csrf: true }; // Explicitly enabling CSRF protection
    
    if (req.method === 'POST') {
      // Validate CSRF token
      if (!req.body._csrf || req.body._csrf !== req.session.csrfToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
      }
      
      // Process form submission with CSRF validation
      const { username, password } = req.body;
      // Process user data
      res.status(200).json({ success: true });
    } else {
      res.status(405).end();
    }
  }
}
// {/fact}

// Example 3: Express app with proper CSRF middleware
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_3() {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true
  }));
  
  // ok: javascript-csrf-disabled
  app.use(csrf({ cookie: true }));
  
  app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
  });
  
  app.post('/api/update-profile', (req, res) => {
    // CSRF validation is handled by the middleware
    const { name, email } = req.body;
    // Update user profile
    res.json({ success: true });
  });
}
// {/fact}

// Example 4: Apollo GraphQL server with CSRF protection enabled
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_4() {
  const typeDefs = buildSchema(`
    type Query {
      hello: String
    }
    type Mutation {
      updateUser(id: ID!, name: String!): Boolean
    }
  `);
  
  const resolvers = {
    Mutation: {
      updateUser: (parent, args) => {
        // Update user logic
        return true;
      }
    }
  };
  
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    // ok: javascript-csrf-disabled
    csrfPrevention: true, // Explicitly enabling CSRF protection
    context: ({ req }) => {
      // Context setup
      return { user: req.user };
    }
  });
}
// {/fact}

// Example 5: Express app with custom CSRF middleware that's properly implemented
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_5() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // Custom CSRF middleware
  function customCSRFMiddleware(req, res, next) {
    // Skip CSRF for GET, HEAD, OPTIONS requests (safe methods)
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next();
    }
    
    // ok: javascript-csrf-disabled
    // CSRF validation logic for unsafe methods
    if (!req.headers['x-csrf-token'] || req.headers['x-csrf-token'] !== req.session.csrfToken) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    next();
  }
  
  app.use(customCSRFMiddleware);
  
  app.post('/api/update-settings', (req, res) => {
    // Process request (CSRF already validated)
    res.json({ success: true });
  });
}
// {/fact}

// Example 6: Express app with proper cookie settings for CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_6() {
  const app = express();
  app.use(cookieParser());
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
      // ok: javascript-csrf-disabled
      sameSite: 'lax', // SameSite=Lax provides some CSRF protection
      secure: process.env.NODE_ENV === 'production' // Secure in production
    }
  }));
  
  app.use(csrf({ cookie: true }));
  
  app.post('/api/transfer-money', (req, res) => {
    // Process money transfer with CSRF protection
    const { amount, recipient } = req.body;
    // Transfer money logic
    res.json({ success: true });
  });
}
// {/fact}

// Example 7: Next.js API with Iron Session and CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_7() {
  export default withIronSession(
    async (req, res) => {
      if (req.method === 'POST') {
        // ok: javascript-csrf-disabled
        // Validate CSRF token
        if (!req.body.csrfToken || req.body.csrfToken !== req.session.csrfToken) {
          return res.status(403).json({ error: 'Invalid CSRF token' });
        }
        
        // Process form submission with CSRF validation
        const { username, password } = req.body;
        // Process user data
        res.status(200).json({ success: true });
      }
    },
    {
      cookieName: "session",
      password: "complex_password_at_least_32_characters",
      cookieOptions: {
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax"
      },
    }
  );
}
// {/fact}

// Example 8: Express app with Helmet's CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_8() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: javascript-csrf-disabled
  app.use(helmet());
  app.use(csrf({ cookie: true }));
  
  app.get('/form', (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
  });
  
  app.post('/api/submit-form', (req, res) => {
    // CSRF validation is handled by the middleware
    // Process form submission
    res.json({ success: true });
  });
}
// {/fact}

// Example 9: Express app with double submit cookie pattern for CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_9() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  
  // Generate CSRF token
  app.get('/api/csrf-token', (req, res) => {
    const csrfToken = require('crypto').randomBytes(16).toString('hex');
    res.cookie('XSRF-TOKEN', csrfToken, { 
      httpOnly: false, 
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production'
    });
    res.json({ csrfToken });
  });
  
  app.post('/api/update-account', (req, res) => {
    // ok: javascript-csrf-disabled
    // Double submit cookie pattern
    const cookieToken = req.cookies['XSRF-TOKEN'];
    const headerToken = req.headers['x-xsrf-token'];
    
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    // Process account update
    res.json({ success: true });
  });
}
// {/fact}

// Example 10: Express app with proper CSRF protection in all environments
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_10() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: javascript-csrf-disabled
  // Apply CSRF protection in all environments
  app.use(csrf({ cookie: true }));
  
  app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
  });
  
  app.post('/api/update-profile', (req, res) => {
    // CSRF validation is handled by the middleware
    const { name, email } = req.body;
    // Update profile logic
    res.json({ success: true });
  });
}
// {/fact}

// Example 11: Express app with SPA-friendly CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_11() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: javascript-csrf-disabled
  // Generate CSRF token and set as cookie
  app.use((req, res, next) => {
    if (!req.session.csrfToken) {
      req.session.csrfToken = require('crypto').randomBytes(16).toString('hex');
      res.cookie('XSRF-TOKEN', req.session.csrfToken, { 
        httpOnly: false, 
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production'
      });
    }
    next();
  });
  
  // Validate CSRF token for unsafe methods
  app.use((req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next();
    }
    
    const token = req.headers['x-xsrf-token'] || req.body._csrf;
    if (!token || token !== req.session.csrfToken) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    next();
  });
  
  app.post('/api/user/settings', (req, res) => {
    // Process user settings update with CSRF protection
    res.json({ success: true });
  });
}
// {/fact}

// Example 12: Express app with proper CSRF protection for all routes
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_12() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: javascript-csrf-disabled
  const csrfProtection = csrf({ cookie: { sameSite: 'strict' } });
  
  // Apply CSRF protection to all routes that need it
  app.get('/form', csrfProtection, (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
  });
  
  app.post('/api/submit-form', csrfProtection, (req, res) => {
    // Process form submission with CSRF protection
    res.json({ success: true });
  });
  
  app.put('/api/update/:id', csrfProtection, (req, res) => {
    // Update resource with CSRF protection
    res.json({ success: true });
  });
  
  app.delete('/api/delete/:id', csrfProtection, (req, res) => {
    // Delete resource with CSRF protection
    res.json({ success: true });
  });
}
// {/fact}

// Example 13: Express app with CSRF protection and proper token handling
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_13() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: javascript-csrf-disabled
  app.use(csrf({ cookie: true }));
  
  app.post('/api/change-password', (req, res) => {
    // CSRF validation is handled by the middleware
    const { oldPassword, newPassword } = req.body;
    
    // Additional security checks
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Change password logic
    res.json({ success: true });
  });
}
// {/fact}

// Example 14: Express app with CSRF protection for all unsafe methods
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_14() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: javascript-csrf-disabled
  app.use((req, res, next) => {
    // Skip CSRF for safe methods
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next();
    }
    
    // Apply CSRF protection to all unsafe methods
    csrf({ cookie: true })(req, res, next);
  });
  
  app.put('/api/user/:id', (req, res) => {
    // Update user with CSRF protection
    const userId = req.params.id;
    const userData = req.body;
    // Update user logic
    res.json({ success: true });
  });
}
// {/fact}

// Example 15: Express app with synchronizer token pattern for CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_15() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // Generate CSRF token
  app.get('/api/csrf-token', (req, res) => {
    // ok: javascript-csrf-disabled
    // Generate a new CSRF token and store it in the session
    req.session.csrfToken = require('crypto').randomBytes(16).toString('hex');
    res.json({ csrfToken: req.session.csrfToken });
  });
  
  app.post('/api/submit-form', (req, res) => {
    // Validate CSRF token using synchronizer token pattern
    if (!req.body._csrf || req.body._csrf !== req.session.csrfToken) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    // Process form submission
    res.json({ success: true });
  });
}
// {/fact}