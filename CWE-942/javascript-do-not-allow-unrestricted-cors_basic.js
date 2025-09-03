// Filename: cors_examples.js

const express = require('express');
const cors = require('cors');
const http = require('http');
const https = require('https');
const axios = require('axios');
const fastify = require('fastify')();
const Koa = require('koa');
const koaCors = require('@koa/cors');
const restify = require('restify');
const helmet = require('helmet');

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Express app with wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // ruleid: javascript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: '*'
  }));
  
  app.get('/api/user-data', (req, res) => {
    res.json({ username: 'john_doe', email: 'john@example.com' });
  });
  
  app.listen(3000);
}
// {/fact}

// Example 2: Express app with manual CORS headers
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.use((req, res, next) => {
    // ruleid: javascript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
  });
  
  app.get('/api/sensitive-data', (req, res) => {
    res.json({ secretKey: 'abc123', userId: 42 });
  });
  
  app.listen(3001);
}
// {/fact}

// Example 3: Node.js HTTP server with wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_3() {
  const server = http.createServer((req, res) => {
    // ruleid: javascript-do-not-allow-unrestricted-cors
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.url === '/api/data' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: 'sensitive information' }));
    }
  });
  
  server.listen(3002);
}
// {/fact}

// Example 4: Express middleware function with wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  function setupCors(req, res, next) {
    // ruleid: javascript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
  }
  
  app.use(setupCors);
  
  app.get('/api/payment-info', (req, res) => {
    res.json({ cardNumber: '****-****-****-1234', expiryDate: '12/25' });
  });
  
  app.listen(3003);
}
// {/fact}

// Example 5: Fastify with wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_5() {
  // ruleid: javascript-do-not-allow-unrestricted-cors
  fastify.register(require('@fastify/cors'), { 
    origin: '*'
  });
  
  fastify.get('/api/user-profile', async (request, reply) => {
    return { name: 'Jane Doe', role: 'admin' };
  });
  
  fastify.listen({ port: 3004 });
}
// {/fact}

// Example 6: Koa with wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_6() {
  const app = new Koa();
  
  // ruleid: javascript-do-not-allow-unrestricted-cors
  app.use(koaCors({
    origin: '*'
  }));
  
  app.use(async ctx => {
    if (ctx.path === '/api/admin') {
      ctx.body = { adminAccess: true, privileges: ['read', 'write', 'delete'] };
    }
  });
  
  app.listen(3005);
}
// {/fact}

// Example 7: Restify with wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_7() {
  const server = restify.createServer();
  
  // ruleid: javascript-do-not-allow-unrestricted-cors
  server.use(function crossOrigin(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'X-Requested-With');
    return next();
  });
  
  server.get('/api/financial-records', function(req, res, next) {
    res.send({ income: 75000, expenses: 50000 });
    return next();
  });
  
  server.listen(3006);
}
// {/fact}

// Example 8: Express with conditional wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) {
      // ruleid: javascript-do-not-allow-unrestricted-cors
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET,POST');
    }
    next();
  });
  
  app.get('/api/health-records', (req, res) => {
    res.json({ patientId: 'P12345', diagnosis: 'Confidential' });
  });
  
  app.listen(3007);
}
// {/fact}

// Example 9: Express with route-specific wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/api/account-details', (req, res) => {
    // ruleid: javascript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', '*');
    res.json({ accountNumber: '987654321', balance: 5000 });
  });
  
  app.listen(3008);
}
// {/fact}

// Example 10: Node.js HTTPS server with wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_10() {
  const options = {
    key: 'private-key-content',
    cert: 'certificate-content'
  };
  
  const server = https.createServer(options, (req, res) => {
    // ruleid: javascript-do-not-allow-unrestricted-cors
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/json');
    
    if (req.url === '/api/secure-data') {
      res.end(JSON.stringify({ secureData: 'top secret' }));
    }
  });
  
  server.listen(3009);
}
// {/fact}

// Example 11: Express with dynamic but always wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.use((req, res, next) => {
    const origin = '*'; // Always wildcard, but stored in a variable
    // ruleid: javascript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', origin);
    next();
  });
  
  app.get('/api/personal-info', (req, res) => {
    res.json({ ssn: '123-45-6789', dob: '1980-01-01' });
  });
  
  app.listen(3010);
}
// {/fact}

// Example 12: Express with wildcard CORS in specific environment
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  app.use((req, res, next) => {
    if (isDevelopment) {
      // ruleid: javascript-do-not-allow-unrestricted-cors
      res.header('Access-Control-Allow-Origin', '*');
    } else {
      res.header('Access-Control-Allow-Origin', 'https://example.com');
    }
    next();
  });
  
  app.get('/api/user-settings', (req, res) => {
    res.json({ theme: 'dark', notifications: true });
  });
  
  app.listen(3011);
}
// {/fact}

// Example 13: Express with wildcard CORS and additional security headers
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.use(helmet()); // Adding security headers
  
  app.use((req, res, next) => {
    // ruleid: javascript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Content-Security-Policy', "default-src 'self'");
    next();
  });
  
  app.get('/api/documents', (req, res) => {
    res.json([{ id: 1, title: 'Confidential Report' }]);
  });
  
  app.listen(3012);
}
// {/fact}

// Example 14: Express with wildcard CORS in API router
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const apiRouter = express.Router();
  
  apiRouter.use((req, res, next) => {
    // ruleid: javascript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', '*');
    next();
  });
  
  apiRouter.get('/customer-data', (req, res) => {
    res.json({ customerId: 'C789', purchaseHistory: [...] });
  });
  
  app.use('/api', apiRouter);
  app.listen(3013);
}
// {/fact}

// Example 15: Express with wildcard CORS in error handler
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/api/restricted-data', (req, res) => {
    try {
      // Some operation that might fail
      throw new Error('Access denied');
    } catch (error) {
      // ruleid: javascript-do-not-allow-unrestricted-cors
      res.header('Access-Control-Allow-Origin', '*');
      res.status(403).json({ error: error.message });
    }
  });
  
  app.listen(3014);
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// Example 1: Express app with specific origin CORS
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: 'https://trusted-site.com'
  }));
  
  app.get('/api/user-data', (req, res) => {
    res.json({ username: 'john_doe', email: 'john@example.com' });
  });
  
  app.listen(4000);
}
// {/fact}

// Example 2: Express app with array of allowed origins
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: ['https://trusted-site.com', 'https://admin.trusted-site.com']
  }));
  
  app.get('/api/sensitive-data', (req, res) => {
    res.json({ secretKey: 'abc123', userId: 42 });
  });
  
  app.listen(4001);
}
// {/fact}

// Example 3: Express with function to validate origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  const allowedOrigins = ['https://example.com', 'https://www.example.com'];
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: function(origin, callback) {
      if (!origin || allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  }));
  
  app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive information' });
  });
  
  app.listen(4002);
}
// {/fact}

// Example 4: Node.js HTTP server with specific origin CORS
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_4() {
  const server = http.createServer((req, res) => {
    const origin = req.headers.origin;
    
    // ok: javascript-do-not-allow-unrestricted-cors
    if (origin === 'https://trusted-site.com') {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.url === '/api/payment-info' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ cardNumber: '****-****-****-1234', expiryDate: '12/25' }));
    }
  });
  
  server.listen(4003);
}
// {/fact}

// Example 5: Express with environment-based CORS configuration
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  const allowedOrigins = process.env.NODE_ENV === 'production' 
    ? ['https://production-app.com'] 
    : ['http://localhost:8080', 'http://localhost:3000'];
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: allowedOrigins
  }));
  
  app.get('/api/user-profile', (req, res) => {
    res.json({ name: 'Jane Doe', role: 'admin' });
  });
  
  app.listen(4004);
}
// {/fact}

// Example 6: Fastify with specific origin CORS
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_6() {
  // ok: javascript-do-not-allow-unrestricted-cors
  fastify.register(require('@fastify/cors'), { 
    origin: 'https://trusted-site.com'
  });
  
  fastify.get('/api/admin', async (request, reply) => {
    return { adminAccess: true, privileges: ['read', 'write', 'delete'] };
  });
  
  fastify.listen({ port: 4005 });
}
// {/fact}

// Example 7: Koa with specific origin CORS
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_7() {
  const app = new Koa();
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use(koaCors({
    origin: 'https://trusted-site.com'
  }));
  
  app.use(async ctx => {
    if (ctx.path === '/api/financial-records') {
      ctx.body = { income: 75000, expenses: 50000 };
    }
  });
  
  app.listen(4006);
}
// {/fact}

// Example 8: Restify with specific origin CORS
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_8() {
  const server = restify.createServer();
  
  // ok: javascript-do-not-allow-unrestricted-cors
  server.use(function crossOrigin(req, res, next) {
    const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Headers', 'X-Requested-With');
    return next();
  });
  
  server.get('/api/health-records', function(req, res, next) {
    res.send({ patientId: 'P12345', diagnosis: 'Confidential' });
    return next();
  });
  
  server.listen(4007);
}
// {/fact}

// Example 9: Express with regex validation for CORS origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: function(origin, callback) {
      // Allow subdomains of example.com
      const regex = /^https:\/\/.*\.example\.com$/;
      
      if (regex.test(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  }));
  
  app.get('/api/account-details', (req, res) => {
    res.json({ accountNumber: '987654321', balance: 5000 });
  });
  
  app.listen(4008);
}
// {/fact}

// Example 10: Express with route-specific CORS for different origins
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  const publicApiCors = cors({ origin: 'https://public.example.com' });
  const adminApiCors = cors({ origin: 'https://admin.example.com' });
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.get('/api/public-data', publicApiCors, (req, res) => {
    res.json({ publicInfo: 'This is public' });
  });
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.get('/api/admin-data', adminApiCors, (req, res) => {
    res.json({ adminInfo: 'This is for admins only' });
  });
  
  app.listen(4009);
}
// {/fact}

// Example 11: Node.js HTTPS server with specific origin CORS
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_11() {
  const options = {
    key: 'private-key-content',
    cert: 'certificate-content'
  };
  
  const server = https.createServer(options, (req, res) => {
    const origin = req.headers.origin;
    
    // ok: javascript-do-not-allow-unrestricted-cors
    if (origin === 'https://secure-client.com') {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    
    res.setHeader('Content-Type', 'application/json');
    
    if (req.url === '/api/secure-data') {
      res.end(JSON.stringify({ secureData: 'top secret' }));
    }
  });
  
  server.listen(4010);
}
// {/fact}

// Example 12: Express with CORS whitelist from configuration
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  const corsWhitelist = [
    'https://app.example.com',
    'https://dashboard.example.com',
    'https://admin.example.com'
  ];
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: function(origin, callback) {
      if (corsWhitelist.indexOf(origin) !== -1 || !origin) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  }));
  
  app.get('/api/personal-info', (req, res) => {
    res.json({ ssn: '123-45-6789', dob: '1980-01-01' });
  });
  
  app.listen(4011);
}
// {/fact}

// Example 13: Express with domain validation for CORS
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    if (origin && origin.endsWith('.trusted-domain.com')) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    }
    
    next();
  });
  
  app.get('/api/documents', (req, res) => {
    res.json([{ id: 1, title: 'Confidential Report' }]);
  });
  
  app.listen(4012);
}
// {/fact}

// Example 14: Express with CORS and additional security measures
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.use(helmet()); // Adding security headers
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: 'https://trusted-site.com',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }));
  
  app.get('/api/customer-data', (req, res) => {
    res.json({ customerId: 'C789', purchaseHistory: [...] });
  });
  
  app.listen(4013);
}
// {/fact}

// Example 15: Express with dynamic CORS based on request path
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // ok: javascript-do-not-allow-unrestricted-cors
  app.use((req, res, next) => {
    if (req.path.startsWith('/api/public/')) {
      res.header('Access-Control-Allow-Origin', 'https://public.example.com');
    } else if (req.path.startsWith('/api/partner/')) {
      res.header('Access-Control-Allow-Origin', 'https://partner.example.com');
    } else if (req.path.startsWith('/api/admin/')) {
      res.header('Access-Control-Allow-Origin', 'https://admin.example.com');
    }
    
    next();
  });
  
  app.get('/api/admin/restricted-data', (req, res) => {
    res.json({ sensitive: true, data: 'Admin only content' });
  });
  
  app.listen(4014);
}
// {/fact}

module.exports = {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};