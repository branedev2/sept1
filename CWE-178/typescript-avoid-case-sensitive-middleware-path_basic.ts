// File: middleware_path_examples.ts
import express from 'express';
import { Router } from 'express';
import * as http from 'http';
import Koa from 'koa';
import Router from '@koa/router';
import { Application } from 'express';
import * as path from 'path';
import * as fs from 'fs';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/^\/admin\/dashboard/, (req, res, next) => {
    // Check if user is authenticated
    if (!req.session.isAuthenticated) {
      return res.status(401).send('Unauthorized');
    }
    next();
  });
  
  app.get('/admin/dashboard', (req, res) => {
    res.send('Admin Dashboard');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  const router = express.Router();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  router.use(/\/api\/users\/[0-9]+\/profile/, (req, res, next) => {
    // Verify user permissions
    if (!req.user.hasPermission('view_profile')) {
      return res.status(403).send('Forbidden');
    }
    next();
  });
  
  app.use(router);
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/^\/secure-area/, (req, res, next) => {
    if (!req.headers.authorization) {
      return res.status(401).send('Authentication required');
    }
    next();
  });
  
  app.get('/secure-area/documents', (req, res) => {
    res.send('Secure documents');
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_4() {
  const koaApp = new Koa();
  const router = new Router();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  router.use(/^\/restricted\/.*/, async (ctx, next) => {
    if (!ctx.state.user) {
      ctx.status = 401;
      ctx.body = 'Authentication required';
      return;
    }
    await next();
  });
  
  koaApp.use(router.routes());
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/payment\/checkout/, (req, res, next) => {
    if (!req.session.cart) {
      return res.redirect('/cart');
    }
    next();
  });
  
  app.post('/payment/checkout', (req, res) => {
    // Process payment
    res.send('Payment processed');
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/v1\/private/, (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !validateApiKey(apiKey)) {
      return res.status(403).json({ error: 'Invalid API key' });
    }
    next();
  });
  
  function validateApiKey(key: string): boolean {
    return key === process.env.API_KEY;
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  const adminRouter = express.Router();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  adminRouter.use(/\/settings\/.*/, (req, res, next) => {
    if (req.user.role !== 'admin') {
      return res.status(403).send('Admin access required');
    }
    next();
  });
  
  app.use('/admin', adminRouter);
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/^\/dashboard\/reports/, (req, res, next) => {
    if (!req.session.user.permissions.includes('view_reports')) {
      return res.status(403).send('Permission denied');
    }
    next();
  });
  
  app.get('/dashboard/reports/sales', (req, res) => {
    res.send('Sales reports');
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/user\/([0-9]+)\/edit/, (req, res, next) => {
    const userId = parseInt(req.params[0]);
    if (req.session.userId !== userId) {
      return res.status(403).send('You can only edit your own profile');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/confidential\/documents/, (req, res, next) => {
    const token = req.cookies.accessToken;
    if (!token || !verifyToken(token)) {
      return res.status(401).send('Authentication required');
    }
    next();
  });
  
  function verifyToken(token: string): boolean {
    // Token verification logic
    return token.length > 10;
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/health-check/, (req, res, next) => {
    const internalKey = req.headers['internal-key'];
    if (internalKey !== process.env.INTERNAL_KEY) {
      return res.status(403).send('Unauthorized');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/uploads\/private/, (req, res, next) => {
    if (!req.session.isAuthenticated) {
      return res.status(401).send('Login required');
    }
    next();
  });
  
  app.get('/uploads/private/file.pdf', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', 'private', 'file.pdf');
    res.sendFile(filePath);
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/beta\/features/, (req, res, next) => {
    if (!req.user.isBetaTester) {
      return res.status(403).send('Beta access required');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/admin-panel\/logs/, (req, res, next) => {
    const ipAddress = req.ip;
    if (!isWhitelistedIP(ipAddress)) {
      return res.status(403).send('Access denied');
    }
    next();
  });
  
  function isWhitelistedIP(ip: string): boolean {
    const whitelistedIPs = ['127.0.0.1', '::1'];
    return whitelistedIPs.includes(ip);
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // Case-sensitive middleware path using regex without 'i' flag
  // ruleid: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/v2\/metrics/, (req, res, next) => {
    const apiToken = req.headers['x-metrics-token'];
    if (!apiToken || apiToken !== process.env.METRICS_TOKEN) {
      return res.status(401).json({ error: 'Invalid metrics token' });
    }
    next();
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // Case-insensitive middleware path using regex with 'i' flag
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use(/^\/admin\/dashboard/i, (req, res, next) => {
    // Check if user is authenticated
    if (!req.session.isAuthenticated) {
      return res.status(401).send('Unauthorized');
    }
    next();
  });
  
  app.get('/admin/dashboard', (req, res) => {
    res.send('Admin Dashboard');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_2() {
  const app = express();
  const router = express.Router();
  
  // Case-insensitive middleware path using regex with 'i' flag
  // ok: typescript-avoid-case-sensitive-middleware-path
  router.use(/\/api\/users\/[0-9]+\/profile/i, (req, res, next) => {
    // Verify user permissions
    if (!req.user.hasPermission('view_profile')) {
      return res.status(403).send('Forbidden');
    }
    next();
  });
  
  app.use(router);
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // Using string path instead of regex (Express handles this in a standard way)
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use('/secure-area', (req, res, next) => {
    if (!req.headers.authorization) {
      return res.status(401).send('Authentication required');
    }
    next();
  });
  
  app.get('/secure-area/documents', (req, res) => {
    res.send('Secure documents');
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_4() {
  const koaApp = new Koa();
  const router = new Router();
  
  // Case-insensitive middleware path using regex with 'i' flag
  // ok: typescript-avoid-case-sensitive-middleware-path
  router.use(/^\/restricted\/.*/i, async (ctx, next) => {
    if (!ctx.state.user) {
      ctx.status = 401;
      ctx.body = 'Authentication required';
      return;
    }
    await next();
  });
  
  koaApp.use(router.routes());
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // Case-insensitive middleware path using regex with 'i' flag
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/payment\/checkout/i, (req, res, next) => {
    if (!req.session.cart) {
      return res.redirect('/cart');
    }
    next();
  });
  
  app.post('/payment/checkout', (req, res) => {
    // Process payment
    res.send('Payment processed');
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  // Using string path instead of regex
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use('/api/v1/private', (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !validateApiKey(apiKey)) {
      return res.status(403).json({ error: 'Invalid API key' });
    }
    next();
  });
  
  function validateApiKey(key: string): boolean {
    return key === process.env.API_KEY;
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // Case-insensitive middleware path using regex with 'i' flag
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/v2\/admin/i, (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !verifyAdminToken(token)) {
      return res.status(403).send('Admin access required');
    }
    next();
  });
  
  function verifyAdminToken(token: string): boolean {
    // Token verification logic
    return token === process.env.ADMIN_TOKEN;
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // Using middleware function without path (applies to all routes)
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use((req, res, next) => {
    // Log all requests
    console.log(`${req.method} ${req.path}`);
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // Case-insensitive middleware path using regex with 'i' flag
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/dashboard\/reports/i, (req, res, next) => {
    if (!req.session.user.permissions.includes('view_reports')) {
      return res.status(403).send('Permission denied');
    }
    next();
  });
  
  app.get('/dashboard/reports/sales', (req, res) => {
    res.send('Sales reports');
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // Using array of paths
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use(['/user/profile', '/user/settings'], (req, res, next) => {
    if (!req.session.isAuthenticated) {
      return res.redirect('/login');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // Case-insensitive middleware path using regex with 'i' flag
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/user\/([0-9]+)\/edit/i, (req, res, next) => {
    const userId = parseInt(req.params[0]);
    if (req.session.userId !== userId) {
      return res.status(403).send('You can only edit your own profile');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // Using router with string paths
  // ok: typescript-avoid-case-sensitive-middleware-path
  const apiRouter = express.Router();
  apiRouter.use('/private', (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.API_KEY) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    next();
  });
  
  app.use('/api', apiRouter);
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // Case-insensitive middleware path using regex with 'i' flag
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/confidential\/documents/i, (req, res, next) => {
    const token = req.cookies.accessToken;
    if (!token || !verifyToken(token)) {
      return res.status(401).send('Authentication required');
    }
    next();
  });
  
  function verifyToken(token: string): boolean {
    // Token verification logic
    return token.length > 10;
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // Using multiple middleware functions
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use('/admin', 
    (req, res, next) => {
      // First middleware: check authentication
      if (!req.session.isAuthenticated) {
        return res.status(401).send('Authentication required');
      }
      next();
    },
    (req, res, next) => {
      // Second middleware: check admin role
      if (req.session.user.role !== 'admin') {
        return res.status(403).send('Admin access required');
      }
      next();
    }
  );
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // Case-insensitive middleware path using regex with 'i' flag and complex pattern
  // ok: typescript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/(v1|v2)\/protected\/.*/i, (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Bearer token required' });
    }
    const token = authHeader.split(' ')[1];
    if (!validateToken(token)) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    next();
  });
  
  function validateToken(token: string): boolean {
    // Token validation logic
    return token.length >= 32;
  }
}
// {/fact}

// Helper types for TypeScript
interface Session {
  isAuthenticated: boolean;
  userId: number;
  user: {
    role: string;
    permissions: string[];
    isBetaTester: boolean;
  };
  cart: any;
}

declare global {
  namespace Express {
    interface Request {
      session: Session;
      user: {
        hasPermission: (permission: string) => boolean;
        role: string;
      };
    }
  }
}