// Example file for javascript-missing-authorization rule
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

// Middleware for authorization
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(token, 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function isAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Forbidden' });
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_1() {
  // ruleid: javascript-missing-authorization
  app.get('/api/users', (req, res) => {
    // This endpoint returns all users without any authorization check
    const users = [{ id: 1, name: 'Admin' }, { id: 2, name: 'User' }];
    res.json(users);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_2() {
  // ruleid: javascript-missing-authorization
  app.post('/api/delete-user', (req, res) => {
    const userId = req.body.userId;
    // Deleting a user without authorization check
    console.log(`Deleting user ${userId}`);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_3() {
  const router = express.Router();
  
  // ruleid: javascript-missing-authorization
  router.put('/api/update-settings', (req, res) => {
    const settings = req.body;
    // Updating system settings without authorization
    console.log('Updating settings:', settings);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_4() {
  // ruleid: javascript-missing-authorization
  app.delete('/api/articles/:id', (req, res) => {
    const articleId = req.params.id;
    // Deleting an article without checking if the user has permission
    console.log(`Deleting article ${articleId}`);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_5() {
  // ruleid: javascript-missing-authorization
  app.get('/api/admin-dashboard', (req, res) => {
    // Admin dashboard accessible without authorization check
    const adminData = { users: 100, revenue: '$50,000' };
    res.json(adminData);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_6() {
  const router = express.Router();
  
  // ruleid: javascript-missing-authorization
  router.post('/api/create-user', (req, res) => {
    const userData = req.body;
    // Creating a new user without proper authorization
    console.log('Creating user:', userData);
    res.json({ success: true, id: 123 });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_7() {
  // ruleid: javascript-missing-authorization
  app.get('/api/reports/:year', (req, res) => {
    const year = req.params.year;
    // Accessing financial reports without authorization
    const reports = { year, revenue: '$1M', expenses: '$700K' };
    res.json(reports);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_8() {
  // Using a different HTTP framework
  const http = require('http');
  
  // ruleid: javascript-missing-authorization
  http.createServer((req, res) => {
    if (req.url === '/api/sensitive-data' && req.method === 'GET') {
      // Returning sensitive data without authorization
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ secretKey: '12345', data: 'sensitive' }));
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_9() {
  // ruleid: javascript-missing-authorization
  app.post('/api/payment-process', (req, res) => {
    const { amount, destination } = req.body;
    // Processing payment without authorization check
    console.log(`Processing payment of ${amount} to ${destination}`);
    res.json({ success: true, transactionId: '123456' });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_10() {
  // Using Koa framework
  const Koa = require('koa');
  const Router = require('koa-router');
  const koa = new Koa();
  const router = new Router();
  
  // ruleid: javascript-missing-authorization
  router.get('/api/user-data/:id', async (ctx) => {
    const userId = ctx.params.id;
    // Accessing user data without authorization check
    ctx.body = { id: userId, email: 'user@example.com', role: 'admin' };
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_11() {
  // ruleid: javascript-missing-authorization
  app.get('/api/export-database', (req, res) => {
    // Exporting entire database without authorization
    const dbDump = { users: [], posts: [], settings: {} };
    res.json(dbDump);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_12() {
  // Using Fastify framework
  const fastify = require('fastify')();
  
  // ruleid: javascript-missing-authorization
  fastify.get('/api/logs', async (request, reply) => {
    // Accessing system logs without authorization
    const logs = ['User login at 12:00', 'System restart at 13:00'];
    return logs;
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_13() {
  // ruleid: javascript-missing-authorization
  app.patch('/api/user-role/:id', (req, res) => {
    const userId = req.params.id;
    const newRole = req.body.role;
    // Changing user role without authorization check
    console.log(`Changing role of user ${userId} to ${newRole}`);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_14() {
  // Using Express with a different route pattern
  const apiRouter = express.Router();
  
  // ruleid: javascript-missing-authorization
  apiRouter.post('/backup/create', (req, res) => {
    // Creating system backup without authorization
    console.log('Creating system backup');
    res.json({ success: true, backupId: 'backup-2023' });
  });
  
  app.use('/api', apiRouter);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_15() {
  // ruleid: javascript-missing-authorization
  app.get('/api/config/system', (req, res) => {
    // Exposing system configuration without authorization
    const config = {
      dbConnection: 'mongodb://localhost:27017',
      apiKeys: { google: 'abc123', aws: 'xyz789' }
    };
    res.json(config);
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_1() {
  // ok: javascript-missing-authorization
  app.get('/api/users', authMiddleware, (req, res) => {
    // This endpoint has authorization middleware
    const users = [{ id: 1, name: 'Admin' }, { id: 2, name: 'User' }];
    res.json(users);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_2() {
  // ok: javascript-missing-authorization
  app.post('/api/delete-user', authMiddleware, isAdmin, (req, res) => {
    const userId = req.body.userId;
    // Deleting a user with proper authorization checks
    console.log(`Deleting user ${userId}`);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_3() {
  const router = express.Router();
  
  // ok: javascript-missing-authorization
  router.put('/api/update-settings', authMiddleware, (req, res) => {
    const settings = req.body;
    // Updating system settings with authorization
    console.log('Updating settings:', settings);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_4() {
  // Custom authorization middleware
  function checkArticleOwnership(req, res, next) {
    const articleId = req.params.id;
    // Check if user owns the article or is admin
    if (req.user && (req.user.role === 'admin' || req.user.articles.includes(articleId))) {
      next();
    } else {
      res.status(403).json({ message: 'Forbidden' });
    }
  }
  
  // ok: javascript-missing-authorization
  app.delete('/api/articles/:id', authMiddleware, checkArticleOwnership, (req, res) => {
    const articleId = req.params.id;
    console.log(`Deleting article ${articleId}`);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_5() {
  // ok: javascript-missing-authorization
  app.get('/api/admin-dashboard', authMiddleware, isAdmin, (req, res) => {
    // Admin dashboard with proper authorization checks
    const adminData = { users: 100, revenue: '$50,000' };
    res.json(adminData);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_6() {
  // Role-based authorization middleware
  function checkRole(role) {
    return (req, res, next) => {
      if (req.user && req.user.role === role) {
        next();
      } else {
        res.status(403).json({ message: 'Forbidden' });
      }
    };
  }
  
  // ok: javascript-missing-authorization
  app.post('/api/create-user', authMiddleware, checkRole('admin'), (req, res) => {
    const userData = req.body;
    console.log('Creating user:', userData);
    res.json({ success: true, id: 123 });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_7() {
  // ok: javascript-missing-authorization
  app.get('/api/reports/:year', authMiddleware, (req, res) => {
    const year = req.params.year;
    // Check if user has permission to access reports
    if (req.user.permissions.includes('view_reports')) {
      const reports = { year, revenue: '$1M', expenses: '$700K' };
      res.json(reports);
    } else {
      res.status(403).json({ message: 'Forbidden' });
    }
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_8() {
  // Using a different HTTP framework with authorization
  const http = require('http');
  
  function validateToken(req) {
    const token = req.headers.authorization?.split(' ')[1];
    // Simplified token validation logic
    return token === 'valid_token';
  }
  
  // ok: javascript-missing-authorization
  http.createServer((req, res) => {
    if (req.url === '/api/sensitive-data' && req.method === 'GET') {
      if (validateToken(req)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ secretKey: '12345', data: 'sensitive' }));
      } else {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
      }
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_9() {
  // ok: javascript-missing-authorization
  app.post('/api/payment-process', authMiddleware, (req, res) => {
    const { amount, destination } = req.body;
    // Additional authorization check for payment processing
    if (req.user.role === 'finance' || req.user.role === 'admin') {
      console.log(`Processing payment of ${amount} to ${destination}`);
      res.json({ success: true, transactionId: '123456' });
    } else {
      res.status(403).json({ message: 'Forbidden' });
    }
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_10() {
  // Using Koa framework with authorization
  const Koa = require('koa');
  const Router = require('koa-router');
  const koa = new Koa();
  const router = new Router();
  
  async function koaAuthMiddleware(ctx, next) {
    const token = ctx.headers.authorization?.split(' ')[1];
    if (!token) {
      ctx.status = 401;
      ctx.body = { message: 'Unauthorized' };
      return;
    }
    // Simplified token validation
    ctx.user = { id: 123, role: 'user' };
    await next();
  }
  
  // ok: javascript-missing-authorization
  router.get('/api/user-data/:id', koaAuthMiddleware, async (ctx) => {
    const userId = ctx.params.id;
    // Check if user is requesting their own data or is admin
    if (ctx.user.id.toString() === userId || ctx.user.role === 'admin') {
      ctx.body = { id: userId, email: 'user@example.com', role: 'user' };
    } else {
      ctx.status = 403;
      ctx.body = { message: 'Forbidden' };
    }
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_11() {
  // ok: javascript-missing-authorization
  app.get('/api/export-database', authMiddleware, isAdmin, (req, res) => {
    // Exporting database with proper authorization
    const dbDump = { users: [], posts: [], settings: {} };
    res.json(dbDump);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_12() {
  // Using Fastify framework with authorization
  const fastify = require('fastify')();
  
  fastify.register(require('fastify-auth'));
  
  const verifyToken = async (request, reply) => {
    const token = request.headers.authorization?.split(' ')[1];
    if (!token) {
      throw new Error('Missing token');
    }
    // Token verification logic
    request.user = { role: 'admin' };
  };
  
  // ok: javascript-missing-authorization
  fastify.get('/api/logs', {
    preHandler: fastify.auth([verifyToken])
  }, async (request, reply) => {
    // Accessing system logs with authorization
    const logs = ['User login at 12:00', 'System restart at 13:00'];
    return logs;
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_13() {
  // Permission-based middleware
  function hasPermission(permission) {
    return (req, res, next) => {
      if (req.user && req.user.permissions.includes(permission)) {
        next();
      } else {
        res.status(403).json({ message: 'Forbidden' });
      }
    };
  }
  
  // ok: javascript-missing-authorization
  app.patch('/api/user-role/:id', authMiddleware, hasPermission('manage_users'), (req, res) => {
    const userId = req.params.id;
    const newRole = req.body.role;
    console.log(`Changing role of user ${userId} to ${newRole}`);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_14() {
  // Using Express with a different route pattern and authorization
  const apiRouter = express.Router();
  
  // Apply auth middleware to all routes in this router
  apiRouter.use(authMiddleware);
  
  // ok: javascript-missing-authorization
  apiRouter.post('/backup/create', isAdmin, (req, res) => {
    // Creating system backup with authorization
    console.log('Creating system backup');
    res.json({ success: true, backupId: 'backup-2023' });
  });
  
  app.use('/api', apiRouter);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_15() {
  // ok: javascript-missing-authorization
  app.get('/api/config/system', authMiddleware, (req, res) => {
    // Check for specific permission to view system config
    if (req.user.permissions.includes('view_system_config')) {
      const config = {
        dbConnection: 'mongodb://localhost:27017',
        apiKeys: { google: 'abc123', aws: 'xyz789' }
      };
      res.json(config);
    } else {
      res.status(403).json({ message: 'Forbidden' });
    }
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});