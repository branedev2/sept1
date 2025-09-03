// Test cases for javascript-avoid-case-sensitive-middleware-path
const express = require('express');
const app = express();

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(/^\/admin/, (req, res, next) => {
    // Check if user is authenticated
    if (!req.session.isAdmin) {
      return res.status(403).send('Unauthorized');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/private\/.*/, (req, res, next) => {
    if (!req.headers.authorization) {
      return res.status(401).send('Authentication required');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_3() {
  const router = express.Router();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  router.use(/^\/dashboard/, (req, res, next) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.all(/\/secure\/.*/, (req, res, next) => {
    // Verify JWT token
    if (!req.headers.authorization) {
      return res.status(401).json({ error: 'No token provided' });
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/users\/profile/, (req, res, next) => {
    if (!req.session.userId) {
      return res.status(401).send('Login required');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_6() {
  const router = express.Router();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  router.use(/^\/settings/, requireAuth);
  
  function requireAuth(req, res, next) {
    if (!req.user) {
      return res.status(401).send('Authentication required');
    }
    next();
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/admin-panel/, function(req, res, next) {
    // Check admin role
    if (req.user && req.user.role === 'admin') {
      next();
    } else {
      res.status(403).send('Admin access required');
    }
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  const adminRegex = new RegExp('^/admin');
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(adminRegex, (req, res, next) => {
    if (!req.session.adminUser) {
      return res.status(403).send('Admin access required');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/v1\/protected/, (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !isValidApiKey(apiKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    next();
  });
  
  function isValidApiKey(key) {
    return key === process.env.API_KEY;
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/payment\/checkout/, (req, res, next) => {
    if (!req.session.authenticated) {
      return res.redirect('/login?redirect=' + req.originalUrl);
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_11() {
  const router = express.Router();
  const securePathPattern = /\/secure-data/;
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  router.use(securePathPattern, (req, res, next) => {
    if (!req.user.hasPermission('view_secure_data')) {
      return res.status(403).send('Permission denied');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/confidential\/documents/, function(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !verifyJwt(token)) {
      return res.status(401).send('Valid token required');
    }
    next();
  });
  
  function verifyJwt(token) {
    // JWT verification logic
    return true;
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/reports\/[0-9]+/, (req, res, next) => {
    if (!req.session.user || !req.session.user.canAccessReports) {
      return res.status(403).json({ error: 'No permission to access reports' });
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const restrictedPaths = [/\/internal\//, /\/admin\//, /\/config\//];
  
  restrictedPaths.forEach(path => {
    // ruleid: javascript-avoid-case-sensitive-middleware-path
    app.use(path, (req, res, next) => {
      if (!req.session.isInternal) {
        return res.status(403).send('Internal access only');
      }
      next();
    });
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  const pathRegex = new RegExp('/api/private');
  // ruleid: javascript-avoid-case-sensitive-middleware-path
  app.use(pathRegex, (req, res, next) => {
    const apiKey = req.query.key || req.headers['x-api-key'];
    if (!apiKey) {
      return res.status(401).json({ error: 'API key required' });
    }
    next();
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use(/^\/admin/i, (req, res, next) => {
    // Check if user is authenticated
    if (!req.session.isAdmin) {
      return res.status(403).send('Unauthorized');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_2() {
  const app = express();
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/private\/.*/i, (req, res, next) => {
    if (!req.headers.authorization) {
      return res.status(401).send('Authentication required');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_3() {
  const router = express.Router();
  // ok: javascript-avoid-case-sensitive-middleware-path
  router.use(/^\/dashboard/i, (req, res, next) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_4() {
  const app = express();
  // Using a string path instead of regex is fine
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use('/admin', (req, res, next) => {
    if (!req.session.isAdmin) {
      return res.status(403).send('Unauthorized');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_5() {
  const app = express();
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/secure\/.*/i, (req, res, next) => {
    // Verify JWT token
    if (!req.headers.authorization) {
      return res.status(401).json({ error: 'No token provided' });
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_6() {
  const app = express();
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/users\/profile/i, (req, res, next) => {
    if (!req.session.userId) {
      return res.status(401).send('Login required');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_7() {
  const router = express.Router();
  // ok: javascript-avoid-case-sensitive-middleware-path
  router.use(/^\/settings/i, requireAuth);
  
  function requireAuth(req, res, next) {
    if (!req.user) {
      return res.status(401).send('Authentication required');
    }
    next();
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_8() {
  const app = express();
  // Using a middleware function directly without path regex is fine
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use((req, res, next) => {
    if (req.path.startsWith('/admin') && !req.session.isAdmin) {
      return res.status(403).send('Unauthorized');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_9() {
  const app = express();
  const adminRegex = new RegExp('^/admin', 'i');
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use(adminRegex, (req, res, next) => {
    if (!req.session.adminUser) {
      return res.status(403).send('Admin access required');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_10() {
  const app = express();
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use(/\/api\/v1\/protected/i, (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !isValidApiKey(apiKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    next();
  });
  
  function isValidApiKey(key) {
    return key === process.env.API_KEY;
  }
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_11() {
  const app = express();
  // Using a function to check the path instead of regex
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use((req, res, next) => {
    if (req.path.toLowerCase() === '/admin' && !req.session.isAdmin) {
      return res.status(403).send('Unauthorized');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_12() {
  const router = express.Router();
  const securePathPattern = /\/secure-data/i;
  // ok: javascript-avoid-case-sensitive-middleware-path
  router.use(securePathPattern, (req, res, next) => {
    if (!req.user.hasPermission('view_secure_data')) {
      return res.status(403).send('Permission denied');
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_13() {
  const app = express();
  // Using a specific path with parameters instead of regex
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use('/reports/:reportId', (req, res, next) => {
    if (!req.session.user || !req.session.user.canAccessReports) {
      return res.status(403).json({ error: 'No permission to access reports' });
    }
    next();
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_14() {
  const app = express();
  const restrictedPaths = [/\/internal\//i, /\/admin\//i, /\/config\//i];
  
  restrictedPaths.forEach(path => {
    // ok: javascript-avoid-case-sensitive-middleware-path
    app.use(path, (req, res, next) => {
      if (!req.session.isInternal) {
        return res.status(403).send('Internal access only');
      }
      next();
    });
  });
}
// {/fact}

// {fact rule=improper-handling-of-case-sensitivity@v1.0 defects=0}
function good_case_15() {
  const app = express();
  const pathRegex = new RegExp('/api/private', 'i');
  // ok: javascript-avoid-case-sensitive-middleware-path
  app.use(pathRegex, (req, res, next) => {
    const apiKey = req.query.key || req.headers['x-api-key'];
    if (!apiKey) {
      return res.status(401).json({ error: 'API key required' });
    }
    next();
  });
}
// {/fact}