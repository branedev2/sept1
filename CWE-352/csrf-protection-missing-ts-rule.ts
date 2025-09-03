// File: csrf_protection_examples.ts

import express from 'express';
import axios from 'axios';
import fetch from 'node-fetch';
import request from 'request';
import superagent from 'superagent';
import got from 'got';
import http from 'http';
import https from 'https';
import csurf from 'csurf';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';

// True Positive Examples (Vulnerable Code)

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(bodyParser.json());
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/user', (req, res) => {
    const user = req.body;
    // Process user data without CSRF protection
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  app.use(express.json());
  
  // ruleid: csrf-protection-missing-ts-rule
  app.put('/api/update-profile', (req, res) => {
    const profileData = req.body;
    // Update profile without CSRF protection
    res.send('Profile updated');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  app.use(express.urlencoded({ extended: true }));
  
  // ruleid: csrf-protection-missing-ts-rule
  app.delete('/api/delete-account/:id', (req, res) => {
    const userId = req.params.id;
    // Delete account without CSRF protection
    res.status(200).send('Account deleted');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_4() {
  const router = express.Router();
  
  // ruleid: csrf-protection-missing-ts-rule
  router.post('/submit-form', (req, res) => {
    // Process form submission without CSRF protection
    const formData = req.body;
    res.redirect('/thank-you');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // CSRF protection only applied to GET requests, not POST
  app.use((req, res, next) => {
    if (req.method === 'GET') {
      // Some custom validation
      const token = req.headers['x-csrf-token'];
      // Validate token for GET requests only
    }
    next();
  });
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/payment', (req, res) => {
    // Process payment without CSRF protection
    const paymentDetails = req.body;
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  // Using CSRF protection but only for specific routes, not including this one
  const csrfProtection = csurf({ cookie: true });
  app.use('/protected-route', csrfProtection);
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/unprotected-route', (req, res) => {
    // This route is not protected by CSRF middleware
    const data = req.body;
    res.send('Data processed');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: csrf-protection-missing-ts-rule
  app.put('/api/articles/:id', async (req, res) => {
    try {
      const articleId = req.params.id;
      const updates = req.body;
      // Update article without CSRF protection
      res.json({ updated: true });
    } catch (error) {
      res.status(500).send('Error updating article');
    }
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  app.use(express.json());
  
  const adminRouter = express.Router();
  
  // ruleid: csrf-protection-missing-ts-rule
  adminRouter.post('/admin/settings', (req, res) => {
    // Update admin settings without CSRF protection
    const settings = req.body;
    res.json({ success: true });
  });
  
  app.use(adminRouter);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // Using conditional middleware that skips CSRF for API routes
  app.use((req, res, next) => {
    if (!req.path.startsWith('/api/')) {
      // Apply CSRF protection for non-API routes
      csurf({ cookie: true })(req, res, next);
    } else {
      next();
    }
  });
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/data', (req, res) => {
    // This API route doesn't have CSRF protection
    const data = req.body;
    res.json({ received: true });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  // ruleid: csrf-protection-missing-ts-rule
  app.delete('/api/comments/:id', (req, res) => {
    const commentId = req.params.id;
    // Delete comment without CSRF protection
    res.status(204).end();
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  app.use(bodyParser.json());
  
  // Using custom authentication but no CSRF protection
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization;
    if (token) {
      // Authenticate user
      next();
    } else {
      res.status(401).send('Unauthorized');
    }
  };
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/orders', authenticate, (req, res) => {
    // Create order without CSRF protection
    const orderData = req.body;
    res.json({ orderId: '12345' });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_12() {
  const router = express.Router();
  
  // ruleid: csrf-protection-missing-ts-rule
  router.put('/api/preferences', (req, res) => {
    // Update user preferences without CSRF protection
    const preferences = req.body;
    res.json({ updated: true });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/upload', (req, res) => {
    // File upload endpoint without CSRF protection
    // Process file upload
    res.send('File uploaded');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  // CSRF protection applied but then removed for this specific route
  const csrfProtection = csurf({ cookie: true });
  app.use(csrfProtection);
  
  app.use('/api/webhook', (req, res, next) => {
    // Disable CSRF for webhook
    req.csrfToken = () => '';
    next();
  });
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/webhook', (req, res) => {
    // Process webhook without CSRF protection
    const webhookData = req.body;
    res.status(200).end();
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // Using JWT authentication but no CSRF protection
  const verifyJWT = (req: any, res: any, next: any) => {
    const token = req.headers['authorization'];
    if (token) {
      // Verify JWT token
      next();
    } else {
      res.status(401).send('Unauthorized');
    }
  };
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/feedback', verifyJWT, (req, res) => {
    // Submit feedback without CSRF protection
    const feedback = req.body;
    res.json({ received: true });
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(cookieParser());
  
  // Apply CSRF protection middleware
  const csrfProtection = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/api/user', csrfProtection, (req, res) => {
    const user = req.body;
    // Process user data with CSRF protection
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_2() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.urlencoded({ extended: false }));
  
  // Apply CSRF protection globally
  app.use(csurf({ cookie: true }));
  
  // ok: csrf-protection-missing-ts-rule
  app.put('/api/update-profile', (req, res) => {
    const profileData = req.body;
    // Update profile with CSRF protection
    res.send('Profile updated');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_3() {
  const app = express();
  app.use(cookieParser());
  app.use(express.json());
  
  const csrfProtection = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  app.delete('/api/delete-account/:id', csrfProtection, (req, res) => {
    const userId = req.params.id;
    // Delete account with CSRF protection
    res.status(200).send('Account deleted');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_4() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.json());
  
  // Apply CSRF protection globally
  app.use(csurf({ cookie: { secure: true, sameSite: 'strict' } }));
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/submit-form', (req, res) => {
    // Process form submission with CSRF protection
    const formData = req.body;
    res.redirect('/thank-you');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_5() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.json());
  
  // Apply CSRF protection to all routes
  app.use(csurf({ cookie: true }));
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/api/payment', (req, res) => {
    // Process payment with CSRF protection
    const paymentDetails = req.body;
    // Include CSRF token in response for client-side validation
    res.json({ success: true, csrfToken: req.csrfToken() });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_6() {
  const app = express();
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: true }));
  
  // Create CSRF middleware
  const csrfMiddleware = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/api/data', csrfMiddleware, (req, res) => {
    // This route is protected by CSRF middleware
    const data = req.body;
    res.send('Data processed');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_7() {
  const app = express();
  app.use(cookieParser());
  app.use(express.json());
  
  // Apply CSRF protection
  const csrfProtection = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  app.put('/api/articles/:id', csrfProtection, async (req, res) => {
    try {
      const articleId = req.params.id;
      const updates = req.body;
      // Update article with CSRF protection
      res.json({ updated: true });
    } catch (error) {
      res.status(500).send('Error updating article');
    }
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_8() {
  const app = express();
  app.use(cookieParser());
  app.use(express.json());
  
  const adminRouter = express.Router();
  
  // Apply CSRF protection to admin routes
  adminRouter.use(csurf({ cookie: true }));
  
  // ok: csrf-protection-missing-ts-rule
  adminRouter.post('/admin/settings', (req, res) => {
    // Update admin settings with CSRF protection
    const settings = req.body;
    res.json({ success: true });
  });
  
  app.use(adminRouter);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_9() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.json());
  
  // Apply CSRF protection to all routes
  app.use(csurf({ cookie: true }));
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/api/data', (req, res) => {
    // This API route has CSRF protection
    const data = req.body;
    res.json({ received: true, csrfToken: req.csrfToken() });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_10() {
  const app = express();
  app.use(cookieParser());
  
  // Apply CSRF protection
  const csrfProtection = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  app.delete('/api/comments/:id', csrfProtection, (req, res) => {
    const commentId = req.params.id;
    // Delete comment with CSRF protection
    res.status(204).end();
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_11() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.json());
  
  // Using both authentication and CSRF protection
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization;
    if (token) {
      // Authenticate user
      next();
    } else {
      res.status(401).send('Unauthorized');
    }
  };
  
  const csrfProtection = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/api/orders', authenticate, csrfProtection, (req, res) => {
    // Create order with both authentication and CSRF protection
    const orderData = req.body;
    res.json({ orderId: '12345' });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_12() {
  const router = express.Router();
  const csrfProtection = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  router.put('/api/preferences', csrfProtection, (req, res) => {
    // Update user preferences with CSRF protection
    const preferences = req.body;
    res.json({ updated: true });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_13() {
  const app = express();
  app.use(cookieParser());
  
  // Apply CSRF protection
  const csrfProtection = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/upload', csrfProtection, (req, res) => {
    // File upload endpoint with CSRF protection
    // Process file upload
    res.send('File uploaded');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_14() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.json());
  
  // Using a custom CSRF implementation
  const customCsrfProtection = (req: any, res: any, next: any) => {
    const csrfToken = req.headers['x-csrf-token'];
    const sessionToken = req.cookies.sessionCsrf;
    
    if (csrfToken && sessionToken && csrfToken === sessionToken) {
      next();
    } else {
      res.status(403).send('CSRF token validation failed');
    }
  };
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/api/webhook', customCsrfProtection, (req, res) => {
    // Process webhook with custom CSRF protection
    const webhookData = req.body;
    res.status(200).end();
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_15() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.json());
  
  // Using JWT authentication and CSRF protection together
  const verifyJWT = (req: any, res: any, next: any) => {
    const token = req.headers['authorization'];
    if (token) {
      // Verify JWT token
      next();
    } else {
      res.status(401).send('Unauthorized');
    }
  };
  
  const csrfProtection = csurf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  app.post('/api/feedback', verifyJWT, csrfProtection, (req, res) => {
    // Submit feedback with both JWT authentication and CSRF protection
    const feedback = req.body;
    res.json({ received: true });
  });
}
// {/fact}

export {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};