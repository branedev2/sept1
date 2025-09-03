// Express.js Unsafe HTTP Methods Examples
const express = require('express');
const bodyParser = require('body-parser');

// True Positive Examples (Vulnerable Code)

// bad_case_1: Using express().all() for a sensitive operation
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(bodyParser.json());
  
  // ruleid: javascript-express-unsafe-http-methods
  app.all('/update-user-profile', (req, res) => {
    const userId = req.body.userId;
    const userData = req.body.userData;
    
    // This endpoint can be accessed via GET, POST, PUT, DELETE, etc.
    // which could lead to CSRF attacks
    updateUserProfile(userId, userData);
    res.send('Profile updated');
  });
  
  return app;
}
// {/fact}

// bad_case_2: Using express.Router().all() for a sensitive operation
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_2() {
  const router = express.Router();
  
  // ruleid: javascript-express-unsafe-http-methods
  router.all('/delete-account', (req, res) => {
    const accountId = req.query.id || req.body.id;
    
    // This endpoint can be accessed via any HTTP method
    deleteAccount(accountId);
    res.send('Account deleted');
  });
  
  return router;
}
// {/fact}

// bad_case_3: Using express().route().all() for a payment operation
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // ruleid: javascript-express-unsafe-http-methods
  app.route('/process-payment')
    .all((req, res) => {
      const amount = req.body.amount;
      const cardInfo = req.body.cardInfo;
      
      // This payment processing endpoint can be accessed via any HTTP method
      processPayment(amount, cardInfo);
      res.json({ success: true });
    });
  
  return app;
}
// {/fact}

// bad_case_4: Using express.Router().route().all() for an admin operation
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_4() {
  const adminRouter = express.Router();
  
  // ruleid: javascript-express-unsafe-http-methods
  adminRouter.route('/system-settings')
    .all((req, res) => {
      const settings = req.body.settings;
      
      // This admin endpoint can be accessed via any HTTP method
      updateSystemSettings(settings);
      res.send('Settings updated');
    });
  
  return adminRouter;
}
// {/fact}

// bad_case_5: Using app.all() with middleware chain
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  const authMiddleware = (req, res, next) => {
    // Some authentication logic
    next();
  };
  
  // ruleid: javascript-express-unsafe-http-methods
  app.all('/update-password', authMiddleware, (req, res) => {
    const userId = req.session.userId;
    const newPassword = req.body.password;
    
    // Password update endpoint accessible via any HTTP method
    updateUserPassword(userId, newPassword);
    res.send('Password updated');
  });
  
  return app;
}
// {/fact}

// bad_case_6: Using router.all() with path parameters
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_6() {
  const router = express.Router();
  
  // ruleid: javascript-express-unsafe-http-methods
  router.all('/users/:userId/delete', (req, res) => {
    const userId = req.params.userId;
    
    // User deletion endpoint accessible via any HTTP method
    deleteUser(userId);
    res.send(`User ${userId} deleted`);
  });
  
  return router;
}
// {/fact}

// bad_case_7: Using app.all() with regex path
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: javascript-express-unsafe-http-methods
  app.all(/\/api\/admin\/.*/, (req, res) => {
    const path = req.path;
    const data = req.body;
    
    // Admin API endpoint accessible via any HTTP method
    processAdminRequest(path, data);
    res.json({ success: true });
  });
  
  return app;
}
// {/fact}

// bad_case_8: Using router.all() with multiple middleware functions
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_8() {
  const router = express.Router();
  
  const validateInput = (req, res, next) => {
    // Input validation
    next();
  };
  
  const logRequest = (req, res, next) => {
    // Request logging
    next();
  };
  
  // ruleid: javascript-express-unsafe-http-methods
  router.all('/transfer-funds', validateInput, logRequest, (req, res) => {
    const sourceAccount = req.body.source;
    const targetAccount = req.body.target;
    const amount = req.body.amount;
    
    // Fund transfer endpoint accessible via any HTTP method
    transferFunds(sourceAccount, targetAccount, amount);
    res.send('Funds transferred');
  });
  
  return router;
}
// {/fact}

// bad_case_9: Using app.route().all() with error handling
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // ruleid: javascript-express-unsafe-http-methods
  app.route('/update-subscription')
    .all((req, res) => {
      try {
        const userId = req.session.userId;
        const planId = req.body.planId;
        
        // Subscription update endpoint accessible via any HTTP method
        updateSubscription(userId, planId);
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
  
  return app;
}
// {/fact}

// bad_case_10: Using router.all() with async handler
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_10() {
  const router = express.Router();
  
  // ruleid: javascript-express-unsafe-http-methods
  router.all('/publish-article', async (req, res) => {
    try {
      const articleId = req.body.articleId;
      const publishStatus = req.body.publish;
      
      // Article publishing endpoint accessible via any HTTP method
      await publishArticle(articleId, publishStatus);
      res.send('Article status updated');
    } catch (error) {
      res.status(500).send(error.message);
    }
  });
  
  return router;
}
// {/fact}

// bad_case_11: Using app.all() for file upload
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const multer = require('multer');
  const upload = multer({ dest: 'uploads/' });
  
  // ruleid: javascript-express-unsafe-http-methods
  app.all('/upload-profile-picture', upload.single('avatar'), (req, res) => {
    const userId = req.session.userId;
    const file = req.file;
    
    // File upload endpoint accessible via any HTTP method
    saveProfilePicture(userId, file);
    res.send('Profile picture uploaded');
  });
  
  return app;
}
// {/fact}

// bad_case_12: Using router.route().all() with JSON response
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_12() {
  const router = express.Router();
  
  // ruleid: javascript-express-unsafe-http-methods
  router.route('/api/v1/orders')
    .all((req, res) => {
      const orderData = req.body;
      
      // Order processing endpoint accessible via any HTTP method
      const result = processOrder(orderData);
      res.json(result);
    });
  
  return router;
}
// {/fact}

// bad_case_13: Using app.all() with conditional logic
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // ruleid: javascript-express-unsafe-http-methods
  app.all('/toggle-feature', (req, res) => {
    const featureId = req.query.id || req.body.id;
    const enabled = req.query.enabled || req.body.enabled;
    
    if (enabled === 'true') {
      enableFeature(featureId);
    } else {
      disableFeature(featureId);
    }
    
    // Feature toggle endpoint accessible via any HTTP method
    res.send(`Feature ${featureId} updated`);
  });
  
  return app;
}
// {/fact}

// bad_case_14: Using router.all() with database operations
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_14() {
  const router = express.Router();
  const db = require('./database');
  
  // ruleid: javascript-express-unsafe-http-methods
  router.all('/user-preferences', (req, res) => {
    const userId = req.session.userId;
    const preferences = req.body.preferences;
    
    // User preferences update endpoint accessible via any HTTP method
    db.users.updatePreferences(userId, preferences);
    res.send('Preferences updated');
  });
  
  return router;
}
// {/fact}

// bad_case_15: Using app.all() with destructuring and template literals
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // ruleid: javascript-express-unsafe-http-methods
  app.all('/api/comments/:postId', (req, res) => {
    const { postId } = req.params;
    const { content, author } = req.body;
    
    // Comment submission endpoint accessible via any HTTP method
    const comment = addComment(postId, { content, author });
    res.send(`Comment added to post ${postId}: ${comment.id}`);
  });
  
  return app;
}
// {/fact}

// True Negative Examples (Secure Code)

// good_case_1: Using specific HTTP methods instead of .all()
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(bodyParser.json());
  
  // ok: javascript-express-unsafe-http-methods
  app.get('/user-profile', (req, res) => {
    const userId = req.query.id;
    const userProfile = getUserProfile(userId);
    res.json(userProfile);
  });
  
  // ok: javascript-express-unsafe-http-methods
  app.post('/update-user-profile', (req, res) => {
    const userId = req.body.userId;
    const userData = req.body.userData;
    updateUserProfile(userId, userData);
    res.send('Profile updated');
  });
  
  return app;
}
// {/fact}

// good_case_2: Using express.Router() with specific HTTP methods
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_2() {
  const router = express.Router();
  
  // ok: javascript-express-unsafe-http-methods
  router.get('/account', (req, res) => {
    const accountId = req.query.id;
    const accountInfo = getAccountInfo(accountId);
    res.json(accountInfo);
  });
  
  // ok: javascript-express-unsafe-http-methods
  router.delete('/delete-account', (req, res) => {
    const accountId = req.body.id;
    deleteAccount(accountId);
    res.send('Account deleted');
  });
  
  return router;
}
// {/fact}

// good_case_3: Using express().route() with specific HTTP methods
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // ok: javascript-express-unsafe-http-methods
  app.route('/process-payment')
    .get((req, res) => {
      // Return payment form
      res.send('Payment form');
    })
    .post((req, res) => {
      const amount = req.body.amount;
      const cardInfo = req.body.cardInfo;
      processPayment(amount, cardInfo);
      res.json({ success: true });
    });
  
  return app;
}
// {/fact}

// good_case_4: Using express.Router().route() with specific HTTP methods
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_4() {
  const adminRouter = express.Router();
  
  // ok: javascript-express-unsafe-http-methods
  adminRouter.route('/system-settings')
    .get((req, res) => {
      const settings = getSystemSettings();
      res.json(settings);
    })
    .put((req, res) => {
      const settings = req.body.settings;
      updateSystemSettings(settings);
      res.send('Settings updated');
    });
  
  return adminRouter;
}
// {/fact}

// good_case_5: Using specific HTTP methods with middleware chain
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  const authMiddleware = (req, res, next) => {
    // Some authentication logic
    next();
  };
  
  // ok: javascript-express-unsafe-http-methods
  app.post('/update-password', authMiddleware, (req, res) => {
    const userId = req.session.userId;
    const newPassword = req.body.password;
    updateUserPassword(userId, newPassword);
    res.send('Password updated');
  });
  
  return app;
}
// {/fact}

// good_case_6: Using specific HTTP methods with path parameters
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_6() {
  const router = express.Router();
  
  // ok: javascript-express-unsafe-http-methods
  router.get('/users/:userId', (req, res) => {
    const userId = req.params.userId;
    const user = getUser(userId);
    res.json(user);
  });
  
  // ok: javascript-express-unsafe-http-methods
  router.delete('/users/:userId', (req, res) => {
    const userId = req.params.userId;
    deleteUser(userId);
    res.send(`User ${userId} deleted`);
  });
  
  return router;
}
// {/fact}

// good_case_7: Using specific HTTP methods with regex path
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: javascript-express-unsafe-http-methods
  app.get(/\/api\/products\/.*/, (req, res) => {
    const path = req.path;
    const productData = getProductByPath(path);
    res.json(productData);
  });
  
  // ok: javascript-express-unsafe-http-methods
  app.post(/\/api\/products\/.*/, (req, res) => {
    const path = req.path;
    const data = req.body;
    updateProductByPath(path, data);
    res.json({ success: true });
  });
  
  return app;
}
// {/fact}

// good_case_8: Using specific HTTP methods with multiple middleware functions
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_8() {
  const router = express.Router();
  
  const validateInput = (req, res, next) => {
    // Input validation
    next();
  };
  
  const logRequest = (req, res, next) => {
    // Request logging
    next();
  };
  
  // ok: javascript-express-unsafe-http-methods
  router.post('/transfer-funds', validateInput, logRequest, (req, res) => {
    const sourceAccount = req.body.source;
    const targetAccount = req.body.target;
    const amount = req.body.amount;
    transferFunds(sourceAccount, targetAccount, amount);
    res.send('Funds transferred');
  });
  
  return router;
}
// {/fact}

// good_case_9: Using app.route() with specific HTTP methods and error handling
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // ok: javascript-express-unsafe-http-methods
  app.route('/subscription')
    .get((req, res) => {
      try {
        const userId = req.session.userId;
        const subscription = getSubscription(userId);
        res.json(subscription);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    })
    .put((req, res) => {
      try {
        const userId = req.session.userId;
        const planId = req.body.planId;
        updateSubscription(userId, planId);
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
  
  return app;
}
// {/fact}

// good_case_10: Using specific HTTP methods with async handler
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_10() {
  const router = express.Router();
  
  // ok: javascript-express-unsafe-http-methods
  router.put('/publish-article', async (req, res) => {
    try {
      const articleId = req.body.articleId;
      const publishStatus = req.body.publish;
      await publishArticle(articleId, publishStatus);
      res.send('Article status updated');
    } catch (error) {
      res.status(500).send(error.message);
    }
  });
  
  return router;
}
// {/fact}

// good_case_11: Using specific HTTP methods for file upload
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const multer = require('multer');
  const upload = multer({ dest: 'uploads/' });
  
  // ok: javascript-express-unsafe-http-methods
  app.post('/upload-profile-picture', upload.single('avatar'), (req, res) => {
    const userId = req.session.userId;
    const file = req.file;
    saveProfilePicture(userId, file);
    res.send('Profile picture uploaded');
  });
  
  return app;
}
// {/fact}

// good_case_12: Using router.route() with specific HTTP methods and JSON response
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_12() {
  const router = express.Router();
  
  // ok: javascript-express-unsafe-http-methods
  router.route('/api/v1/orders')
    .get((req, res) => {
      const orders = getOrders();
      res.json(orders);
    })
    .post((req, res) => {
      const orderData = req.body;
      const result = createOrder(orderData);
      res.json(result);
    });
  
  return router;
}
// {/fact}

// good_case_13: Using specific HTTP methods with conditional logic
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // ok: javascript-express-unsafe-http-methods
  app.get('/feature-status', (req, res) => {
    const featureId = req.query.id;
    const status = getFeatureStatus(featureId);
    res.json({ id: featureId, enabled: status });
  });
  
  // ok: javascript-express-unsafe-http-methods
  app.put('/toggle-feature', (req, res) => {
    const featureId = req.body.id;
    const enabled = req.body.enabled;
    
    if (enabled === true) {
      enableFeature(featureId);
    } else {
      disableFeature(featureId);
    }
    
    res.send(`Feature ${featureId} updated`);
  });
  
  return app;
}
// {/fact}

// good_case_14: Using specific HTTP methods with database operations
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_14() {
  const router = express.Router();
  const db = require('./database');
  
  // ok: javascript-express-unsafe-http-methods
  router.get('/user-preferences', (req, res) => {
    const userId = req.session.userId;
    const preferences = db.users.getPreferences(userId);
    res.json(preferences);
  });
  
  // ok: javascript-express-unsafe-http-methods
  router.put('/user-preferences', (req, res) => {
    const userId = req.session.userId;
    const preferences = req.body.preferences;
    db.users.updatePreferences(userId, preferences);
    res.send('Preferences updated');
  });
  
  return router;
}
// {/fact}

// good_case_15: Using specific HTTP methods with destructuring and template literals
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // ok: javascript-express-unsafe-http-methods
  app.get('/api/comments/:postId', (req, res) => {
    const { postId } = req.params;
    const comments = getComments(postId);
    res.json(comments);
  });
  
  // ok: javascript-express-unsafe-http-methods
  app.post('/api/comments/:postId', (req, res) => {
    const { postId } = req.params;
    const { content, author } = req.body;
    const comment = addComment(postId, { content, author });
    res.send(`Comment added to post ${postId}: ${comment.id}`);
  });
  
  return app;
}
// {/fact}

// Helper functions to avoid undefined references
function updateUserProfile() {}
function deleteAccount() {}
function processPayment() {}
function updateSystemSettings() {}
function updateUserPassword() {}
function deleteUser() {}
function processAdminRequest() {}
function transferFunds() {}
function updateSubscription() {}
function publishArticle() {}
function saveProfilePicture() {}
function processOrder() {}
function enableFeature() {}
function disableFeature() {}
function addComment() {}
function getUserProfile() {}
function getAccountInfo() {}
function getSystemSettings() {}
function getUser() {}
function getProductByPath() {}
function updateProductByPath() {}
function getSubscription() {}
function getOrders() {}
function createOrder() {}
function getFeatureStatus() {}
function getComments() {}

module.exports = {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};