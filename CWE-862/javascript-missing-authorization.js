// Example test cases for javascript-missing-authorization rule
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const router = express.Router();

// Middleware for authentication and authorization
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  
  try {
    const decoded = jwt.verify(token, 'your-secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function checkAdminRole(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Access denied' });
  }
}

function checkUserAccess(req, res, next) {
  if (req.user && (req.user.id === req.params.userId || req.user.role === 'admin')) {
    next();
  } else {
    res.status(403).json({ message: 'Access denied' });
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_1() {
  // ruleid: javascript-missing-authorization
  app.get('/api/users', (req, res) => {
    // This endpoint returns all users without any authorization check
    // Anyone can access sensitive user data
    const users = fetchAllUsers();
    res.json(users);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_2() {
  // ruleid: javascript-missing-authorization
  app.post('/api/admin/delete-user', (req, res) => {
    // This admin endpoint has no authorization check
    const userId = req.body.userId;
    deleteUser(userId);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_3() {
  // ruleid: javascript-missing-authorization
  router.get('/api/payment-details', (req, res) => {
    // Sensitive financial information without authorization
    const paymentDetails = getPaymentDetails();
    res.json(paymentDetails);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_4() {
  // Authentication but no authorization check
  app.use('/api/settings', authenticate);
  
  // ruleid: javascript-missing-authorization
  app.put('/api/settings/system', (req, res) => {
    // This is authenticated but lacks role-based authorization
    // Any authenticated user can modify system settings
    updateSystemSettings(req.body);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_5() {
  // ruleid: javascript-missing-authorization
  app.delete('/api/posts/:postId', (req, res) => {
    // No check to verify if the user owns this post or has delete rights
    const postId = req.params.postId;
    deletePost(postId);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_6() {
  const userRoutes = express.Router();
  
  // ruleid: javascript-missing-authorization
  userRoutes.get('/profile/:userId', (req, res) => {
    // No check to verify if the requesting user has access to this profile
    const userId = req.params.userId;
    const profile = getUserProfile(userId);
    res.json(profile);
  });
  
  app.use('/api/users', userRoutes);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_7() {
  // ruleid: javascript-missing-authorization
  app.post('/api/orders/refund', (req, res) => {
    // Financial operation without authorization check
    const orderId = req.body.orderId;
    const amount = req.body.amount;
    processRefund(orderId, amount);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_8() {
  // Using a different HTTP method
  // ruleid: javascript-missing-authorization
  app.patch('/api/organization/settings', (req, res) => {
    // Organization settings can be modified by anyone
    updateOrgSettings(req.body);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_9() {
  // ruleid: javascript-missing-authorization
  router.get('/api/reports/revenue', (req, res) => {
    // Sensitive business data without authorization
    const revenueData = generateRevenueReport();
    res.json(revenueData);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_10() {
  // ruleid: javascript-missing-authorization
  app.get('/api/users/:userId/documents', (req, res) => {
    // Access to user documents without verifying ownership
    const userId = req.params.userId;
    const documents = getUserDocuments(userId);
    res.json(documents);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_11() {
  // Authentication middleware but applied after route definition
  // ruleid: javascript-missing-authorization
  const route = app.post('/api/projects/create', (req, res) => {
    createProject(req.body);
    res.json({ success: true });
  });
  
  // Authentication added after route definition doesn't protect the route
  route.use(authenticate);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_12() {
  // Using Express Router with nested routes
  const apiRouter = express.Router();
  const adminRouter = express.Router();
  
  // ruleid: javascript-missing-authorization
  adminRouter.post('/create-user', (req, res) => {
    // Admin functionality without authorization check
    createUser(req.body);
    res.json({ success: true });
  });
  
  apiRouter.use('/admin', adminRouter);
  app.use('/api', apiRouter);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_13() {
  // Using arrow function
  // ruleid: javascript-missing-authorization
  app.get('/api/logs', (req, res) => {
    // System logs accessible without authorization
    const logs = getSystemLogs();
    res.json(logs);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_14() {
  // Using a different pattern with middleware array
  // ruleid: javascript-missing-authorization
  app.post('/api/announcements', [
    validateAnnouncementData
  ], (req, res) => {
    // Has validation but no authorization
    createAnnouncement(req.body);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=1}
function bad_case_15() {
  // Using app.route() chaining
  // ruleid: javascript-missing-authorization
  app.route('/api/sensitive-data')
    .get((req, res) => {
      // Sensitive data accessible without authorization
      const data = getSensitiveData();
      res.json(data);
    })
    .post((req, res) => {
      // Can create sensitive data without authorization
      createSensitiveData(req.body);
      res.json({ success: true });
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_1() {
  // ok: javascript-missing-authorization
  app.get('/api/users', authenticate, checkAdminRole, (req, res) => {
    // This endpoint has proper authentication and authorization
    const users = fetchAllUsers();
    res.json(users);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_2() {
  // ok: javascript-missing-authorization
  app.post('/api/admin/delete-user', authenticate, checkAdminRole, (req, res) => {
    // This admin endpoint has proper authorization check
    const userId = req.body.userId;
    deleteUser(userId);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_3() {
  // ok: javascript-missing-authorization
  router.get('/api/payment-details', authenticate, (req, res) => {
    // Authenticated access to financial information
    const paymentDetails = getPaymentDetails(req.user.id);
    res.json(paymentDetails);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_4() {
  // ok: javascript-missing-authorization
  app.put('/api/settings/system', authenticate, checkAdminRole, (req, res) => {
    // This has both authentication and role-based authorization
    updateSystemSettings(req.body);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_5() {
  // ok: javascript-missing-authorization
  app.delete('/api/posts/:postId', authenticate, async (req, res) => {
    // Check if user owns this post or has admin rights
    const postId = req.params.postId;
    const post = await getPost(postId);
    
    if (post.authorId === req.user.id || req.user.role === 'admin') {
      deletePost(postId);
      res.json({ success: true });
    } else {
      res.status(403).json({ message: 'Unauthorized' });
    }
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_6() {
  const userRoutes = express.Router();
  
  // ok: javascript-missing-authorization
  userRoutes.get('/profile/:userId', authenticate, (req, res) => {
    // Check if user is requesting their own profile or has admin access
    const userId = req.params.userId;
    if (userId === req.user.id || req.user.role === 'admin') {
      const profile = getUserProfile(userId);
      res.json(profile);
    } else {
      res.status(403).json({ message: 'Access denied' });
    }
  });
  
  app.use('/api/users', userRoutes);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_7() {
  // ok: javascript-missing-authorization
  app.post('/api/orders/refund', authenticate, checkAdminRole, (req, res) => {
    // Financial operation with proper authorization
    const orderId = req.body.orderId;
    const amount = req.body.amount;
    processRefund(orderId, amount);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_8() {
  // Using middleware array pattern
  // ok: javascript-missing-authorization
  app.patch('/api/organization/settings', [
    authenticate,
    checkAdminRole
  ], (req, res) => {
    updateOrgSettings(req.body);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_9() {
  // ok: javascript-missing-authorization
  router.get('/api/reports/revenue', authenticate, (req, res) => {
    // Check user role for access to sensitive business data
    if (req.user.role === 'admin' || req.user.role === 'finance') {
      const revenueData = generateRevenueReport();
      res.json(revenueData);
    } else {
      res.status(403).json({ message: 'Unauthorized' });
    }
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_10() {
  // ok: javascript-missing-authorization
  app.get('/api/users/:userId/documents', authenticate, (req, res) => {
    // Verify ownership or admin access
    const userId = req.params.userId;
    if (userId === req.user.id || req.user.role === 'admin') {
      const documents = getUserDocuments(userId);
      res.json(documents);
    } else {
      res.status(403).json({ message: 'Access denied' });
    }
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_11() {
  // Using a custom authorization middleware
  function checkProjectAccess(req, res, next) {
    const projectId = req.params.projectId;
    if (userHasAccessToProject(req.user.id, projectId)) {
      next();
    } else {
      res.status(403).json({ message: 'Access denied' });
    }
  }
  
  // ok: javascript-missing-authorization
  app.get('/api/projects/:projectId', authenticate, checkProjectAccess, (req, res) => {
    const projectId = req.params.projectId;
    const project = getProject(projectId);
    res.json(project);
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_12() {
  // Using Express Router with proper authorization
  const apiRouter = express.Router();
  const adminRouter = express.Router();
  
  // Apply authentication and authorization to all admin routes
  adminRouter.use(authenticate, checkAdminRole);
  
  // ok: javascript-missing-authorization
  adminRouter.post('/create-user', (req, res) => {
    // Admin functionality with authorization check applied at router level
    createUser(req.body);
    res.json({ success: true });
  });
  
  apiRouter.use('/admin', adminRouter);
  app.use('/api', apiRouter);
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_13() {
  // Using app.route() with proper authorization
  // ok: javascript-missing-authorization
  app.route('/api/sensitive-data')
    .all(authenticate, checkAdminRole)
    .get((req, res) => {
      // Authorization applied to all methods on this route
      const data = getSensitiveData();
      res.json(data);
    })
    .post((req, res) => {
      createSensitiveData(req.body);
      res.json({ success: true });
    });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_14() {
  // Using a role-based access control system
  const rbac = {
    canAccessUserData: function(user, targetUserId) {
      return user.id === targetUserId || user.role === 'admin';
    }
  };
  
  // ok: javascript-missing-authorization
  app.get('/api/users/:userId/sensitive-info', authenticate, (req, res) => {
    const targetUserId = req.params.userId;
    
    if (rbac.canAccessUserData(req.user, targetUserId)) {
      const userInfo = getSensitiveUserInfo(targetUserId);
      res.json(userInfo);
    } else {
      res.status(403).json({ message: 'Access denied' });
    }
  });
}
// {/fact}

// {fact rule=missing-authorization@v1.0 defects=0}
function good_case_15() {
  // Using conditional authorization based on resource ownership
  // ok: javascript-missing-authorization
  app.put('/api/comments/:commentId', authenticate, async (req, res) => {
    const commentId = req.params.commentId;
    const comment = await getComment(commentId);
    
    // Check if user owns the comment or has moderator/admin role
    if (comment.authorId === req.user.id || 
        ['moderator', 'admin'].includes(req.user.role)) {
      updateComment(commentId, req.body);
      res.json({ success: true });
    } else {
      res.status(403).json({ message: 'Unauthorized to edit this comment' });
    }
  });
}
// {/fact}

// Helper functions (not part of the test cases)
function fetchAllUsers() { return []; }
function deleteUser() {}
function getPaymentDetails() { return {}; }
function updateSystemSettings() {}
function deletePost() {}
function getUserProfile() { return {}; }
function processRefund() {}
function updateOrgSettings() {}
function generateRevenueReport() { return {}; }
function getUserDocuments() { return []; }
function createProject() {}
function createUser() {}
function getSystemLogs() { return []; }
function validateAnnouncementData(req, res, next) { next(); }
function createAnnouncement() {}
function getSensitiveData() { return {}; }
function createSensitiveData() {}
function getPost() { return { authorId: '123' }; }
function userHasAccessToProject() { return true; }
function getProject() { return {}; }
function getSensitiveUserInfo() { return {}; }
function getComment() { return { authorId: '123' }; }
function updateComment() {}