// File: authentication_examples.js

const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const session = require('express-session');
const app = express();
const router = express.Router();

// Setup middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// JWT secret
const JWT_SECRET = 'your-jwt-secret';

// Database mock
const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'user', password: 'user123', role: 'user' }
];

// Authentication middleware
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function checkAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Admin access required' });
  }
}

// Login function
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// TRUE POSITIVES (Vulnerable Code Examples)

// bad_case_1: Admin panel route with no authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_1() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/admin/dashboard', (req, res) => {
    res.json({ 
      adminStats: 'Sensitive admin statistics',
      userCount: 1000,
      revenue: '$500,000'
    });
  });
}
// {/fact}

// bad_case_2: User data access without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_2() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const user = users.find(u => u.id === parseInt(userId));
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  });
}
// {/fact}

// bad_case_3: Delete user endpoint without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_3() {
  // ruleid: javascript-missing-authn-critical-function
  app.delete('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const userIndex = users.findIndex(u => u.id === parseInt(userId));
    if (userIndex !== -1) {
      users.splice(userIndex, 1);
      res.json({ message: 'User deleted successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  });
}
// {/fact}

// bad_case_4: Update user password without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_4() {
  // ruleid: javascript-missing-authn-critical-function
  app.put('/api/users/:id/password', (req, res) => {
    const userId = req.params.id;
    const { newPassword } = req.body;
    const user = users.find(u => u.id === parseInt(userId));
    
    if (user) {
      user.password = newPassword;
      res.json({ message: 'Password updated successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  });
}
// {/fact}

// bad_case_5: System settings access without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_5() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/system/settings', (req, res) => {
    res.json({
      databaseUrl: 'mongodb://localhost:27017',
      apiKeys: {
        stripe: 'sk_test_123456',
        mailchimp: '8d7f6e5d4c3b2a1'
      },
      emailServer: 'smtp.company.com'
    });
  });
}
// {/fact}

// bad_case_6: Payment processing without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_6() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/payments/process', (req, res) => {
    const { amount, cardDetails, userId } = req.body;
    // Process payment logic
    res.json({
      success: true,
      transactionId: 'txn_' + Math.random().toString(36).substr(2, 9),
      amount: amount
    });
  });
}
// {/fact}

// bad_case_7: File upload without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_7() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/files/upload', (req, res) => {
    // File upload logic would go here
    res.json({
      success: true,
      fileUrl: `https://example.com/uploads/${req.body.filename}`
    });
  });
}
// {/fact}

// bad_case_8: User profile update without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_8() {
  // ruleid: javascript-missing-authn-critical-function
  router.put('/api/profile', (req, res) => {
    const { userId, name, email, address } = req.body;
    // Update user profile logic
    res.json({
      success: true,
      message: 'Profile updated successfully'
    });
  });
}
// {/fact}

// bad_case_9: Export sensitive data without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_9() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/export/users', (req, res) => {
    // Export all users data
    res.json({
      users: users.map(u => ({
        id: u.id,
        username: u.username,
        role: u.role
      }))
    });
  });
}
// {/fact}

// bad_case_10: API key generation without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_10() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/keys/generate', (req, res) => {
    const { userId, permissions } = req.body;
    const apiKey = 'api_' + Math.random().toString(36).substr(2, 16);
    
    res.json({
      apiKey: apiKey,
      permissions: permissions || ['read'],
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    });
  });
}
// {/fact}

// bad_case_11: Webhook configuration without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_11() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/webhooks/configure', (req, res) => {
    const { url, events, secret } = req.body;
    
    // Save webhook configuration
    res.json({
      success: true,
      webhookId: 'wh_' + Math.random().toString(36).substr(2, 9)
    });
  });
}
// {/fact}

// bad_case_12: Database backup endpoint without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_12() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/database/backup', (req, res) => {
    // Logic to create database backup
    res.json({
      success: true,
      backupUrl: 'https://backups.example.com/db-20230815.sql'
    });
  });
}
// {/fact}

// bad_case_13: Email sending endpoint without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_13() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/email/send', (req, res) => {
    const { to, subject, body } = req.body;
    
    // Email sending logic
    res.json({
      success: true,
      messageId: 'msg_' + Math.random().toString(36).substr(2, 9)
    });
  });
}
// {/fact}

// bad_case_14: User impersonation without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_14() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/admin/impersonate', (req, res) => {
    const { targetUserId } = req.body;
    const targetUser = users.find(u => u.id === parseInt(targetUserId));
    
    if (targetUser) {
      const token = jwt.sign({ id: targetUser.id, username: targetUser.username, role: targetUser.role }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  });
}
// {/fact}

// bad_case_15: System logs access without authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_15() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/system/logs', (req, res) => {
    // Logic to fetch system logs
    const logs = [
      { timestamp: '2023-08-15T10:30:00Z', level: 'INFO', message: 'System started' },
      { timestamp: '2023-08-15T10:35:22Z', level: 'ERROR', message: 'Database connection failed' }
    ];
    
    res.json({ logs });
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// good_case_1: Admin panel route with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_1() {
  // ok: javascript-missing-authn-critical-function
  app.get('/admin/dashboard', authenticate, checkAdmin, (req, res) => {
    res.json({ 
      adminStats: 'Sensitive admin statistics',
      userCount: 1000,
      revenue: '$500,000'
    });
  });
}
// {/fact}

// good_case_2: User data access with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_2() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/users/:id', authenticate, (req, res) => {
    const userId = req.params.id;
    
    // Only allow users to access their own data or admins to access any data
    if (req.user.id === parseInt(userId) || req.user.role === 'admin') {
      const user = users.find(u => u.id === parseInt(userId));
      if (user) {
        res.json(user);
      } else {
        res.status(404).json({ message: 'User not found' });
      }
    } else {
      res.status(403).json({ message: 'Access denied' });
    }
  });
}
// {/fact}

// good_case_3: Delete user endpoint with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_3() {
  // ok: javascript-missing-authn-critical-function
  app.delete('/api/users/:id', authenticate, checkAdmin, (req, res) => {
    const userId = req.params.id;
    const userIndex = users.findIndex(u => u.id === parseInt(userId));
    if (userIndex !== -1) {
      users.splice(userIndex, 1);
      res.json({ message: 'User deleted successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  });
}
// {/fact}

// good_case_4: Update user password with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_4() {
  // ok: javascript-missing-authn-critical-function
  app.put('/api/users/:id/password', authenticate, (req, res) => {
    const userId = req.params.id;
    
    // Only allow users to update their own password or admins to update any password
    if (req.user.id === parseInt(userId) || req.user.role === 'admin') {
      const { newPassword } = req.body;
      const user = users.find(u => u.id === parseInt(userId));
      
      if (user) {
        user.password = newPassword;
        res.json({ message: 'Password updated successfully' });
      } else {
        res.status(404).json({ message: 'User not found' });
      }
    } else {
      res.status(403).json({ message: 'Access denied' });
    }
  });
}
// {/fact}

// good_case_5: System settings access with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_5() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/system/settings', authenticate, checkAdmin, (req, res) => {
    res.json({
      databaseUrl: 'mongodb://localhost:27017',
      apiKeys: {
        stripe: 'sk_test_123456',
        mailchimp: '8d7f6e5d4c3b2a1'
      },
      emailServer: 'smtp.company.com'
    });
  });
}
// {/fact}

// good_case_6: Payment processing with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_6() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/payments/process', authenticate, (req, res) => {
    const { amount, cardDetails } = req.body;
    const userId = req.user.id;
    
    // Process payment logic
    res.json({
      success: true,
      transactionId: 'txn_' + Math.random().toString(36).substr(2, 9),
      amount: amount,
      userId: userId
    });
  });
}
// {/fact}

// good_case_7: File upload with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_7() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/files/upload', authenticate, (req, res) => {
    // File upload logic would go here
    res.json({
      success: true,
      fileUrl: `https://example.com/uploads/${req.user.id}/${req.body.filename}`
    });
  });
}
// {/fact}

// good_case_8: User profile update with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_8() {
  // ok: javascript-missing-authn-critical-function
  router.put('/api/profile', authenticate, (req, res) => {
    const { name, email, address } = req.body;
    const userId = req.user.id;
    
    // Update user profile logic
    res.json({
      success: true,
      message: 'Profile updated successfully',
      userId: userId
    });
  });
}
// {/fact}

// good_case_9: Export sensitive data with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_9() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/export/users', authenticate, checkAdmin, (req, res) => {
    // Export all users data
    res.json({
      users: users.map(u => ({
        id: u.id,
        username: u.username,
        role: u.role
      }))
    });
  });
}
// {/fact}

// good_case_10: API key generation with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_10() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/keys/generate', authenticate, (req, res) => {
    const userId = req.user.id;
    const { permissions } = req.body;
    
    // Only allow users to generate keys for themselves or admins for anyone
    const apiKey = 'api_' + Math.random().toString(36).substr(2, 16);
    
    res.json({
      apiKey: apiKey,
      userId: userId,
      permissions: permissions || ['read'],
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    });
  });
}
// {/fact}

// good_case_11: Webhook configuration with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_11() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/webhooks/configure', authenticate, (req, res) => {
    const { url, events, secret } = req.body;
    const userId = req.user.id;
    
    // Save webhook configuration
    res.json({
      success: true,
      webhookId: 'wh_' + Math.random().toString(36).substr(2, 9),
      userId: userId
    });
  });
}
// {/fact}

// good_case_12: Database backup endpoint with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_12() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/database/backup', authenticate, checkAdmin, (req, res) => {
    // Logic to create database backup
    res.json({
      success: true,
      backupUrl: 'https://backups.example.com/db-20230815.sql',
      requestedBy: req.user.username
    });
  });
}
// {/fact}

// good_case_13: Email sending endpoint with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_13() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/email/send', authenticate, (req, res) => {
    const { to, subject, body } = req.body;
    const sender = req.user.username;
    
    // Email sending logic
    res.json({
      success: true,
      messageId: 'msg_' + Math.random().toString(36).substr(2, 9),
      sender: sender
    });
  });
}
// {/fact}

// good_case_14: User impersonation with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_14() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/admin/impersonate', authenticate, checkAdmin, (req, res) => {
    const { targetUserId } = req.body;
    const adminId = req.user.id;
    const targetUser = users.find(u => u.id === parseInt(targetUserId));
    
    if (targetUser) {
      const token = jwt.sign({ 
        id: targetUser.id, 
        username: targetUser.username, 
        role: targetUser.role,
        impersonatedBy: adminId 
      }, JWT_SECRET, { expiresIn: '1h' });
      
      res.json({ token });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  });
}
// {/fact}

// good_case_15: System logs access with authentication
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_15() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/system/logs', authenticate, checkAdmin, (req, res) => {
    // Logic to fetch system logs
    const logs = [
      { timestamp: '2023-08-15T10:30:00Z', level: 'INFO', message: 'System started' },
      { timestamp: '2023-08-15T10:35:22Z', level: 'ERROR', message: 'Database connection failed' }
    ];
    
    res.json({ 
      logs,
      accessedBy: req.user.username
    });
  });
}
// {/fact}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;