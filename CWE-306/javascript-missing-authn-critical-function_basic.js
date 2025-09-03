// File: missing_authn_examples.js
const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const router = express.Router();

// Setup middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ error: 'Authentication required' });
}

function verifyJWT(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  jwt.verify(token, 'secret-key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
}

// Database mock
const users = [
  { id: 1, username: 'admin', password: '$2b$10$...', isAdmin: true },
  { id: 2, username: 'user', password: '$2b$10$...', isAdmin: false }
];

// TRUE POSITIVES - Missing Authentication in Critical Functions

// Bad Case 1: Admin endpoint without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/admin/dashboard', (req, res) => {
    // Critical admin functionality without authentication check
    res.json({ adminData: 'Sensitive admin dashboard data' });
  });
}
// {/fact}

// Bad Case 2: User profile update without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/users/:id/update', (req, res) => {
    const userId = req.params.id;
    const { name, email } = req.body;
    
    // Update user profile without authentication check
    // This allows anyone to update any user's profile
    res.json({ success: true, message: `User ${userId} updated` });
  });
}
// {/fact}

// Bad Case 3: Password reset without proper authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/reset-password', (req, res) => {
    const { username, newPassword } = req.body;
    
    // Reset password without proper authentication
    // This allows anyone to reset any user's password
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    
    res.json({ success: true, message: 'Password reset successful' });
  });
}
// {/fact}

// Bad Case 4: Sensitive data access without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/users/:id/payment-info', (req, res) => {
    const userId = req.params.id;
    
    // Return sensitive payment information without authentication
    const paymentInfo = {
      cardNumber: '1234-5678-9012-3456',
      expiryDate: '12/25',
      cvv: '123'
    };
    
    res.json(paymentInfo);
  });
}
// {/fact}

// Bad Case 5: Delete user account without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5() {
  // ruleid: javascript-missing-authn-critical-function
  app.delete('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    
    // Delete user without authentication check
    // This allows anyone to delete any user account
    
    res.json({ success: true, message: `User ${userId} deleted` });
  });
}
// {/fact}

// Bad Case 6: API key management without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6() {
  // ruleid: javascript-missing-authn-critical-function
  router.post('/api/generate-api-key', (req, res) => {
    const { appName } = req.body;
    
    // Generate API key without authentication
    const apiKey = `key_${Math.random().toString(36).substring(2, 15)}`;
    
    res.json({ success: true, apiKey });
  });
}
// {/fact}

// Bad Case 7: System configuration without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7() {
  // ruleid: javascript-missing-authn-critical-function
  app.put('/api/system/config', (req, res) => {
    const { setting, value } = req.body;
    
    // Update system configuration without authentication
    // This allows anyone to change system settings
    
    res.json({ success: true, message: `Setting ${setting} updated to ${value}` });
  });
}
// {/fact}

// Bad Case 8: File upload without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/upload', (req, res) => {
    // File upload functionality without authentication
    // This allows anyone to upload files to the server
    
    res.json({ success: true, message: 'File uploaded successfully' });
  });
}
// {/fact}

// Bad Case 9: User role assignment without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/users/:id/role', (req, res) => {
    const userId = req.params.id;
    const { role } = req.body;
    
    // Assign role to user without authentication
    // This allows anyone to change user roles
    
    res.json({ success: true, message: `User ${userId} assigned role ${role}` });
  });
}
// {/fact}

// Bad Case 10: Database backup without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/database/backup', (req, res) => {
    // Database backup functionality without authentication
    // This allows anyone to download database backups
    
    res.json({ success: true, backupUrl: 'https://example.com/backups/latest.sql' });
  });
}
// {/fact}

// Bad Case 11: Logs access without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/logs', (req, res) => {
    const { date } = req.query;
    
    // Access to system logs without authentication
    // This allows anyone to view sensitive log data
    
    res.json({ 
      success: true, 
      logs: [
        { timestamp: '2023-01-01T12:00:00Z', level: 'INFO', message: 'User login' },
        { timestamp: '2023-01-01T12:05:00Z', level: 'ERROR', message: 'Failed payment' }
      ]
    });
  });
}
// {/fact}

// Bad Case 12: User search without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/users/search', (req, res) => {
    const { query } = req.query;
    
    // Search users without authentication
    // This allows anyone to search for user data
    
    const results = users.filter(user => 
      user.username.includes(query)
    );
    
    res.json({ success: true, results });
  });
}
// {/fact}

// Bad Case 13: Export data without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/export/users', (req, res) => {
    // Export user data without authentication
    // This allows anyone to download all user data
    
    res.json({ 
      success: true, 
      data: users.map(u => ({ id: u.id, username: u.username }))
    });
  });
}
// {/fact}

// Bad Case 14: Server status without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14() {
  // ruleid: javascript-missing-authn-critical-function
  app.get('/api/server/status', (req, res) => {
    // Server status information without authentication
    // This exposes sensitive system information
    
    res.json({
      success: true,
      status: {
        uptime: '10 days',
        memory: { total: '16GB', used: '8GB' },
        cpu: '45%',
        activeConnections: 132
      }
    });
  });
}
// {/fact}

// Bad Case 15: API to create new users without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15() {
  // ruleid: javascript-missing-authn-critical-function
  app.post('/api/users/create', (req, res) => {
    const { username, password, email } = req.body;
    
    // Create new user without authentication
    // This allows anyone to create users in the system
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    res.json({ success: true, message: 'User created successfully' });
  });
}
// {/fact}

// TRUE NEGATIVES - Proper Authentication in Critical Functions

// Good Case 1: Admin endpoint with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1() {
  // ok: javascript-missing-authn-critical-function
  app.get('/admin/dashboard', isAuthenticated, (req, res) => {
    // Admin functionality with authentication check
    res.json({ adminData: 'Sensitive admin dashboard data' });
  });
}
// {/fact}

// Good Case 2: User profile update with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/users/:id/update', isAuthenticated, (req, res) => {
    const userId = req.params.id;
    const { name, email } = req.body;
    
    // Update user profile with authentication check
    res.json({ success: true, message: `User ${userId} updated` });
  });
}
// {/fact}

// Good Case 3: Password reset with proper authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/reset-password', verifyJWT, (req, res) => {
    const { username, newPassword } = req.body;
    
    // Reset password with proper authentication
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    
    res.json({ success: true, message: 'Password reset successful' });
  });
}
// {/fact}

// Good Case 4: Sensitive data access with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/users/:id/payment-info', isAuthenticated, (req, res) => {
    const userId = req.params.id;
    
    // Only return data if user is authenticated
    const paymentInfo = {
      cardNumber: '1234-5678-9012-3456',
      expiryDate: '12/25',
      cvv: '123'
    };
    
    res.json(paymentInfo);
  });
}
// {/fact}

// Good Case 5: Delete user account with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5() {
  // ok: javascript-missing-authn-critical-function
  app.delete('/api/users/:id', isAuthenticated, (req, res) => {
    const userId = req.params.id;
    
    // Delete user with authentication check
    res.json({ success: true, message: `User ${userId} deleted` });
  });
}
// {/fact}

// Good Case 6: API key management with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6() {
  // ok: javascript-missing-authn-critical-function
  router.post('/api/generate-api-key', verifyJWT, (req, res) => {
    const { appName } = req.body;
    
    // Generate API key with authentication
    const apiKey = `key_${Math.random().toString(36).substring(2, 15)}`;
    
    res.json({ success: true, apiKey });
  });
}
// {/fact}

// Good Case 7: System configuration with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7() {
  // ok: javascript-missing-authn-critical-function
  app.put('/api/system/config', isAuthenticated, (req, res) => {
    const { setting, value } = req.body;
    
    // Update system configuration with authentication
    res.json({ success: true, message: `Setting ${setting} updated to ${value}` });
  });
}
// {/fact}

// Good Case 8: File upload with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/upload', isAuthenticated, (req, res) => {
    // File upload functionality with authentication
    res.json({ success: true, message: 'File uploaded successfully' });
  });
}
// {/fact}

// Good Case 9: User role assignment with authentication and admin check
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9() {
  function isAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.isAdmin) {
      return next();
    }
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  
  // ok: javascript-missing-authn-critical-function
  app.post('/api/users/:id/role', isAuthenticated, isAdmin, (req, res) => {
    const userId = req.params.id;
    const { role } = req.body;
    
    // Assign role to user with authentication and admin check
    res.json({ success: true, message: `User ${userId} assigned role ${role}` });
  });
}
// {/fact}

// Good Case 10: Database backup with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/database/backup', isAuthenticated, (req, res) => {
    // Database backup functionality with authentication
    res.json({ success: true, backupUrl: 'https://example.com/backups/latest.sql' });
  });
}
// {/fact}

// Good Case 11: Logs access with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/logs', verifyJWT, (req, res) => {
    const { date } = req.query;
    
    // Access to system logs with authentication
    res.json({ 
      success: true, 
      logs: [
        { timestamp: '2023-01-01T12:00:00Z', level: 'INFO', message: 'User login' },
        { timestamp: '2023-01-01T12:05:00Z', level: 'ERROR', message: 'Failed payment' }
      ]
    });
  });
}
// {/fact}

// Good Case 12: User search with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/users/search', isAuthenticated, (req, res) => {
    const { query } = req.query;
    
    // Search users with authentication
    const results = users.filter(user => 
      user.username.includes(query)
    );
    
    res.json({ success: true, results });
  });
}
// {/fact}

// Good Case 13: Export data with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/export/users', isAuthenticated, (req, res) => {
    // Export user data with authentication
    res.json({ 
      success: true, 
      data: users.map(u => ({ id: u.id, username: u.username }))
    });
  });
}
// {/fact}

// Good Case 14: Server status with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14() {
  // ok: javascript-missing-authn-critical-function
  app.get('/api/server/status', isAuthenticated, (req, res) => {
    // Server status information with authentication
    res.json({
      success: true,
      status: {
        uptime: '10 days',
        memory: { total: '16GB', used: '8GB' },
        cpu: '45%',
        activeConnections: 132
      }
    });
  });
}
// {/fact}

// Good Case 15: API to create new users with authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15() {
  // ok: javascript-missing-authn-critical-function
  app.post('/api/users/create', isAuthenticated, (req, res) => {
    const { username, password, email } = req.body;
    
    // Create new user with authentication
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    res.json({ success: true, message: 'User created successfully' });
  });
}
// {/fact}

module.exports = app;