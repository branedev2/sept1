// Import necessary modules
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// True Positive Examples (Vulnerable Code)

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_1() {
  app.get('/admin', (req, res) => {
    const isAdmin = req.query.isAdmin === 'true';
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (isAdmin) {
      res.send('Welcome to admin panel');
    } else {
      res.status(403).send('Access denied');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_2() {
  app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const role = req.body.role;
    
    // Some authentication logic here
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (role === 'admin') {
      res.send('Admin dashboard');
    } else {
      res.send('User dashboard');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_3() {
  app.get('/api/user/:id', (req, res) => {
    const requestedId = req.params.id;
    const providedRole = req.headers['x-user-role'];
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (providedRole === 'admin' || providedRole === 'manager') {
      // Fetch any user's data
      res.send(`Data for user ${requestedId}`);
    } else {
      // Only fetch own data
      res.send('Access denied');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_4() {
  app.get('/checkout', (req, res) => {
    const isPremiumUser = req.cookies.userType === 'premium';
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (isPremiumUser) {
      // Apply discount
      res.send('Discount applied');
    } else {
      res.send('Regular price');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_5() {
  app.post('/api/documents', (req, res) => {
    const userPermissions = req.body.permissions || [];
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (userPermissions.includes('create_document')) {
      // Create document
      res.send('Document created');
    } else {
      res.status(403).send('Permission denied');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_6() {
  app.get('/api/settings', (req, res) => {
    const userLevel = parseInt(req.query.userLevel, 10);
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (userLevel >= 5) {
      // Show advanced settings
      res.send('Advanced settings');
    } else {
      res.send('Basic settings');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_7() {
  app.post('/api/transfer', (req, res) => {
    const amount = req.body.amount;
    const bypassLimit = req.body.bypassLimit;
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (bypassLimit) {
      // Transfer any amount
      res.send(`Transferred $${amount}`);
    } else if (amount <= 1000) {
      // Transfer limited amount
      res.send(`Transferred $${amount}`);
    } else {
      res.send('Amount exceeds limit');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_8() {
  app.get('/api/resource', (req, res) => {
    const accessToken = req.query.token;
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (accessToken === 'admin_token') {
      res.send('Sensitive resource data');
    } else {
      res.status(403).send('Access denied');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_9() {
  app.post('/api/delete', (req, res) => {
    const userId = req.session.userId; // Authenticated user
    const targetId = req.body.targetId; // Target to delete
    const override = req.body.override;
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (override === true || userId === targetId) {
      // Delete the target
      res.send('Resource deleted');
    } else {
      res.status(403).send('Cannot delete');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_10() {
  app.get('/api/logs', (req, res) => {
    const showSensitive = req.query.showSensitive === '1';
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (showSensitive) {
      // Show sensitive logs
      res.send('Sensitive logs data');
    } else {
      // Show regular logs
      res.send('Regular logs');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_11() {
  app.post('/api/update-profile', (req, res) => {
    const userId = req.session.userId;
    const targetId = req.body.userId;
    const isSupport = req.body.isSupport;
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (isSupport || userId === targetId) {
      // Update profile
      res.send('Profile updated');
    } else {
      res.status(403).send('Cannot update profile');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_12() {
  app.get('/api/file', (req, res) => {
    const filePath = req.query.path;
    const skipCheck = req.query.skipCheck === 'true';
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (skipCheck) {
      // Serve file without checks
      res.sendFile(filePath);
    } else {
      // Perform security checks
      if (isPathSafe(filePath)) {
        res.sendFile(filePath);
      } else {
        res.status(403).send('Access denied');
      }
    }
  });
  
  function isPathSafe(path) {
    // Some validation logic
    return true;
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_13() {
  app.post('/api/payment', (req, res) => {
    const amount = req.body.amount;
    const skipVerification = req.body.skipVerification;
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (skipVerification) {
      // Process payment without verification
      res.send(`Payment of $${amount} processed`);
    } else {
      // Verify payment
      verifyAndProcess(amount, res);
    }
  });
  
  function verifyAndProcess(amount, res) {
    // Verification logic
    res.send(`Payment of $${amount} verified and processed`);
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_14() {
  app.get('/api/user-data', (req, res) => {
    const userId = req.query.userId;
    const accessLevel = req.query.accessLevel;
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (accessLevel >= 3) {
      // Provide full user data
      res.send(`Full data for user ${userId}`);
    } else {
      // Provide limited data
      res.send(`Limited data for user ${userId}`);
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_15() {
  app.post('/api/execute', (req, res) => {
    const command = req.body.command;
    const isTrusted = req.body.isTrusted;
    
    // ruleid: logic-user-controlled-checks-ts-rule
    if (isTrusted) {
      // Execute command
      executeCommand(command, res);
    } else {
      res.status(403).send('Command not allowed');
    }
  });
  
  function executeCommand(cmd, res) {
    // Execute command logic
    res.send(`Executed: ${cmd}`);
  }
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_1() {
  app.get('/admin', (req, res) => {
    // ok: logic-user-controlled-checks-ts-rule
    if (req.session.userRole === 'admin') {
      res.send('Welcome to admin panel');
    } else {
      res.status(403).send('Access denied');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_2() {
  app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // Authenticate user and retrieve role from database
    const userRole = authenticateAndGetRole(username, password);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (userRole === 'admin') {
      req.session.userRole = 'admin';
      res.send('Admin dashboard');
    } else {
      req.session.userRole = 'user';
      res.send('User dashboard');
    }
  });
  
  function authenticateAndGetRole(username, password) {
    // Authentication logic that verifies credentials and returns role from database
    return 'user'; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_3() {
  app.get('/api/user/:id', (req, res) => {
    const requestedId = req.params.id;
    const currentUserId = req.session.userId;
    const userRole = req.session.userRole;
    
    // ok: logic-user-controlled-checks-ts-rule
    if (userRole === 'admin' || currentUserId === requestedId) {
      // Fetch user data
      res.send(`Data for user ${requestedId}`);
    } else {
      res.status(403).send('Access denied');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_4() {
  app.get('/checkout', (req, res) => {
    const userId = req.session.userId;
    
    // Retrieve user type from database
    const userType = getUserTypeFromDatabase(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (userType === 'premium') {
      // Apply discount
      res.send('Discount applied');
    } else {
      res.send('Regular price');
    }
  });
  
  function getUserTypeFromDatabase(userId) {
    // Database lookup logic
    return 'regular'; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_5() {
  app.post('/api/documents', (req, res) => {
    const userId = req.session.userId;
    
    // Retrieve permissions from database
    const userPermissions = getUserPermissions(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (userPermissions.includes('create_document')) {
      // Create document
      res.send('Document created');
    } else {
      res.status(403).send('Permission denied');
    }
  });
  
  function getUserPermissions(userId) {
    // Database lookup logic
    return ['read_document']; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_6() {
  app.get('/api/settings', (req, res) => {
    const userId = req.session.userId;
    
    // Retrieve user level from database
    const userLevel = getUserLevel(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (userLevel >= 5) {
      // Show advanced settings
      res.send('Advanced settings');
    } else {
      res.send('Basic settings');
    }
  });
  
  function getUserLevel(userId) {
    // Database lookup logic
    return 3; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_7() {
  app.post('/api/transfer', (req, res) => {
    const amount = req.body.amount;
    const userId = req.session.userId;
    
    // Check if user has high limit permission
    const hasHighLimit = checkUserTransferLimit(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (hasHighLimit) {
      // Transfer any amount
      res.send(`Transferred $${amount}`);
    } else if (amount <= 1000) {
      // Transfer limited amount
      res.send(`Transferred $${amount}`);
    } else {
      res.send('Amount exceeds limit');
    }
  });
  
  function checkUserTransferLimit(userId) {
    // Database lookup logic
    return false; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_8() {
  app.get('/api/resource', (req, res) => {
    const accessToken = req.query.token;
    
    try {
      // ok: logic-user-controlled-checks-ts-rule
      const decoded = jwt.verify(accessToken, 'secret_key');
      if (decoded.role === 'admin') {
        res.send('Sensitive resource data');
      } else {
        res.status(403).send('Access denied');
      }
    } catch (err) {
      res.status(401).send('Invalid token');
    }
  });
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_9() {
  app.post('/api/delete', (req, res) => {
    const userId = req.session.userId; // Authenticated user
    const targetId = req.body.targetId; // Target to delete
    
    // Check if user has admin rights
    const isAdmin = checkIfUserIsAdmin(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (isAdmin || userId === targetId) {
      // Delete the target
      res.send('Resource deleted');
    } else {
      res.status(403).send('Cannot delete');
    }
  });
  
  function checkIfUserIsAdmin(userId) {
    // Database lookup logic
    return false; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_10() {
  app.get('/api/logs', (req, res) => {
    const userId = req.session.userId;
    
    // Check if user has permission to view sensitive logs
    const canViewSensitive = checkSensitiveLogsPermission(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (canViewSensitive) {
      // Show sensitive logs
      res.send('Sensitive logs data');
    } else {
      // Show regular logs
      res.send('Regular logs');
    }
  });
  
  function checkSensitiveLogsPermission(userId) {
    // Database lookup logic
    return false; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_11() {
  app.post('/api/update-profile', (req, res) => {
    const userId = req.session.userId;
    const targetId = req.body.userId;
    
    // Check if user is support staff
    const isSupportStaff = checkIfUserIsSupportStaff(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (isSupportStaff || userId === targetId) {
      // Update profile
      res.send('Profile updated');
    } else {
      res.status(403).send('Cannot update profile');
    }
  });
  
  function checkIfUserIsSupportStaff(userId) {
    // Database lookup logic
    return false; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_12() {
  app.get('/api/file', (req, res) => {
    const filePath = req.query.path;
    const userId = req.session.userId;
    
    // Check if user has bypass permission
    const canBypassCheck = checkFileAccessBypass(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (canBypassCheck) {
      // Serve file without checks
      res.sendFile(filePath);
    } else {
      // Perform security checks
      if (isPathSafe(filePath)) {
        res.sendFile(filePath);
      } else {
        res.status(403).send('Access denied');
      }
    }
  });
  
  function checkFileAccessBypass(userId) {
    // Database lookup logic
    return false; // Example return
  }
  
  function isPathSafe(path) {
    // Path validation logic
    return true; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_13() {
  app.post('/api/payment', (req, res) => {
    const amount = req.body.amount;
    const userId = req.session.userId;
    
    // Check if user is verified merchant
    const isVerifiedMerchant = checkVerifiedMerchantStatus(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (isVerifiedMerchant) {
      // Process payment without verification
      res.send(`Payment of $${amount} processed`);
    } else {
      // Verify payment
      verifyAndProcess(amount, res);
    }
  });
  
  function checkVerifiedMerchantStatus(userId) {
    // Database lookup logic
    return false; // Example return
  }
  
  function verifyAndProcess(amount, res) {
    // Verification logic
    res.send(`Payment of $${amount} verified and processed`);
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_14() {
  app.get('/api/user-data', (req, res) => {
    const userId = req.query.userId;
    const requestingUserId = req.session.userId;
    
    // Get access level from database
    const accessLevel = getUserAccessLevel(requestingUserId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (accessLevel >= 3) {
      // Provide full user data
      res.send(`Full data for user ${userId}`);
    } else {
      // Provide limited data
      res.send(`Limited data for user ${userId}`);
    }
  });
  
  function getUserAccessLevel(userId) {
    // Database lookup logic
    return 1; // Example return
  }
}
// {/fact}

// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_15() {
  app.post('/api/execute', (req, res) => {
    const command = req.body.command;
    const userId = req.session.userId;
    
    // Check if user is in trusted group
    const userIsTrusted = checkUserTrustLevel(userId);
    
    // ok: logic-user-controlled-checks-ts-rule
    if (userIsTrusted) {
      // Execute command
      executeCommand(command, res);
    } else {
      res.status(403).send('Command not allowed');
    }
  });
  
  function checkUserTrustLevel(userId) {
    // Database lookup logic
    return false; // Example return
  }
  
  function executeCommand(cmd, res) {
    // Execute command logic
    res.send(`Executed: ${cmd}`);
  }
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});