// This file contains examples of secure and insecure ways to handle sensitive data in cookies
// Rule ID: javascript-avoid-sensitive-data-in-cookie

// ----- True Positive Examples (Insecure) -----

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_1() {
  const express = require('express');
  const app = express();
  
  app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // Authenticate user (simplified)
    if (username === 'admin' && password === 'secret123') {
      // ruleid: javascript-avoid-sensitive-data-in-cookie
      res.cookie('password', password, { maxAge: 900000 });
      res.send('Login successful');
    } else {
      res.status(401).send('Authentication failed');
    }
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_2() {
  const express = require('express');
  const app = express();
  
  app.post('/register', (req, res) => {
    const user = {
      name: req.body.name,
      email: req.body.email,
      ssn: req.body.ssn,
      dob: req.body.dob
    };
    
    // Store user in database (simplified)
    // ...
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('userSSN', user.ssn);
    res.send('Registration successful');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_3() {
  const express = require('express');
  const app = express();
  
  app.post('/payment', (req, res) => {
    const paymentInfo = {
      cardNumber: req.body.cardNumber,
      cvv: req.body.cvv,
      expiry: req.body.expiry
    };
    
    // Process payment (simplified)
    // ...
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('creditCard', paymentInfo.cardNumber);
    res.send('Payment processed');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_4() {
  const http = require('http');
  
  const server = http.createServer((req, res) => {
    if (req.url === '/api/auth') {
      const apiKey = 'sk_live_1234567890abcdef';
      
      // ruleid: javascript-avoid-sensitive-data-in-cookie
      res.setHeader('Set-Cookie', `apiKey=${apiKey}; Path=/`);
      res.end('API key stored in cookie');
    }
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_5() {
  const express = require('express');
  const app = express();
  
  app.get('/account', (req, res) => {
    const accountDetails = {
      accountNumber: '1234567890',
      routingNumber: '987654321',
      balance: 5000
    };
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('accountInfo', JSON.stringify(accountDetails));
    res.send('Account information retrieved');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_6() {
  const express = require('express');
  const app = express();
  
  app.post('/reset-password', (req, res) => {
    const email = req.body.email;
    const securityQuestion = req.body.securityQuestion;
    const securityAnswer = req.body.securityAnswer;
    
    // Verify security question (simplified)
    // ...
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('securityAnswer', securityAnswer);
    res.send('Security answer verified');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_7() {
  const express = require('express');
  const app = express();
  
  app.post('/medical-record', (req, res) => {
    const patientId = req.body.patientId;
    const medicalHistory = req.body.medicalHistory;
    const diagnosis = req.body.diagnosis;
    
    // Store medical record (simplified)
    // ...
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('medicalData', JSON.stringify({ history: medicalHistory, diagnosis }));
    res.send('Medical record updated');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_8() {
  const express = require('express');
  const cookieParser = require('cookie-parser');
  const app = express();
  
  app.use(cookieParser());
  
  app.post('/update-profile', (req, res) => {
    const user = req.body;
    
    // Update user profile (simplified)
    // ...
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('taxId', user.taxIdentificationNumber);
    res.send('Profile updated');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_9() {
  const express = require('express');
  const app = express();
  
  app.post('/two-factor', (req, res) => {
    const phoneNumber = req.body.phoneNumber;
    const twoFactorCode = generateTwoFactorCode(); // Assume this function exists
    
    // Send code to phone number (simplified)
    // ...
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('2faCode', twoFactorCode);
    res.send('Two-factor authentication code sent');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_10() {
  const express = require('express');
  const app = express();
  
  app.post('/oauth/token', (req, res) => {
    // OAuth token generation (simplified)
    const accessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
    const refreshToken = 'rtok_1234567890abcdef';
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('refreshToken', refreshToken);
    res.json({ access_token: accessToken });
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_11() {
  const http = require('http');
  const url = require('url');
  
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    if (parsedUrl.pathname === '/save-credentials') {
      const username = parsedUrl.query.username;
      const password = parsedUrl.query.password;
      
      // ruleid: javascript-avoid-sensitive-data-in-cookie
      res.setHeader('Set-Cookie', `credentials=${username}:${password}; Path=/`);
      res.end('Credentials saved');
    }
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_12() {
  const express = require('express');
  const app = express();
  
  app.post('/store-key', (req, res) => {
    const encryptionKey = req.body.encryptionKey;
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('encKey', encryptionKey, { httpOnly: true });
    res.send('Encryption key stored');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_13() {
  const express = require('express');
  const app = express();
  
  app.get('/user-data', (req, res) => {
    // Get user data (simplified)
    const userData = {
      name: 'John Doe',
      email: 'john@example.com',
      address: '123 Main St, Anytown, USA',
      socialSecurityNumber: '123-45-6789'
    };
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('userData', JSON.stringify(userData));
    res.send('User data retrieved');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_14() {
  const express = require('express');
  const app = express();
  
  app.post('/save-preferences', (req, res) => {
    const preferences = req.body.preferences;
    const privateNotes = req.body.privateNotes;
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('privateData', privateNotes);
    res.cookie('preferences', preferences);
    res.send('Preferences saved');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_15() {
  const express = require('express');
  const app = express();
  
  app.post('/api/webhook', (req, res) => {
    const webhookSecret = req.body.webhookSecret;
    
    // ruleid: javascript-avoid-sensitive-data-in-cookie
    res.cookie('webhookAuth', webhookSecret);
    res.send('Webhook configured');
  });
}
// {/fact}

// ----- True Negative Examples (Secure) -----

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_1() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // Authenticate user (simplified)
    if (username === 'admin' && password === 'secret123') {
      // Generate a session token instead of storing sensitive data
      // ok: javascript-avoid-sensitive-data-in-cookie
      const sessionToken = crypto.randomBytes(64).toString('hex');
      res.cookie('session', sessionToken, { maxAge: 900000 });
      res.send('Login successful');
    } else {
      res.status(401).send('Authentication failed');
    }
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_2() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/register', (req, res) => {
    const user = {
      name: req.body.name,
      email: req.body.email,
      ssn: req.body.ssn,
      dob: req.body.dob
    };
    
    // Store user in database with a unique ID (simplified)
    const userId = 'user_' + crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('userId', userId);
    res.send('Registration successful');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_3() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/payment', (req, res) => {
    const paymentInfo = {
      cardNumber: req.body.cardNumber,
      cvv: req.body.cvv,
      expiry: req.body.expiry
    };
    
    // Process payment and generate transaction ID (simplified)
    const transactionId = 'txn_' + crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('transactionId', transactionId);
    res.send('Payment processed');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_4() {
  const http = require('http');
  const crypto = require('crypto');
  
  const server = http.createServer((req, res) => {
    if (req.url === '/api/auth') {
      const apiKey = 'sk_live_1234567890abcdef';
      
      // Generate a temporary token that maps to the API key on the server
      // ok: javascript-avoid-sensitive-data-in-cookie
      const temporaryToken = crypto.randomBytes(32).toString('hex');
      // Store mapping of temporaryToken -> apiKey in server memory/database
      
      res.setHeader('Set-Cookie', `apiToken=${temporaryToken}; Path=/`);
      res.end('API token stored in cookie');
    }
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_5() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.get('/account', (req, res) => {
    const accountDetails = {
      accountNumber: '1234567890',
      routingNumber: '987654321',
      balance: 5000
    };
    
    // Generate a reference ID for the account details
    const accountRefId = 'acc_' + crypto.randomBytes(16).toString('hex');
    // Store mapping in server-side cache or database
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('accountRef', accountRefId);
    res.send('Account information retrieved');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_6() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/reset-password', (req, res) => {
    const email = req.body.email;
    const securityQuestion = req.body.securityQuestion;
    const securityAnswer = req.body.securityAnswer;
    
    // Verify security question (simplified)
    // ...
    
    // Generate a time-limited token for password reset
    // ok: javascript-avoid-sensitive-data-in-cookie
    const resetToken = crypto.randomBytes(32).toString('hex');
    res.cookie('resetToken', resetToken, { maxAge: 3600000 }); // 1 hour expiry
    res.send('Security answer verified');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_7() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/medical-record', (req, res) => {
    const patientId = req.body.patientId;
    const medicalHistory = req.body.medicalHistory;
    const diagnosis = req.body.diagnosis;
    
    // Store medical record with a reference ID (simplified)
    const recordId = 'rec_' + crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('medicalRecordId', recordId);
    res.send('Medical record updated');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_8() {
  const express = require('express');
  const cookieParser = require('cookie-parser');
  const crypto = require('crypto');
  const app = express();
  
  app.use(cookieParser());
  
  app.post('/update-profile', (req, res) => {
    const user = req.body;
    
    // Update user profile and generate a profile version (simplified)
    const profileVersion = 'v' + Date.now();
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('profileVersion', profileVersion);
    res.send('Profile updated');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_9() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/two-factor', (req, res) => {
    const phoneNumber = req.body.phoneNumber;
    const twoFactorCode = generateTwoFactorCode(); // Assume this function exists
    
    // Send code to phone number (simplified)
    // ...
    
    // Generate a verification request ID
    const verificationId = 'ver_' + crypto.randomBytes(16).toString('hex');
    // Store mapping of verificationId -> twoFactorCode on server
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('verificationId', verificationId);
    res.send('Two-factor authentication code sent');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_10() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/oauth/token', (req, res) => {
    // OAuth token generation (simplified)
    const accessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
    const refreshToken = 'rtok_1234567890abcdef';
    
    // Encrypt the refresh token before storing in cookie
    const encryptionKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    let encryptedToken = cipher.update(refreshToken, 'utf8', 'hex');
    encryptedToken += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('encryptedRefreshToken', `${iv.toString('hex')}:${encryptedToken}:${authTag}`);
    res.json({ access_token: accessToken });
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_11() {
  const http = require('http');
  const url = require('url');
  const crypto = require('crypto');
  
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    if (parsedUrl.pathname === '/save-credentials') {
      const username = parsedUrl.query.username;
      
      // Generate a session ID instead of storing credentials
      // ok: javascript-avoid-sensitive-data-in-cookie
      const sessionId = crypto.randomBytes(32).toString('hex');
      res.setHeader('Set-Cookie', `sessionId=${sessionId}; Path=/; HttpOnly; Secure`);
      res.end('Session created');
    }
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_12() {
  const express = require('express');
  const app = express();
  
  app.post('/store-key', (req, res) => {
    const encryptionKey = req.body.encryptionKey;
    
    // Generate a key reference instead of storing the actual key
    // ok: javascript-avoid-sensitive-data-in-cookie
    const keyReference = `key_ref_${Date.now()}`;
    // Store the mapping in a secure server-side storage
    
    res.cookie('keyRef', keyReference, { httpOnly: true, secure: true });
    res.send('Encryption key reference stored');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_13() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.get('/user-data', (req, res) => {
    // Get user data (simplified)
    const userData = {
      name: 'John Doe',
      email: 'john@example.com',
      address: '123 Main St, Anytown, USA',
      socialSecurityNumber: '123-45-6789'
    };
    
    // Generate a data reference ID
    const dataRefId = 'data_' + crypto.randomBytes(16).toString('hex');
    // Store the mapping in server cache/database
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('userDataRef', dataRefId);
    res.send('User data retrieved');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_14() {
  const express = require('express');
  const app = express();
  
  app.post('/save-preferences', (req, res) => {
    const preferences = req.body.preferences;
    const privateNotes = req.body.privateNotes;
    
    // Store private data server-side and only reference public data in cookie
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('preferencesId', `pref_${Date.now()}`);
    res.send('Preferences saved');
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_15() {
  const express = require('express');
  const crypto = require('crypto');
  const app = express();
  
  app.post('/api/webhook', (req, res) => {
    const webhookSecret = req.body.webhookSecret;
    
    // Generate a webhook configuration ID
    const webhookId = 'whk_' + crypto.randomBytes(16).toString('hex');
    // Store mapping of webhookId -> webhookSecret on server
    
    // ok: javascript-avoid-sensitive-data-in-cookie
    res.cookie('webhookId', webhookId);
    res.send('Webhook configured');
  });
}
// {/fact}