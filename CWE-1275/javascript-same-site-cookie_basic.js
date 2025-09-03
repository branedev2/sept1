// Cookie security examples for SameSite attribute
const express = require('express');
const cookieParser = require('cookie-parser');
const http = require('http');
const https = require('https');
const axios = require('axios');

// BAD EXAMPLES - Vulnerable cookie configurations

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.get('/login', (req, res) => {
    // ruleid: javascript-same-site-cookie
    res.cookie('authToken', 'secret-token-value', {
      httpOnly: true,
      secure: true
      // Missing sameSite attribute for sensitive cookie
    });
    res.send('Logged in');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.post('/authenticate', (req, res) => {
    // ruleid: javascript-same-site-cookie
    res.cookie('sessionId', '12345', {
      maxAge: 3600000,
      httpOnly: true
      // Missing sameSite for session cookie
    });
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/set-preferences', (req, res) => {
    // ruleid: javascript-same-site-cookie
    res.cookie('userToken', 'user-jwt-token', {
      secure: true,
      sameSite: 'none' // Explicitly set to none without secure flag
    });
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.post('/api/payment', (req, res) => {
    // ruleid: javascript-same-site-cookie
    res.cookie('paymentAuth', 'payment-verification-token', {
      // No security attributes at all for sensitive cookie
    });
    res.status(200).send('Payment processed');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/oauth/callback', (req, res) => {
    // ruleid: javascript-same-site-cookie
    res.cookie('oauthState', req.query.state, {
      maxAge: 300000,
      sameSite: '' // Empty string is invalid and won't provide protection
    });
    res.redirect('/complete-oauth');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_6() {
  const http = require('http');
  const server = http.createServer((req, res) => {
    if (req.url === '/login') {
      // ruleid: javascript-same-site-cookie
      res.setHeader('Set-Cookie', 'authToken=abc123; HttpOnly; Secure');
      // Missing SameSite in header-based cookie setting
      res.end('Cookie set');
    }
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.post('/update-profile', (req, res) => {
    const userData = req.body;
    // ruleid: javascript-same-site-cookie
    res.cookie('profileData', JSON.stringify(userData), {
      sameSite: 'lax', // Lax might not be sufficient for sensitive operations
      maxAge: 86400000
    });
    res.send('Profile updated');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/api/auth', (req, res) => {
    if (validateUser(req.body)) {
      // ruleid: javascript-same-site-cookie
      document.cookie = `authToken=${generateToken()}; path=/; secure; httpOnly`;
      // Client-side cookie without SameSite
      res.json({ success: true });
    }
  });
  
  function validateUser(data) { return true; }
  function generateToken() { return 'random-token'; }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.use((req, res, next) => {
    // ruleid: javascript-same-site-cookie
    res.cookie('csrf', generateCSRFToken(), {
      // CSRF token cookie without SameSite protection
      httpOnly: true
    });
    next();
  });
  
  function generateCSRFToken() { return 'random-csrf-token'; }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/api/checkout', (req, res) => {
    const options = {
      maxAge: 3600000,
      httpOnly: true
    };
    
    if (req.secure) {
      options.secure = true;
    }
    
    // ruleid: javascript-same-site-cookie
    res.cookie('checkoutSession', req.body.sessionId, options);
    // Missing SameSite even with conditional secure flag
    res.send('Checkout started');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/remember-me', (req, res) => {
    // ruleid: javascript-same-site-cookie
    res.cookie('rememberMe', 'true', {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: 'None' // Incorrect capitalization won't work properly
    });
    res.redirect('/home');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_12() {
  const cookieValue = encodeURIComponent(JSON.stringify({
    userId: 123,
    role: 'admin'
  }));
  
  // ruleid: javascript-same-site-cookie
  document.cookie = `userInfo=${cookieValue}; path=/admin; secure`;
  // Client-side cookie with sensitive info missing SameSite
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (authenticateUser(username, password)) {
      const token = generateAuthToken(username);
      // ruleid: javascript-same-site-cookie
      res.cookie('auth', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        // Missing SameSite even with environment-based secure flag
      });
      res.json({ success: true });
    }
  });
  
  function authenticateUser(u, p) { return true; }
  function generateAuthToken(u) { return 'token'; }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/third-party-auth', (req, res) => {
    // ruleid: javascript-same-site-cookie
    res.cookie('authRedirect', req.query.redirectUrl, {
      maxAge: 300000,
      sameSite: 'none'
      // Missing secure flag with SameSite=None
    });
    res.redirect(req.query.authProvider);
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.post('/api/set-preferences', (req, res) => {
    const cookieOptions = {};
    
    if (req.body.rememberMe) {
      cookieOptions.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    }
    
    // ruleid: javascript-same-site-cookie
    res.cookie('userPrefs', JSON.stringify(req.body.preferences), cookieOptions);
    // Dynamic options object missing SameSite
    res.json({ success: true });
  });
}
// {/fact}

// GOOD EXAMPLES - Secure cookie configurations

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/login', (req, res) => {
    // ok: javascript-same-site-cookie
    res.cookie('authToken', 'secret-token-value', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' // Properly set sameSite for sensitive cookie
    });
    res.send('Logged in');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/authenticate', (req, res) => {
    // ok: javascript-same-site-cookie
    res.cookie('sessionId', '12345', {
      maxAge: 3600000,
      httpOnly: true,
      secure: true,
      sameSite: 'lax' // Lax is acceptable for most cases
    });
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/set-preferences', (req, res) => {
    // ok: javascript-same-site-cookie
    res.cookie('userToken', 'user-jwt-token', {
      secure: true,
      sameSite: 'none', // None is acceptable when secure is true
      httpOnly: true
    });
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.post('/api/payment', (req, res) => {
    // ok: javascript-same-site-cookie
    res.cookie('paymentAuth', 'payment-verification-token', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' // Strict for highly sensitive operations
    });
    res.status(200).send('Payment processed');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/oauth/callback', (req, res) => {
    // ok: javascript-same-site-cookie
    res.cookie('oauthState', req.query.state, {
      maxAge: 300000,
      secure: true,
      sameSite: 'lax' // Lax is good for OAuth flows
    });
    res.redirect('/complete-oauth');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_6() {
  const http = require('http');
  const server = http.createServer((req, res) => {
    if (req.url === '/login') {
      // ok: javascript-same-site-cookie
      res.setHeader('Set-Cookie', 'authToken=abc123; HttpOnly; Secure; SameSite=Strict');
      // Properly set SameSite in header-based cookie
      res.end('Cookie set');
    }
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.post('/update-profile', (req, res) => {
    const userData = req.body;
    // ok: javascript-same-site-cookie
    res.cookie('profileData', JSON.stringify(userData), {
      sameSite: 'strict', // Strict for profile data
      secure: true,
      httpOnly: true,
      maxAge: 86400000
    });
    res.send('Profile updated');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/api/auth', (req, res) => {
    if (validateUser(req.body)) {
      // ok: javascript-same-site-cookie
      document.cookie = `authToken=${generateToken()}; path=/; secure; httpOnly; sameSite=strict`;
      // Client-side cookie with SameSite
      res.json({ success: true });
    }
  });
  
  function validateUser(data) { return true; }
  function generateToken() { return 'random-token'; }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.use((req, res, next) => {
    // ok: javascript-same-site-cookie
    res.cookie('csrf', generateCSRFToken(), {
      httpOnly: true,
      secure: true,
      sameSite: 'lax' // CSRF token with SameSite protection
    });
    next();
  });
  
  function generateCSRFToken() { return 'random-csrf-token'; }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/api/checkout', (req, res) => {
    const options = {
      maxAge: 3600000,
      httpOnly: true,
      sameSite: 'strict', // Always set SameSite
      secure: req.secure
    };
    
    // ok: javascript-same-site-cookie
    res.cookie('checkoutSession', req.body.sessionId, options);
    res.send('Checkout started');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/remember-me', (req, res) => {
    // ok: javascript-same-site-cookie
    res.cookie('rememberMe', 'true', {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: 'lax', // Properly lowercase
      secure: true
    });
    res.redirect('/home');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_12() {
  const cookieValue = encodeURIComponent(JSON.stringify({
    userId: 123,
    role: 'admin'
  }));
  
  // ok: javascript-same-site-cookie
  document.cookie = `userInfo=${cookieValue}; path=/admin; secure; samesite=strict`;
  // Client-side cookie with sensitive info including SameSite
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (authenticateUser(username, password)) {
      const token = generateAuthToken(username);
      // ok: javascript-same-site-cookie
      res.cookie('auth', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict' // Always set SameSite regardless of environment
      });
      res.json({ success: true });
    }
  });
  
  function authenticateUser(u, p) { return true; }
  function generateAuthToken(u) { return 'token'; }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/third-party-auth', (req, res) => {
    // ok: javascript-same-site-cookie
    res.cookie('authRedirect', req.query.redirectUrl, {
      maxAge: 300000,
      sameSite: 'none',
      secure: true // Properly includes secure flag with SameSite=None
    });
    res.redirect(req.query.authProvider);
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.post('/api/set-preferences', (req, res) => {
    const cookieOptions = {
      sameSite: 'lax', // Always set SameSite
      secure: true
    };
    
    if (req.body.rememberMe) {
      cookieOptions.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    }
    
    // ok: javascript-same-site-cookie
    res.cookie('userPrefs', JSON.stringify(req.body.preferences), cookieOptions);
    res.json({ success: true });
  });
}
// {/fact}

module.exports = {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};