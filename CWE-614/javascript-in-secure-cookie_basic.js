// Import necessary modules for examples
const express = require('express');
const http = require('http');
const https = require('https');
const cookieParser = require('cookie-parser');

// True Positive Examples (Insecure Cookie Settings)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.get('/login', (req, res) => {
    // ruleid: javascript-in-secure-cookie
    res.cookie('sessionId', 'abc123', { httpOnly: true });
    res.send('Logged in');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  app.post('/auth', (req, res) => {
    // ruleid: javascript-in-secure-cookie
    res.cookie('authToken', 'xyz789', { maxAge: 900000 });
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  app.get('/remember-me', (req, res) => {
    // ruleid: javascript-in-secure-cookie
    res.cookie('rememberMe', 'true', { expires: new Date(Date.now() + 86400000) });
    res.send('Preference saved');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  app.use(cookieParser());
  app.post('/set-preferences', (req, res) => {
    const theme = req.body.theme || 'light';
    // ruleid: javascript-in-secure-cookie
    res.cookie('userTheme', theme, { path: '/' });
    res.send('Theme updated');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  app.get('/api/set-language', (req, res) => {
    const lang = req.query.lang || 'en';
    // ruleid: javascript-in-secure-cookie
    res.cookie('language', lang, { sameSite: 'lax' });
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  const http = require('http');
  const server = http.createServer((req, res) => {
    // ruleid: javascript-in-secure-cookie
    res.setHeader('Set-Cookie', 'sessionId=abc123; HttpOnly');
    res.end('Cookie set');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  app.get('/store-cart', (req, res) => {
    const cartId = generateCartId();
    // ruleid: javascript-in-secure-cookie
    res.cookie('cartId', cartId, { httpOnly: true, maxAge: 3600000 });
    res.send('Cart created');
  });
  
  function generateCartId() {
    return Math.random().toString(36).substring(2, 15);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Authentication logic here
    const userId = authenticateUser(username, password);
    if (userId) {
      // ruleid: javascript-in-secure-cookie
      res.cookie('userId', userId, { httpOnly: true, sameSite: 'strict' });
      res.redirect('/dashboard');
    } else {
      res.status(401).send('Authentication failed');
    }
  });
  
  function authenticateUser(username, password) {
    // Simplified authentication
    return username === 'admin' && password === 'password' ? '12345' : null;
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  app.get('/api/tracking', (req, res) => {
    const trackingId = req.query.tid || generateTrackingId();
    // ruleid: javascript-in-secure-cookie
    res.cookie('tracking', trackingId, { 
      maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
    });
    res.json({ success: true });
  });
  
  function generateTrackingId() {
    return 'track-' + Date.now();
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  app.use((req, res, next) => {
    if (!req.cookies.visitorId) {
      // ruleid: javascript-in-secure-cookie
      res.cookie('visitorId', generateVisitorId(), { 
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });
    }
    next();
  });
  
  function generateVisitorId() {
    return 'v-' + Math.random().toString(36).substring(2, 10);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const cookieOptions = { 
    httpOnly: true,
    maxAge: 7200000 // 2 hours
  };
  
  app.post('/api/login', (req, res) => {
    // ruleid: javascript-in-secure-cookie
    res.cookie('sessionToken', generateToken(), cookieOptions);
    res.json({ success: true });
  });
  
  function generateToken() {
    return 'token-' + Date.now();
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  app.get('/set-region', (req, res) => {
    const region = req.query.region || 'us';
    // ruleid: javascript-in-secure-cookie
    document.cookie = `userRegion=${region}; path=/; max-age=31536000`;
    res.send('Region set to ' + region);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  function setUserPreferences(theme, fontSize) {
    // ruleid: javascript-in-secure-cookie
    document.cookie = `theme=${theme}; path=/; max-age=31536000`;
    document.cookie = `fontSize=${fontSize}; path=/; max-age=31536000`;
    return true;
  }
  
  setUserPreferences('dark', 'large');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  app.post('/api/subscribe', (req, res) => {
    const email = req.body.email;
    if (validateEmail(email)) {
      // ruleid: javascript-in-secure-cookie
      res.cookie('subscriberEmail', email, { 
        httpOnly: false, // Allow JavaScript access
        maxAge: 90 * 24 * 60 * 60 * 1000 // 90 days
      });
      res.json({ subscribed: true });
    } else {
      res.status(400).json({ error: 'Invalid email' });
    }
  });
  
  function validateEmail(email) {
    return /\S+@\S+\.\S+/.test(email);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  window.onload = function() {
    const consentGiven = checkUserConsent();
    if (consentGiven) {
      // ruleid: javascript-in-secure-cookie
      document.cookie = "cookieConsent=true; path=/; max-age=31536000";
      initializeAnalytics();
    }
  };
  
  function checkUserConsent() {
    return localStorage.getItem('userConsented') === 'true';
  }
  
  function initializeAnalytics() {
    console.log('Analytics initialized');
  }
}
// {/fact}

// True Negative Examples (Secure Cookie Settings)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.get('/login', (req, res) => {
    // ok: javascript-in-secure-cookie
    res.cookie('sessionId', 'abc123', { httpOnly: true, secure: true });
    res.send('Logged in');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const app = express();
  app.post('/auth', (req, res) => {
    // ok: javascript-in-secure-cookie
    res.cookie('authToken', 'xyz789', { maxAge: 900000, secure: true });
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  const app = express();
  app.get('/remember-me', (req, res) => {
    // ok: javascript-in-secure-cookie
    res.cookie('rememberMe', 'true', { 
      expires: new Date(Date.now() + 86400000),
      secure: true
    });
    res.send('Preference saved');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const app = express();
  app.use(cookieParser());
  app.post('/set-preferences', (req, res) => {
    const theme = req.body.theme || 'light';
    // ok: javascript-in-secure-cookie
    res.cookie('userTheme', theme, { path: '/', secure: true });
    res.send('Theme updated');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const app = express();
  app.get('/api/set-language', (req, res) => {
    const lang = req.query.lang || 'en';
    // ok: javascript-in-secure-cookie
    res.cookie('language', lang, { sameSite: 'lax', secure: true });
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  const https = require('https');
  const fs = require('fs');
  
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
  };
  
  const server = https.createServer(options, (req, res) => {
    // ok: javascript-in-secure-cookie
    res.setHeader('Set-Cookie', 'sessionId=abc123; HttpOnly; Secure');
    res.end('Cookie set');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const app = express();
  app.get('/store-cart', (req, res) => {
    const cartId = generateCartId();
    // ok: javascript-in-secure-cookie
    res.cookie('cartId', cartId, { 
      httpOnly: true, 
      maxAge: 3600000,
      secure: true,
      sameSite: 'strict'
    });
    res.send('Cart created');
  });
  
  function generateCartId() {
    return Math.random().toString(36).substring(2, 15);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // Define secure cookie options
  const secureCookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  };
  
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Authentication logic here
    const userId = authenticateUser(username, password);
    if (userId) {
      // ok: javascript-in-secure-cookie
      res.cookie('userId', userId, secureCookieOptions);
      res.redirect('/dashboard');
    } else {
      res.status(401).send('Authentication failed');
    }
  });
  
  function authenticateUser(username, password) {
    // Simplified authentication
    return username === 'admin' && password === 'password' ? '12345' : null;
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // Environment-based cookie settings
  const isProduction = process.env.NODE_ENV === 'production';
  
  app.get('/api/tracking', (req, res) => {
    const trackingId = req.query.tid || generateTrackingId();
    // ok: javascript-in-secure-cookie
    res.cookie('tracking', trackingId, { 
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
      secure: true // Always use secure in any environment
    });
    res.json({ success: true });
  });
  
  function generateTrackingId() {
    return 'track-' + Date.now();
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const app = express();
  app.use((req, res, next) => {
    if (!req.cookies.visitorId) {
      // ok: javascript-in-secure-cookie
      res.cookie('visitorId', generateVisitorId(), { 
        httpOnly: true,
        secure: true,
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });
    }
    next();
  });
  
  function generateVisitorId() {
    return 'v-' + Math.random().toString(36).substring(2, 10);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const cookieOptions = { 
    httpOnly: true,
    secure: true,
    maxAge: 7200000 // 2 hours
  };
  
  app.post('/api/login', (req, res) => {
    // ok: javascript-in-secure-cookie
    res.cookie('sessionToken', generateToken(), cookieOptions);
    res.json({ success: true });
  });
  
  function generateToken() {
    return 'token-' + Date.now();
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const app = express();
  app.get('/set-region', (req, res) => {
    const region = req.query.region || 'us';
    // ok: javascript-in-secure-cookie
    document.cookie = `userRegion=${region}; path=/; max-age=31536000; secure`;
    res.send('Region set to ' + region);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  function setUserPreferences(theme, fontSize) {
    // ok: javascript-in-secure-cookie
    document.cookie = `theme=${theme}; path=/; max-age=31536000; secure`;
    document.cookie = `fontSize=${fontSize}; path=/; max-age=31536000; secure`;
    return true;
  }
  
  setUserPreferences('dark', 'large');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  const app = express();
  app.post('/api/subscribe', (req, res) => {
    const email = req.body.email;
    if (validateEmail(email)) {
      // ok: javascript-in-secure-cookie
      res.cookie('subscriberEmail', email, { 
        httpOnly: false, // Allow JavaScript access
        secure: true,
        sameSite: 'strict',
        maxAge: 90 * 24 * 60 * 60 * 1000 // 90 days
      });
      res.json({ subscribed: true });
    } else {
      res.status(400).json({ error: 'Invalid email' });
    }
  });
  
  function validateEmail(email) {
    return /\S+@\S+\.\S+/.test(email);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  window.onload = function() {
    const consentGiven = checkUserConsent();
    if (consentGiven) {
      // ok: javascript-in-secure-cookie
      document.cookie = "cookieConsent=true; path=/; max-age=31536000; secure";
      initializeAnalytics();
    }
  };
  
  function checkUserConsent() {
    return localStorage.getItem('userConsented') === 'true';
  }
  
  function initializeAnalytics() {
    console.log('Analytics initialized');
  }
}
// {/fact}