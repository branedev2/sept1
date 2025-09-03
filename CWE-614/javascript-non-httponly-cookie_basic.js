// Various cookie libraries and methods for Node.js and browser environments

// Express.js
const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const app = express();

// Browser environment
function setCookie(name, value, options = {}) {
  let str = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
  
  if (options.path) str += `;path=${options.path}`;
  if (options.domain) str += `;domain=${options.domain}`;
  if (options.maxAge) str += `;max-age=${options.maxAge}`;
  if (options.expires) str += `;expires=${options.expires.toUTCString()}`;
  if (options.secure) str += `;secure`;
  if (options.httpOnly) str += `;httpOnly`;
  if (options.sameSite) str += `;sameSite=${options.sameSite}`;
  
  document.cookie = str;
}

// True Positives (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(cookieParser());
  
  app.get('/login', (req, res) => {
    // ruleid: javascript-non-httponly-cookie
    res.cookie('sessionId', 'abc123', { 
      secure: true,
      maxAge: 3600000
    });
    res.send('Logged in');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/remember-me', (req, res) => {
    // ruleid: javascript-non-httponly-cookie
    res.cookie('rememberMe', 'true', { 
      maxAge: 604800000 // 7 days
    });
    res.send('Preference saved');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  // Browser environment
  function saveUserPreference() {
    // ruleid: javascript-non-httponly-cookie
    document.cookie = "theme=dark; path=/; secure=true";
  }
  saveUserPreference();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.post('/api/auth', (req, res) => {
    const token = generateToken(req.body.username);
    // ruleid: javascript-non-httponly-cookie
    res.cookie('authToken', token, {
      secure: true,
      sameSite: 'strict'
    });
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  // Using js-cookie library
  const Cookies = require('js-cookie');
  
  function storeUserSession(sessionData) {
    // ruleid: javascript-non-httponly-cookie
    Cookies.set('userSession', JSON.stringify(sessionData), { 
      expires: 7,
      secure: true
    });
  }
  
  storeUserSession({ userId: 123, role: 'admin' });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  // Using cookie-parser directly
  const app = express();
  app.use(cookieParser());
  
  app.get('/set-language', (req, res) => {
    const lang = req.query.lang || 'en';
    // ruleid: javascript-non-httponly-cookie
    res.cookie('language', lang, {
      maxAge: 31536000000 // 1 year
    });
    res.redirect('/');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  // Express session with explicit cookie settings
  const app = express();
  
  // ruleid: javascript-non-httponly-cookie
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  // Using cookie with explicit httpOnly: false
  const app = express();
  
  app.get('/track', (req, res) => {
    // ruleid: javascript-non-httponly-cookie
    res.cookie('tracker', generateTrackingId(), {
      httpOnly: false,
      maxAge: 86400000 // 1 day
    });
    res.send('Tracked');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  // Browser environment with setCookie helper
  function trackPageView() {
    // ruleid: javascript-non-httponly-cookie
    setCookie('lastVisited', new Date().toISOString(), {
      path: '/',
      secure: true
    });
  }
  
  trackPageView();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/cart/add', (req, res) => {
    const cart = req.cookies.cart ? JSON.parse(req.cookies.cart) : [];
    cart.push({
      productId: req.body.productId,
      quantity: req.body.quantity
    });
    
    // ruleid: javascript-non-httponly-cookie
    res.cookie('cart', JSON.stringify(cart), {
      maxAge: 604800000 // 7 days
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  // Using cookie-session package
  const cookieSession = require('cookie-session');
  const app = express();
  
  // ruleid: javascript-non-httponly-cookie
  app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  // Direct cookie manipulation in browser
  function setAnalyticsCookie() {
    const visitorId = generateRandomId();
    // ruleid: javascript-non-httponly-cookie
    document.cookie = `visitorId=${visitorId}; path=/; max-age=31536000; secure`;
  }
  
  setAnalyticsCookie();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/oauth/callback', (req, res) => {
    const { code } = req.query;
    const tokenData = exchangeCodeForToken(code);
    
    // ruleid: javascript-non-httponly-cookie
    res.cookie('refreshToken', tokenData.refreshToken, {
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  // Using connect-redis for session store
  const redis = require('redis');
  const connectRedis = require('connect-redis');
  const RedisStore = connectRedis(session);
  const redisClient = redis.createClient();
  
  const app = express();
  
  // ruleid: javascript-non-httponly-cookie
  app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: true,
      maxAge: 86400000
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  // Using cookie with domain and path
  const app = express();
  
  app.get('/subscribe', (req, res) => {
    // ruleid: javascript-non-httponly-cookie
    res.cookie('subscribed', 'true', {
      domain: '.example.com',
      path: '/',
      maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
    });
    
    res.send('Subscribed to newsletter');
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(cookieParser());
  
  app.get('/login', (req, res) => {
    // ok: javascript-non-httponly-cookie
    res.cookie('sessionId', 'abc123', { 
      httpOnly: true,
      secure: true,
      maxAge: 3600000
    });
    res.send('Logged in');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/remember-me', (req, res) => {
    // ok: javascript-non-httponly-cookie
    res.cookie('rememberMe', 'true', { 
      httpOnly: true,
      maxAge: 604800000 // 7 days
    });
    res.send('Preference saved');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  // Using client-side storage instead of cookies for client-accessible data
  function saveUserPreference() {
    // ok: javascript-non-httponly-cookie
    localStorage.setItem('theme', 'dark');
  }
  saveUserPreference();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.post('/api/auth', (req, res) => {
    const token = generateToken(req.body.username);
    // ok: javascript-non-httponly-cookie
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    });
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  // Using js-cookie library for client-side data, but sensitive data in httpOnly cookie
  const Cookies = require('js-cookie');
  const app = express();
  
  app.post('/login', (req, res) => {
    // Store session in httpOnly cookie
    // ok: javascript-non-httponly-cookie
    res.cookie('session', generateSessionId(), {
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    });
    
    // Store UI preferences in client-accessible storage
    res.send(`
      <script>
        localStorage.setItem('uiPrefs', JSON.stringify({
          theme: 'dark',
          fontSize: 'medium'
        }));
      </script>
    `);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  // Using cookie-parser directly with httpOnly
  const app = express();
  app.use(cookieParser());
  
  app.get('/set-language', (req, res) => {
    const lang = req.query.lang || 'en';
    // ok: javascript-non-httponly-cookie
    res.cookie('language', lang, {
      httpOnly: true,
      maxAge: 31536000000 // 1 year
    });
    res.redirect('/');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  // Express session with secure cookie settings
  const app = express();
  
  // ok: javascript-non-httponly-cookie
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { 
      secure: true,
      httpOnly: true
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  // Splitting data between httpOnly and non-httpOnly cookies
  const app = express();
  
  app.get('/user/preferences', (req, res) => {
    // Sensitive data in httpOnly cookie
    // ok: javascript-non-httponly-cookie
    res.cookie('userId', req.user.id, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    });
    
    // UI preferences in localStorage (client-side)
    res.send(`
      <script>
        localStorage.setItem('theme', '${req.user.theme}');
      </script>
    `);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  // Using JWT for authentication with httpOnly cookie
  const jwt = require('jsonwebtoken');
  const app = express();
  
  app.post('/login', (req, res) => {
    const token = jwt.sign({ userId: 123 }, 'secret', { expiresIn: '1h' });
    
    // ok: javascript-non-httponly-cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: true,
      maxAge: 3600000
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/cart/add', (req, res) => {
    const cart = req.cookies.cart ? JSON.parse(req.cookies.cart) : [];
    cart.push({
      productId: req.body.productId,
      quantity: req.body.quantity
    });
    
    // ok: javascript-non-httponly-cookie
    res.cookie('cart', JSON.stringify(cart), {
      httpOnly: true,
      maxAge: 604800000 // 7 days
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  // Using cookie-session package with httpOnly
  const cookieSession = require('cookie-session');
  const app = express();
  
  // ok: javascript-non-httponly-cookie
  app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  // Using sessionStorage for analytics instead of cookies
  function setAnalyticsCookie() {
    const visitorId = generateRandomId();
    // ok: javascript-non-httponly-cookie
    sessionStorage.setItem('visitorId', visitorId);
  }
  
  setAnalyticsCookie();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/oauth/callback', (req, res) => {
    const { code } = req.query;
    const tokenData = exchangeCodeForToken(code);
    
    // ok: javascript-non-httponly-cookie
    res.cookie('refreshToken', tokenData.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  // Using connect-redis for session store with httpOnly
  const redis = require('redis');
  const connectRedis = require('connect-redis');
  const RedisStore = connectRedis(session);
  const redisClient = redis.createClient();
  
  const app = express();
  
  // ok: javascript-non-httponly-cookie
  app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: true,
      httpOnly: true,
      maxAge: 86400000
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  // Using cookie with domain, path and httpOnly
  const app = express();
  
  app.get('/subscribe', (req, res) => {
    // ok: javascript-non-httponly-cookie
    res.cookie('subscribed', 'true', {
      httpOnly: true,
      domain: '.example.com',
      path: '/',
      maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
    });
    
    res.send('Subscribed to newsletter');
  });
}
// {/fact}

// Helper functions (not part of test cases)
function generateToken(username) {
  return 'token_' + username + '_' + Date.now();
}

function generateTrackingId() {
  return 'track_' + Math.random().toString(36).substring(2, 15);
}

function generateRandomId() {
  return Math.random().toString(36).substring(2, 15);
}

function generateSessionId() {
  return 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
}

function exchangeCodeForToken(code) {
  return {
    accessToken: 'access_' + code,
    refreshToken: 'refresh_' + code
  };
}