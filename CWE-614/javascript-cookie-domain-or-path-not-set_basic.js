// Imports for Express.js examples
const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());

// Imports for browser-side examples
// No imports needed for standard browser APIs

// True Positives (Vulnerable Code)

// Bad Case 1: Setting a cookie without domain or path in Express.js
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1(req, res) {
  // ruleid: javascript-cookie-domain-or-path-not-set
  res.cookie('sessionId', 'abc123', { 
    secure: true,
    httpOnly: true 
  });
  
  res.send('Cookie has been set');
}
// {/fact}

// Bad Case 2: Setting a cookie with document.cookie without domain or path
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const userToken = generateToken();
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  document.cookie = `userToken=${userToken}; secure; httpOnly`;
  
  console.log('User token cookie has been set');
}
// {/fact}

// Bad Case 3: Setting multiple cookies without domain or path
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3(req, res) {
  const userId = getUserId();
  const authToken = generateAuthToken();
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  res.cookie('userId', userId, { 
    maxAge: 900000,
    httpOnly: true 
  });
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  res.cookie('authToken', authToken, { 
    secure: true,
    sameSite: 'strict' 
  });
  
  res.json({ status: 'success' });
}
// {/fact}

// Bad Case 4: Setting a cookie with js-cookie library without domain or path
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const Cookies = require('js-cookie');
  const userPreferences = JSON.stringify({ theme: 'dark', fontSize: 'large' });
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  Cookies.set('preferences', userPreferences, { 
    expires: 7,
    secure: true 
  });
  
  updateUserInterface();
}
// {/fact}

// Bad Case 5: Setting a cookie in a conditional block without domain or path
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5(req, res) {
  const isAuthenticated = checkAuthentication(req);
  
  if (isAuthenticated) {
    const sessionData = generateSessionData(req.user);
    
    // ruleid: javascript-cookie-domain-or-path-not-set
    res.cookie('sessionData', sessionData, { 
      maxAge: 3600000,
      httpOnly: true,
      secure: true 
    });
    
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
}
// {/fact}

// Bad Case 6: Setting a cookie with dynamic name but no domain or path
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6(req, res) {
  const cookieName = `user_${req.params.id}_preferences`;
  const preferences = getUserPreferences(req.params.id);
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  res.cookie(cookieName, JSON.stringify(preferences), { 
    maxAge: 86400000,
    secure: process.env.NODE_ENV === 'production' 
  });
  
  res.send('Preferences saved');
}
// {/fact}

// Bad Case 7: Setting a cookie with document.cookie using template literals
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const username = getCurrentUsername();
  const expireDate = new Date(Date.now() + 86400000).toUTCString();
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  document.cookie = `username=${username}; expires=${expireDate}; secure`;
  
  updateWelcomeMessage(username);
}
// {/fact}

// Bad Case 8: Setting a cookie with options from a variable
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8(req, res) {
  const cookieOptions = {
    maxAge: 3600000,
    httpOnly: true,
    secure: true,
    sameSite: 'lax'
  };
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  res.cookie('analyticsId', generateAnalyticsId(), cookieOptions);
  
  res.status(200).json({ success: true });
}
// {/fact}

// Bad Case 9: Setting a cookie in an async function without domain or path
// {fact rule=insecure-cookie@v1.0 defects=1}
async function bad_case_9(req, res) {
  try {
    const userData = await fetchUserData(req.params.userId);
    
    // ruleid: javascript-cookie-domain-or-path-not-set
    res.cookie('userData', JSON.stringify(userData), {
      maxAge: 7200000,
      httpOnly: true,
      secure: true
    });
    
    res.render('profile', { user: userData });
  } catch (error) {
    res.status(500).send('Error fetching user data');
  }
}
// {/fact}

// Bad Case 10: Setting a cookie with a callback function
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10(req, res) {
  authenticateUser(req.body.username, req.body.password, (err, token) => {
    if (err) {
      return res.status(401).send('Authentication failed');
    }
    
    // ruleid: javascript-cookie-domain-or-path-not-set
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    });
    
    res.redirect('/welcome');
  });
}
// {/fact}

// Bad Case 11: Setting a cookie with third-party library (cookie package)
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11(req, res) {
  const cookie = require('cookie');
  const serialized = cookie.serialize('rememberMe', 'true', {
    httpOnly: true,
    maxAge: 604800 // 1 week
    // No domain or path
  });
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  res.setHeader('Set-Cookie', serialized);
  
  res.send('Remember me preference saved');
}
// {/fact}

// Bad Case 12: Setting a cookie in response to an AJAX request
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  document.getElementById('savePreferences').addEventListener('click', function() {
    const preferences = collectPreferences();
    
    fetch('/api/save-preferences', {
      method: 'POST',
      body: JSON.stringify(preferences),
      headers: {
        'Content-Type': 'application/json'
      }
    }).then(response => {
      if (response.ok) {
        // ruleid: javascript-cookie-domain-or-path-not-set
        document.cookie = `preferences=${JSON.stringify(preferences)}; secure; samesite=strict`;
        showSuccessMessage();
      }
    });
  });
}
// {/fact}

// Bad Case 13: Setting a cookie with express-session without domain or path
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  const express = require('express');
  const session = require('express-session');
  const app = express();
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { 
      secure: true,
      httpOnly: true
      // No domain or path
    }
  }));
  
  app.listen(3000);
}
// {/fact}

// Bad Case 14: Setting a cookie with specific options but missing domain and path
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14(req, res) {
  const userRole = determineUserRole(req.user);
  
  // ruleid: javascript-cookie-domain-or-path-not-set
  res.cookie('userRole', userRole, {
    maxAge: 3600000,
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    signed: true
    // Missing domain and path
  });
  
  res.redirect('/dashboard');
}
// {/fact}

// Bad Case 15: Setting a cookie in a loop without domain or path
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15(req, res) {
  const userPreferences = getUserPreferences(req.user.id);
  
  Object.entries(userPreferences).forEach(([key, value]) => {
    // ruleid: javascript-cookie-domain-or-path-not-set
    res.cookie(`pref_${key}`, value, {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: false,
      secure: true
    });
  });
  
  res.send('All preferences have been saved');
}
// {/fact}

// True Negatives (Secure Code)

// Good Case 1: Setting a cookie with domain and path in Express.js
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1(req, res) {
  // ok: javascript-cookie-domain-or-path-not-set
  res.cookie('sessionId', 'abc123', { 
    secure: true,
    httpOnly: true,
    domain: 'example.com',
    path: '/app'
  });
  
  res.send('Cookie has been set securely');
}
// {/fact}

// Good Case 2: Setting a cookie with document.cookie with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const userToken = generateToken();
  
  // ok: javascript-cookie-domain-or-path-not-set
  document.cookie = `userToken=${userToken}; secure; httpOnly; domain=example.com; path=/account`;
  
  console.log('User token cookie has been set securely');
}
// {/fact}

// Good Case 3: Setting multiple cookies with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3(req, res) {
  const userId = getUserId();
  const authToken = generateAuthToken();
  
  // ok: javascript-cookie-domain-or-path-not-set
  res.cookie('userId', userId, { 
    maxAge: 900000,
    httpOnly: true,
    domain: 'example.com',
    path: '/user'
  });
  
  // ok: javascript-cookie-domain-or-path-not-set
  res.cookie('authToken', authToken, { 
    secure: true,
    sameSite: 'strict',
    domain: 'api.example.com',
    path: '/auth'
  });
  
  res.json({ status: 'success' });
}
// {/fact}

// Good Case 4: Setting a cookie with js-cookie library with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const Cookies = require('js-cookie');
  const userPreferences = JSON.stringify({ theme: 'dark', fontSize: 'large' });
  
  // ok: javascript-cookie-domain-or-path-not-set
  Cookies.set('preferences', userPreferences, { 
    expires: 7,
    secure: true,
    domain: 'example.com',
    path: '/settings'
  });
  
  updateUserInterface();
}
// {/fact}

// Good Case 5: Setting a cookie in a conditional block with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5(req, res) {
  const isAuthenticated = checkAuthentication(req);
  
  if (isAuthenticated) {
    const sessionData = generateSessionData(req.user);
    
    // ok: javascript-cookie-domain-or-path-not-set
    res.cookie('sessionData', sessionData, { 
      maxAge: 3600000,
      httpOnly: true,
      secure: true,
      domain: 'secure.example.com',
      path: '/dashboard'
    });
    
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
}
// {/fact}

// Good Case 6: Setting a cookie with dynamic name with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6(req, res) {
  const cookieName = `user_${req.params.id}_preferences`;
  const preferences = getUserPreferences(req.params.id);
  
  // ok: javascript-cookie-domain-or-path-not-set
  res.cookie(cookieName, JSON.stringify(preferences), { 
    maxAge: 86400000,
    secure: process.env.NODE_ENV === 'production',
    domain: 'app.example.com',
    path: `/users/${req.params.id}`
  });
  
  res.send('Preferences saved');
}
// {/fact}

// Good Case 7: Setting a cookie with document.cookie using template literals with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const username = getCurrentUsername();
  const expireDate = new Date(Date.now() + 86400000).toUTCString();
  
  // ok: javascript-cookie-domain-or-path-not-set
  document.cookie = `username=${username}; expires=${expireDate}; secure; domain=example.org; path=/profile`;
  
  updateWelcomeMessage(username);
}
// {/fact}

// Good Case 8: Setting a cookie with options from a variable including domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8(req, res) {
  const cookieOptions = {
    maxAge: 3600000,
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    domain: 'analytics.example.com',
    path: '/tracking'
  };
  
  // ok: javascript-cookie-domain-or-path-not-set
  res.cookie('analyticsId', generateAnalyticsId(), cookieOptions);
  
  res.status(200).json({ success: true });
}
// {/fact}

// Good Case 9: Setting a cookie in an async function with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
async function good_case_9(req, res) {
  try {
    const userData = await fetchUserData(req.params.userId);
    
    // ok: javascript-cookie-domain-or-path-not-set
    res.cookie('userData', JSON.stringify(userData), {
      maxAge: 7200000,
      httpOnly: true,
      secure: true,
      domain: 'api.example.com',
      path: `/users/${req.params.userId}`
    });
    
    res.render('profile', { user: userData });
  } catch (error) {
    res.status(500).send('Error fetching user data');
  }
}
// {/fact}

// Good Case 10: Setting a cookie with a callback function with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10(req, res) {
  authenticateUser(req.body.username, req.body.password, (err, token) => {
    if (err) {
      return res.status(401).send('Authentication failed');
    }
    
    // ok: javascript-cookie-domain-or-path-not-set
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      domain: 'auth.example.com',
      path: '/session'
    });
    
    res.redirect('/welcome');
  });
}
// {/fact}

// Good Case 11: Setting a cookie with third-party library (cookie package) with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11(req, res) {
  const cookie = require('cookie');
  const serialized = cookie.serialize('rememberMe', 'true', {
    httpOnly: true,
    maxAge: 604800, // 1 week
    domain: 'example.com',
    path: '/account'
  });
  
  // ok: javascript-cookie-domain-or-path-not-set
  res.setHeader('Set-Cookie', serialized);
  
  res.send('Remember me preference saved');
}
// {/fact}

// Good Case 12: Setting a cookie in response to an AJAX request with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  document.getElementById('savePreferences').addEventListener('click', function() {
    const preferences = collectPreferences();
    
    fetch('/api/save-preferences', {
      method: 'POST',
      body: JSON.stringify(preferences),
      headers: {
        'Content-Type': 'application/json'
      }
    }).then(response => {
      if (response.ok) {
        // ok: javascript-cookie-domain-or-path-not-set
        document.cookie = `preferences=${JSON.stringify(preferences)}; secure; samesite=strict; domain=app.example.com; path=/settings`;
        showSuccessMessage();
      }
    });
  });
}
// {/fact}

// Good Case 13: Setting a cookie with express-session with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const express = require('express');
  const session = require('express-session');
  const app = express();
  
  // ok: javascript-cookie-domain-or-path-not-set
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { 
      secure: true,
      httpOnly: true,
      domain: 'session.example.com',
      path: '/app'
    }
  }));
  
  app.listen(3000);
}
// {/fact}

// Good Case 14: Setting a cookie with specific options including domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14(req, res) {
  const userRole = determineUserRole(req.user);
  
  // ok: javascript-cookie-domain-or-path-not-set
  res.cookie('userRole', userRole, {
    maxAge: 3600000,
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    signed: true,
    domain: 'roles.example.com',
    path: '/permissions'
  });
  
  res.redirect('/dashboard');
}
// {/fact}

// Good Case 15: Setting a cookie in a loop with domain and path
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15(req, res) {
  const userPreferences = getUserPreferences(req.user.id);
  
  Object.entries(userPreferences).forEach(([key, value]) => {
    // ok: javascript-cookie-domain-or-path-not-set
    res.cookie(`pref_${key}`, value, {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: false,
      secure: true,
      domain: 'preferences.example.com',
      path: `/user/${req.user.id}/preferences`
    });
  });
  
  res.send('All preferences have been saved');
}
// {/fact}

// Helper functions (not part of the test cases)
function generateToken() { return 'generated-token'; }
function getUserId() { return '12345'; }
function generateAuthToken() { return 'auth-token-xyz'; }
function updateUserInterface() {}
function checkAuthentication() { return true; }
function generateSessionData() { return 'session-data'; }
function getUserPreferences() { return { theme: 'dark' }; }
function getCurrentUsername() { return 'user123'; }
function generateAnalyticsId() { return 'analytics-id'; }
function determineUserRole() { return 'admin'; }
function fetchUserData() { return Promise.resolve({ name: 'John' }); }
function authenticateUser(username, password, callback) { callback(null, 'token'); }
function updateWelcomeMessage() {}
function collectPreferences() { return { notifications: true }; }
function showSuccessMessage() {}