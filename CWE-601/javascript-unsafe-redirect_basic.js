// Filename: unsafe_redirect_test_cases.js

// Common imports for HTTP handling in JavaScript
const express = require('express');
const app = express();
const http = require('http');
const https = require('https');
const url = require('url');

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  const express = require('express');
  const app = express();
  
  app.get('/redirect', (req, res) => {
    const redirectUrl = req.query.url;
    // ruleid: javascript-unsafe-redirect
    res.redirect(redirectUrl);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  const express = require('express');
  const app = express();
  
  app.post('/login', (req, res) => {
    // Authentication logic here
    const nextPage = req.body.next;
    // ruleid: javascript-unsafe-redirect
    res.redirect(nextPage);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  const express = require('express');
  const app = express();
  
  app.get('/navigate', (req, res) => {
    const destination = req.query.to;
    // ruleid: javascript-unsafe-redirect
    res.location(destination);
    res.status(302).send();
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  const http = require('http');
  
  http.createServer((req, res) => {
    const parsedUrl = new URL(req.url, 'http://example.com');
    const redirectTarget = parsedUrl.searchParams.get('redirect');
    
    // ruleid: javascript-unsafe-redirect
    res.writeHead(302, { 'Location': redirectTarget });
    res.end();
  }).listen(3000);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  const express = require('express');
  const app = express();
  
  app.get('/external', (req, res) => {
    const referer = req.headers.referer;
    // ruleid: javascript-unsafe-redirect
    res.redirect(referer || '/home');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  const express = require('express');
  const app = express();
  
  app.get('/checkout/complete', (req, res) => {
    let returnUrl = req.cookies.returnUrl;
    // ruleid: javascript-unsafe-redirect
    res.redirect(returnUrl);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  const express = require('express');
  const app = express();
  
  app.get('/auth/callback', (req, res) => {
    const state = JSON.parse(req.query.state);
    // ruleid: javascript-unsafe-redirect
    res.redirect(state.returnTo);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  const fastify = require('fastify')();
  
  fastify.get('/go', (request, reply) => {
    const target = request.query.target;
    // ruleid: javascript-unsafe-redirect
    reply.redirect(target);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  const Koa = require('koa');
  const app = new Koa();
  
  app.use(async ctx => {
    if (ctx.path === '/redirect') {
      const target = ctx.query.to;
      // ruleid: javascript-unsafe-redirect
      ctx.redirect(target);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  const express = require('express');
  const app = express();
  
  app.get('/product/:id', (req, res) => {
    const backUrl = req.query.back;
    if (req.query.action === 'cancel') {
      // ruleid: javascript-unsafe-redirect
      res.redirect(backUrl);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  const express = require('express');
  const router = express.Router();
  
  router.get('/sso', (req, res) => {
    const redirectUrl = req.query.redirectUrl;
    const token = generateToken(); // Assume this function exists
    const finalUrl = redirectUrl + '?token=' + token;
    // ruleid: javascript-unsafe-redirect
    res.redirect(finalUrl);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    if (parsedUrl.pathname === '/redirect') {
      // ruleid: javascript-unsafe-redirect
      res.writeHead(301, { 'Location': parsedUrl.query.url });
      res.end();
    }
  }).listen(8080);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  const express = require('express');
  const app = express();
  
  app.get('/download', (req, res) => {
    const fileUrl = req.query.file;
    const downloadComplete = req.query.complete;
    
    // Process download
    
    if (downloadComplete === 'true') {
      // ruleid: javascript-unsafe-redirect
      res.redirect(req.query.next);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  const express = require('express');
  const app = express();
  
  app.get('/language', (req, res) => {
    const lang = req.query.lang;
    const returnPath = req.query.return;
    
    // Set language preference
    res.cookie('lang', lang);
    
    // ruleid: javascript-unsafe-redirect
    res.redirect(returnPath);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  const express = require('express');
  const app = express();
  
  app.post('/process-form', (req, res) => {
    // Process form data
    const formData = req.body;
    
    // Get the success URL from a hidden form field
    const successUrl = formData.successUrl;
    
    // ruleid: javascript-unsafe-redirect
    res.redirect(successUrl);
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  const express = require('express');
  const app = express();
  
  app.get('/redirect', (req, res) => {
    const redirectUrl = req.query.url;
    // ok: javascript-unsafe-redirect
    if (redirectUrl && redirectUrl.startsWith('/dashboard/')) {
      res.redirect(redirectUrl);
    } else {
      res.redirect('/default');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  const express = require('express');
  const app = express();
  
  const ALLOWED_REDIRECTS = ['/home', '/dashboard', '/profile', '/settings'];
  
  app.post('/login', (req, res) => {
    // Authentication logic here
    const nextPage = req.body.next;
    // ok: javascript-unsafe-redirect
    if (ALLOWED_REDIRECTS.includes(nextPage)) {
      res.redirect(nextPage);
    } else {
      res.redirect('/home');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  const express = require('express');
  const app = express();
  
  app.get('/navigate', (req, res) => {
    // ok: javascript-unsafe-redirect
    const safeDestinations = {
      'home': '/home',
      'profile': '/user/profile',
      'settings': '/user/settings'
    };
    
    const destination = safeDestinations[req.query.to];
    if (destination) {
      res.redirect(destination);
    } else {
      res.redirect('/home');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    // ok: javascript-unsafe-redirect
    const redirectMap = {
      'dashboard': '/dashboard',
      'profile': '/profile',
      'settings': '/settings'
    };
    
    const redirectKey = parsedUrl.query.page;
    const redirectTarget = redirectMap[redirectKey] || '/home';
    
    res.writeHead(302, { 'Location': redirectTarget });
    res.end();
  }).listen(3000);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  const express = require('express');
  const app = express();
  
  app.get('/external', (req, res) => {
    const referer = req.headers.referer;
    // ok: javascript-unsafe-redirect
    const domain = new URL(referer || 'https://example.com').hostname;
    if (domain === 'example.com' || domain === 'subdomain.example.com') {
      res.redirect(referer);
    } else {
      res.redirect('/home');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  const express = require('express');
  const app = express();
  
  app.get('/checkout/complete', (req, res) => {
    let returnUrl = req.cookies.returnUrl;
    // ok: javascript-unsafe-redirect
    if (returnUrl && returnUrl.startsWith('/')) {
      res.redirect(returnUrl);
    } else {
      res.redirect('/checkout/thankyou');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  const express = require('express');
  const app = express();
  
  app.get('/auth/callback', (req, res) => {
    try {
      const state = JSON.parse(req.query.state);
      const returnTo = state.returnTo;
      
      // ok: javascript-unsafe-redirect
      const url = new URL(returnTo, 'https://example.com');
      if (url.hostname === 'example.com') {
        res.redirect(returnTo);
      } else {
        res.redirect('/dashboard');
      }
    } catch (e) {
      res.redirect('/error');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  const express = require('express');
  const app = express();
  
  // ok: javascript-unsafe-redirect
  // Using a fixed redirect URL
  app.get('/go', (req, res) => {
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  const express = require('express');
  const app = express();
  
  // ok: javascript-unsafe-redirect
  // Using a relative path constructed from validated input
  app.get('/product/:id', (req, res) => {
    const id = req.params.id;
    const action = req.query.action;
    
    if (action === 'view' && /^\d+$/.test(id)) {
      res.redirect(`/product/details/${id}`);
    } else {
      res.redirect('/products');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  const express = require('express');
  const app = express();
  
  app.get('/redirect', (req, res) => {
    const targetId = req.query.id;
    
    // ok: javascript-unsafe-redirect
    // Using a URL builder function with validation
    function buildSafeUrl(id) {
      if (/^\d+$/.test(id)) {
        return `/resource/${id}`;
      }
      return '/resources';
    }
    
    res.redirect(buildSafeUrl(targetId));
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  const express = require('express');
  const app = express();
  
  app.get('/sso', (req, res) => {
    const redirectUrl = req.query.redirectUrl;
    
    // ok: javascript-unsafe-redirect
    // Validate against a whitelist of allowed domains
    const allowedDomains = ['example.com', 'sub.example.com', 'partner.com'];
    
    try {
      const urlObj = new URL(redirectUrl);
      if (allowedDomains.includes(urlObj.hostname)) {
        res.redirect(redirectUrl);
      } else {
        res.redirect('/home');
      }
    } catch (e) {
      res.redirect('/error');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  const express = require('express');
  const app = express();
  
  // ok: javascript-unsafe-redirect
  // Using a map of allowed redirect targets
  app.get('/language', (req, res) => {
    const lang = req.query.lang;
    const returnPath = req.query.return;
    
    const allowedPaths = {
      'dashboard': '/dashboard',
      'profile': '/profile',
      'settings': '/settings'
    };
    
    // Set language preference
    res.cookie('lang', lang);
    
    if (allowedPaths[returnPath]) {
      res.redirect(allowedPaths[returnPath]);
    } else {
      res.redirect('/dashboard');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  const express = require('express');
  const app = express();
  
  // ok: javascript-unsafe-redirect
  // Using a URL builder with path validation
  app.post('/process-form', (req, res) => {
    // Process form data
    const formData = req.body;
    
    // Get the success path from a hidden form field
    const successPath = formData.successPath;
    
    if (successPath && successPath.startsWith('/') && !successPath.includes('..')) {
      res.redirect(successPath);
    } else {
      res.redirect('/thank-you');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  const express = require('express');
  const app = express();
  
  // ok: javascript-unsafe-redirect
  // Using a hash-based approach for allowed redirects
  app.get('/goto', (req, res) => {
    const crypto = require('crypto');
    const target = req.query.target;
    const hash = req.query.hash;
    
    const secretKey = 'your-secret-key'; // In production, use a proper secret management
    const expectedHash = crypto.createHmac('sha256', secretKey)
                             .update(target)
                             .digest('hex');
    
    if (hash === expectedHash) {
      res.redirect(target);
    } else {
      res.redirect('/invalid-redirect');
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  const express = require('express');
  const app = express();
  
  // ok: javascript-unsafe-redirect
  // Using path validation with regex
  app.get('/files', (req, res) => {
    const filePath = req.query.path;
    
    // Ensure the path is a valid relative path within allowed directories
    const validPathRegex = /^\/?(docs|images|public)\/[\w\-\.\/]+$/;
    
    if (filePath && validPathRegex.test(filePath)) {
      res.redirect(filePath);
    } else {
      res.redirect('/files/browser');
    }
  });
}
// {/fact}

// Export the app for testing purposes
module.exports = app;