const express = require('express');
const http = require('http');
const https = require('https');
const axios = require('axios');
const url = require('url');
const validator = require('validator');
const app = express();

// BAD EXAMPLES - Host Header Injection Vulnerabilities

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1() {
  app.get('/redirect', (req, res) => {
    const host = req.headers.host;
    // ruleid: javascript-host-header-injection
    res.redirect(`https://${host}/login`);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2() {
  app.get('/api/proxy', (req, res) => {
    const targetHost = req.headers.host;
    const options = {
      hostname: targetHost,
      path: '/api/data',
      method: 'GET'
    };
    
    // ruleid: javascript-host-header-injection
    const request = http.request(options, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.send(data);
      });
    });
    
    request.end();
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3() {
  app.get('/reset-password', (req, res) => {
    const host = req.headers.host;
    const token = generateToken();
    const resetLink = `https://${host}/reset?token=${token}`;
    
    // ruleid: javascript-host-header-injection
    sendEmail(user.email, 'Password Reset', `Click here to reset your password: ${resetLink}`);
    
    res.send('Password reset email sent');
  });
  
  function generateToken() {
    return Math.random().toString(36).substring(2, 15);
  }
  
  function sendEmail(to, subject, body) {
    // Email sending logic
    console.log(`Sending email to ${to}: ${body}`);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4() {
  app.get('/webhook-config', (req, res) => {
    const host = req.headers.host;
    const userId = req.query.userId;
    
    // ruleid: javascript-host-header-injection
    const webhookUrl = `https://${host}/api/webhook/${userId}`;
    
    saveWebhookConfig(userId, webhookUrl);
    res.send('Webhook configured');
  });
  
  function saveWebhookConfig(userId, url) {
    // Save webhook URL to database
    console.log(`Saving webhook URL for user ${userId}: ${url}`);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5() {
  app.get('/load-script', (req, res) => {
    const host = req.headers.host;
    
    // ruleid: javascript-host-header-injection
    res.send(`<script src="https://${host}/assets/main.js"></script>`);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6() {
  app.get('/api/fetch-data', async (req, res) => {
    try {
      const host = req.headers.host;
      // ruleid: javascript-host-header-injection
      const response = await axios.get(`https://${host}/api/data`);
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Error fetching data');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7() {
  app.get('/generate-sitemap', (req, res) => {
    const host = req.headers.host;
    let sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n';
    sitemap += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    
    const pages = ['/', '/about', '/contact', '/products'];
    
    for (const page of pages) {
      // ruleid: javascript-host-header-injection
      sitemap += `  <url><loc>https://${host}${page}</loc></url>\n`;
    }
    
    sitemap += '</urlset>';
    res.header('Content-Type', 'application/xml');
    res.send(sitemap);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8() {
  app.get('/api/forward', (req, res) => {
    const host = req.headers.host;
    const path = req.query.path || '/default';
    
    // ruleid: javascript-host-header-injection
    https.get(`https://${host}${path}`, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.send(data);
      });
    }).on('error', (err) => {
      res.status(500).send('Error forwarding request');
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9() {
  app.get('/set-cookie', (req, res) => {
    const host = req.headers.host;
    // ruleid: javascript-host-header-injection
    res.cookie('session', 'value', { 
      domain: host.split(':')[0], // Extract domain without port
      secure: true,
      httpOnly: true
    });
    res.send('Cookie set');
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10() {
  app.get('/api/cors-proxy', (req, res) => {
    const targetUrl = req.query.url;
    const host = req.headers.host;
    
    // Set CORS headers
    res.header('Access-Control-Allow-Origin', '*');
    
    // ruleid: javascript-host-header-injection
    const proxyUrl = `https://${host}/proxy?target=${encodeURIComponent(targetUrl)}`;
    
    https.get(proxyUrl, (response) => {
      response.pipe(res);
    }).on('error', (err) => {
      res.status(500).send('Error proxying request');
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11() {
  app.get('/oauth/callback', (req, res) => {
    const host = req.headers.host;
    const code = req.query.code;
    
    // ruleid: javascript-host-header-injection
    const redirectUri = `https://${host}/oauth/callback`;
    
    // Exchange code for token
    exchangeCodeForToken(code, redirectUri)
      .then(token => {
        res.redirect('/dashboard');
      })
      .catch(err => {
        res.status(500).send('Authentication failed');
      });
  });
  
  function exchangeCodeForToken(code, redirectUri) {
    // OAuth token exchange logic
    return Promise.resolve('token');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12() {
  app.get('/api/websocket-config', (req, res) => {
    const host = req.headers.host;
    
    // ruleid: javascript-host-header-injection
    const config = {
      wsUrl: `wss://${host}/ws`,
      authToken: 'some-token',
      timeout: 30000
    };
    
    res.json(config);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13() {
  app.get('/cdn-url', (req, res) => {
    const host = req.headers.host;
    const file = req.query.file || 'default.js';
    
    // ruleid: javascript-host-header-injection
    const cdnUrl = `https://cdn.${host}/assets/${file}`;
    
    res.json({ url: cdnUrl });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14() {
  app.post('/api/webhook-register', (req, res) => {
    const host = req.headers.host;
    const event = req.body.event;
    
    // ruleid: javascript-host-header-injection
    registerWebhook(event, `https://${host}/api/events/${event}`);
    
    res.send('Webhook registered');
  });
  
  function registerWebhook(event, url) {
    // Register webhook logic
    console.log(`Registered webhook for ${event} at ${url}`);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15() {
  app.get('/api/health-check', (req, res) => {
    const services = ['api', 'auth', 'database'];
    const host = req.headers.host;
    const results = {};
    
    for (const service of services) {
      try {
        // ruleid: javascript-host-header-injection
        const serviceUrl = `https://${host}/internal/${service}/health`;
        // Check service health
        results[service] = 'healthy';
      } catch (error) {
        results[service] = 'unhealthy';
      }
    }
    
    res.json(results);
  });
}
// {/fact}

// GOOD EXAMPLES - Secure Implementations

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1() {
  const ALLOWED_HOSTS = ['example.com', 'api.example.com'];
  
  app.get('/redirect', (req, res) => {
    const host = req.headers.host;
    
    // ok: javascript-host-header-injection
    if (ALLOWED_HOSTS.includes(host)) {
      res.redirect(`https://${host}/login`);
    } else {
      res.redirect('https://example.com/login');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2() {
  app.get('/api/proxy', (req, res) => {
    // ok: javascript-host-header-injection
    const targetHost = 'api.internal.example.com'; // Hardcoded trusted host
    
    const options = {
      hostname: targetHost,
      path: '/api/data',
      method: 'GET'
    };
    
    const request = http.request(options, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.send(data);
      });
    });
    
    request.end();
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3() {
  const APP_DOMAIN = process.env.APP_DOMAIN || 'example.com';
  
  app.get('/reset-password', (req, res) => {
    const token = generateToken();
    
    // ok: javascript-host-header-injection
    const resetLink = `https://${APP_DOMAIN}/reset?token=${token}`;
    
    sendEmail(user.email, 'Password Reset', `Click here to reset your password: ${resetLink}`);
    
    res.send('Password reset email sent');
  });
  
  function generateToken() {
    return Math.random().toString(36).substring(2, 15);
  }
  
  function sendEmail(to, subject, body) {
    // Email sending logic
    console.log(`Sending email to ${to}: ${body}`);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4() {
  const CONFIG = {
    webhookDomain: 'webhooks.example.com'
  };
  
  app.get('/webhook-config', (req, res) => {
    const userId = req.query.userId;
    
    // ok: javascript-host-header-injection
    const webhookUrl = `https://${CONFIG.webhookDomain}/api/webhook/${userId}`;
    
    saveWebhookConfig(userId, webhookUrl);
    res.send('Webhook configured');
  });
  
  function saveWebhookConfig(userId, url) {
    // Save webhook URL to database
    console.log(`Saving webhook URL for user ${userId}: ${url}`);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5() {
  const ASSET_DOMAIN = 'assets.example.com';
  
  app.get('/load-script', (req, res) => {
    // ok: javascript-host-header-injection
    res.send(`<script src="https://${ASSET_DOMAIN}/assets/main.js"></script>`);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6() {
  const API_HOST = process.env.API_HOST || 'api.example.com';
  
  app.get('/api/fetch-data', async (req, res) => {
    try {
      // ok: javascript-host-header-injection
      const response = await axios.get(`https://${API_HOST}/api/data`);
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Error fetching data');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7() {
  const SITE_DOMAIN = 'example.com';
  
  app.get('/generate-sitemap', (req, res) => {
    let sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n';
    sitemap += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    
    const pages = ['/', '/about', '/contact', '/products'];
    
    for (const page of pages) {
      // ok: javascript-host-header-injection
      sitemap += `  <url><loc>https://${SITE_DOMAIN}${page}</loc></url>\n`;
    }
    
    sitemap += '</urlset>';
    res.header('Content-Type', 'application/xml');
    res.send(sitemap);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8() {
  const INTERNAL_API = 'internal-api.example.com';
  
  app.get('/api/forward', (req, res) => {
    const path = req.query.path || '/default';
    
    // ok: javascript-host-header-injection
    https.get(`https://${INTERNAL_API}${path}`, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.send(data);
      });
    }).on('error', (err) => {
      res.status(500).send('Error forwarding request');
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9() {
  const COOKIE_DOMAIN = '.example.com';
  
  app.get('/set-cookie', (req, res) => {
    // ok: javascript-host-header-injection
    res.cookie('session', 'value', { 
      domain: COOKIE_DOMAIN,
      secure: true,
      httpOnly: true
    });
    res.send('Cookie set');
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10() {
  const PROXY_HOST = 'proxy.example.com';
  
  app.get('/api/cors-proxy', (req, res) => {
    const targetUrl = req.query.url;
    
    // Set CORS headers
    res.header('Access-Control-Allow-Origin', '*');
    
    // ok: javascript-host-header-injection
    const proxyUrl = `https://${PROXY_HOST}/proxy?target=${encodeURIComponent(targetUrl)}`;
    
    https.get(proxyUrl, (response) => {
      response.pipe(res);
    }).on('error', (err) => {
      res.status(500).send('Error proxying request');
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11() {
  const OAUTH_REDIRECT_HOST = 'auth.example.com';
  
  app.get('/oauth/callback', (req, res) => {
    const code = req.query.code;
    
    // ok: javascript-host-header-injection
    const redirectUri = `https://${OAUTH_REDIRECT_HOST}/oauth/callback`;
    
    // Exchange code for token
    exchangeCodeForToken(code, redirectUri)
      .then(token => {
        res.redirect('/dashboard');
      })
      .catch(err => {
        res.status(500).send('Authentication failed');
      });
  });
  
  function exchangeCodeForToken(code, redirectUri) {
    // OAuth token exchange logic
    return Promise.resolve('token');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12() {
  const WS_HOST = process.env.WS_HOST || 'ws.example.com';
  
  app.get('/api/websocket-config', (req, res) => {
    // ok: javascript-host-header-injection
    const config = {
      wsUrl: `wss://${WS_HOST}/ws`,
      authToken: 'some-token',
      timeout: 30000
    };
    
    res.json(config);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13() {
  const CDN_HOST = 'cdn.example.com';
  
  app.get('/cdn-url', (req, res) => {
    const file = req.query.file || 'default.js';
    const sanitizedFile = file.replace(/[^a-zA-Z0-9._-]/g, '');
    
    // ok: javascript-host-header-injection
    const cdnUrl = `https://${CDN_HOST}/assets/${sanitizedFile}`;
    
    res.json({ url: cdnUrl });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14() {
  const WEBHOOK_HOST = 'events.example.com';
  
  app.post('/api/webhook-register', (req, res) => {
    const event = req.body.event;
    
    // ok: javascript-host-header-injection
    registerWebhook(event, `https://${WEBHOOK_HOST}/api/events/${event}`);
    
    res.send('Webhook registered');
  });
  
  function registerWebhook(event, url) {
    // Register webhook logic
    console.log(`Registered webhook for ${event} at ${url}`);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15() {
  const SERVICES = {
    api: 'api.internal.example.com',
    auth: 'auth.internal.example.com',
    database: 'db.internal.example.com'
  };
  
  app.get('/api/health-check', (req, res) => {
    const results = {};
    
    for (const [service, host] of Object.entries(SERVICES)) {
      try {
        // ok: javascript-host-header-injection
        const serviceUrl = `https://${host}/health`;
        // Check service health
        results[service] = 'healthy';
      } catch (error) {
        results[service] = 'unhealthy';
      }
    }
    
    res.json(results);
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});