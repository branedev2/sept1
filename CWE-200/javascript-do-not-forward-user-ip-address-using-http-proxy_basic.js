const http = require('http');
const https = require('https');
const express = require('express');
const axios = require('axios');
const request = require('request');
const superagent = require('superagent');
const fetch = require('node-fetch');
const got = require('got');
const httpProxy = require('http-proxy');

// True Positives (Vulnerable Code)

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const clientIp = req.ip || req.connection.remoteAddress;
    
    // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
    axios.get('https://api.example.com/data', {
      headers: {
        'X-Forwarded-For': clientIp,
        'User-Agent': req.headers['user-agent']
      }
    }).then(response => {
      res.json(response.data);
    }).catch(error => {
      res.status(500).send('Error');
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_2() {
  const server = http.createServer((req, res) => {
    const clientIp = req.socket.remoteAddress;
    const options = {
      hostname: 'api.example.com',
      path: '/user/data',
      method: 'GET',
      headers: {
        // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
        'X-Client-IP': clientIp,
        'Accept': 'application/json'
      }
    };
    
    const proxyReq = https.request(options, (proxyRes) => {
      let data = '';
      proxyRes.on('data', (chunk) => {
        data += chunk;
      });
      proxyRes.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(data);
      });
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/api/fetch', (req, res) => {
    const userIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
    request({
      url: 'https://third-party-api.com/data',
      method: 'GET',
      headers: {
        'X-Real-IP': userIp
      }
    }, (error, response, body) => {
      if (error) {
        return res.status(500).send('Error');
      }
      res.json(JSON.parse(body));
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_4() {
  const proxy = httpProxy.createProxyServer({});
  
  const server = http.createServer((req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    // Add the client IP to the headers
    // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
    req.headers['X-Forwarded-For'] = clientIp;
    
    proxy.web(req, res, {
      target: 'https://api.example.com'
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/submit-data', async (req, res) => {
    const userIp = req.ip;
    
    try {
      // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await fetch('https://analytics.example.com/track', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Visitor-IP': userIp
        },
        body: JSON.stringify({ data: req.body.data })
      });
      
      const data = await response.json();
      res.json(data);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.get('/proxy-request', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
    superagent
      .get('https://api.thirdparty.com/data')
      .set('X-Original-Client-IP', clientIp)
      .end((err, response) => {
        if (err) {
          return res.status(500).send('Error');
        }
        res.json(response.body);
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/user-profile', async (req, res) => {
    const userIp = req.ip || req.connection.remoteAddress;
    const userId = req.query.id;
    
    try {
      // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await got(`https://user-service.example.com/users/${userId}`, {
        headers: {
          'X-Source-IP': userIp
        }
      });
      
      res.json(JSON.parse(response.body));
    } catch (error) {
      res.status(500).send('Error fetching user data');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/analytics', (req, res) => {
    const clientIp = req.headers['cf-connecting-ip'] || req.ip;
    const userData = { userId: req.query.userId, action: req.query.action };
    
    // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
    axios.post('https://analytics.example.com/track', userData, {
      headers: {
        'X-User-IP': clientIp,
        'Content-Type': 'application/json'
      }
    }).then(response => {
      res.json({ success: true });
    }).catch(error => {
      res.status(500).send('Error tracking analytics');
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_9() {
  const server = http.createServer((req, res) => {
    const clientIp = req.socket.remoteAddress;
    
    if (req.url.startsWith('/api/')) {
      const options = {
        hostname: 'internal-api.example.com',
        path: req.url,
        method: req.method,
        headers: {
          ...req.headers,
          // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
          'X-Forwarded-For': clientIp
        }
      };
      
      const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      });
      
      req.pipe(proxyReq);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.use((req, res, next) => {
    req.clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    next();
  });
  
  app.get('/proxy-api', async (req, res) => {
    try {
      // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await axios.get('https://api.example.org/data', {
        headers: {
          'X-Client-Address': req.clientIp
        }
      });
      
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_11() {
  const proxy = httpProxy.createProxyServer({});
  
  proxy.on('proxyReq', (proxyReq, req, res, options) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
    proxyReq.setHeader('X-Original-IP', clientIp);
  });
  
  http.createServer((req, res) => {
    proxy.web(req, res, {
      target: 'https://backend.example.com'
    });
  }).listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.get('/weather', (req, res) => {
    const userIp = req.ip || req.connection.remoteAddress;
    const city = req.query.city || 'New York';
    
    // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
    request({
      url: `https://weather-api.example.com/forecast?city=${encodeURIComponent(city)}`,
      method: 'GET',
      headers: {
        'User-IP': userIp,
        'User-Agent': req.headers['user-agent']
      }
    }, (error, response, body) => {
      if (error) {
        return res.status(500).send('Error fetching weather data');
      }
      res.json(JSON.parse(body));
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/log-activity', async (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || 
                     req.headers['x-real-ip'] || 
                     req.connection.remoteAddress;
    
    const activityData = {
      action: req.body.action,
      timestamp: new Date().toISOString(),
      userId: req.body.userId
    };
    
    try {
      // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await fetch('https://logging-service.example.com/activity', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-IP-Address': clientIp
        },
        body: JSON.stringify(activityData)
      });
      
      if (!response.ok) {
        throw new Error('Logging service error');
      }
      
      res.json({ success: true });
    } catch (error) {
      res.status(500).send('Error logging activity');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/content', (req, res) => {
    const userIp = req.ip;
    const contentId = req.query.id;
    
    if (!contentId) {
      return res.status(400).send('Content ID is required');
    }
    
    // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
    superagent
      .get(`https://content-delivery.example.com/content/${contentId}`)
      .set({
        'X-Forwarded-IP': userIp,
        'Accept': 'application/json'
      })
      .end((err, response) => {
        if (err) {
          return res.status(500).send('Error fetching content');
        }
        res.json(response.body);
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/geo-locate', async (req, res) => {
    const userIp = req.headers['cf-connecting-ip'] || 
                   req.headers['x-forwarded-for'] || 
                   req.connection.remoteAddress;
    
    try {
      // ruleid: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await axios({
        method: 'get',
        url: 'https://geo-location-api.example.com/locate',
        headers: {
          'X-IP-To-Locate': userIp
        }
      });
      
      res.json({
        country: response.data.country,
        city: response.data.city,
        coordinates: response.data.coordinates
      });
    } catch (error) {
      res.status(500).send('Error determining location');
    }
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
    axios.get('https://api.example.com/data', {
      headers: {
        'User-Agent': req.headers['user-agent'],
        'Authorization': process.env.API_KEY
      }
    }).then(response => {
      res.json(response.data);
    }).catch(error => {
      res.status(500).send('Error');
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_2() {
  const server = http.createServer((req, res) => {
    const options = {
      hostname: 'api.example.com',
      path: '/user/data',
      method: 'GET',
      headers: {
        // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
        'Accept': 'application/json',
        'Authorization': `Bearer ${process.env.API_TOKEN}`
      }
    };
    
    const proxyReq = https.request(options, (proxyRes) => {
      let data = '';
      proxyRes.on('data', (chunk) => {
        data += chunk;
      });
      proxyRes.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(data);
      });
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/api/fetch', (req, res) => {
    // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
    request({
      url: 'https://third-party-api.com/data',
      method: 'GET',
      headers: {
        'API-Key': process.env.THIRD_PARTY_API_KEY
      }
    }, (error, response, body) => {
      if (error) {
        return res.status(500).send('Error');
      }
      res.json(JSON.parse(body));
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_4() {
  const proxy = httpProxy.createProxyServer({});
  
  const server = http.createServer((req, res) => {
    // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
    // Don't forward the client IP address
    proxy.web(req, res, {
      target: 'https://api.example.com',
      headers: {
        'Authorization': `Bearer ${process.env.API_TOKEN}`
      }
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/submit-data', async (req, res) => {
    try {
      // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await fetch('https://analytics.example.com/track', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'API-Key': process.env.ANALYTICS_API_KEY
        },
        body: JSON.stringify({ data: req.body.data })
      });
      
      const data = await response.json();
      res.json(data);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.get('/proxy-request', (req, res) => {
    // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
    superagent
      .get('https://api.thirdparty.com/data')
      .set('Authorization', `Bearer ${process.env.API_TOKEN}`)
      .set('Accept', 'application/json')
      .end((err, response) => {
        if (err) {
          return res.status(500).send('Error');
        }
        res.json(response.body);
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/user-profile', async (req, res) => {
    const userId = req.query.id;
    
    try {
      // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await got(`https://user-service.example.com/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${process.env.USER_SERVICE_TOKEN}`
        }
      });
      
      res.json(JSON.parse(response.body));
    } catch (error) {
      res.status(500).send('Error fetching user data');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/analytics', (req, res) => {
    const userData = { userId: req.query.userId, action: req.query.action };
    
    // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
    axios.post('https://analytics.example.com/track', userData, {
      headers: {
        'Content-Type': 'application/json',
        'API-Key': process.env.ANALYTICS_API_KEY
      }
    }).then(response => {
      res.json({ success: true });
    }).catch(error => {
      res.status(500).send('Error tracking analytics');
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_9() {
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/api/')) {
      const options = {
        hostname: 'internal-api.example.com',
        path: req.url,
        method: req.method,
        headers: {
          // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
          'Authorization': `Bearer ${process.env.INTERNAL_API_TOKEN}`,
          'Content-Type': req.headers['content-type']
        }
      };
      
      const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      });
      
      req.pipe(proxyReq);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.get('/proxy-api', async (req, res) => {
    try {
      // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await axios.get('https://api.example.org/data', {
        headers: {
          'Authorization': `Bearer ${process.env.API_KEY}`,
          'Accept': 'application/json'
        }
      });
      
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_11() {
  const proxy = httpProxy.createProxyServer({});
  
  proxy.on('proxyReq', (proxyReq, req, res, options) => {
    // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
    proxyReq.setHeader('Authorization', `Bearer ${process.env.API_TOKEN}`);
    proxyReq.setHeader('X-Request-ID', generateRequestId());
  });
  
  function generateRequestId() {
    return `req-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
  }
  
  http.createServer((req, res) => {
    proxy.web(req, res, {
      target: 'https://backend.example.com'
    });
  }).listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/weather', (req, res) => {
    const city = req.query.city || 'New York';
    
    // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
    request({
      url: `https://weather-api.example.com/forecast?city=${encodeURIComponent(city)}`,
      method: 'GET',
      headers: {
        'API-Key': process.env.WEATHER_API_KEY,
        'Accept-Language': req.headers['accept-language']
      }
    }, (error, response, body) => {
      if (error) {
        return res.status(500).send('Error fetching weather data');
      }
      res.json(JSON.parse(body));
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/log-activity', async (req, res) => {
    const activityData = {
      action: req.body.action,
      timestamp: new Date().toISOString(),
      userId: req.body.userId
    };
    
    try {
      // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await fetch('https://logging-service.example.com/activity', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.LOGGING_SERVICE_TOKEN}`
        },
        body: JSON.stringify(activityData)
      });
      
      if (!response.ok) {
        throw new Error('Logging service error');
      }
      
      res.json({ success: true });
    } catch (error) {
      res.status(500).send('Error logging activity');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/content', (req, res) => {
    const contentId = req.query.id;
    
    if (!contentId) {
      return res.status(400).send('Content ID is required');
    }
    
    // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
    superagent
      .get(`https://content-delivery.example.com/content/${contentId}`)
      .set({
        'Authorization': `Bearer ${process.env.CONTENT_API_KEY}`,
        'Accept': 'application/json'
      })
      .end((err, response) => {
        if (err) {
          return res.status(500).send('Error fetching content');
        }
        res.json(response.body);
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/geo-locate', async (req, res) => {
    // Use a default location or ask user for their location instead of forwarding IP
    const defaultCoordinates = { lat: 40.7128, lng: -74.0060 }; // New York
    
    try {
      // ok: javascript-do-not-forward-user-ip-address-using-http-proxy
      const response = await axios({
        method: 'get',
        url: 'https://geo-location-api.example.com/locate',
        headers: {
          'Authorization': `Bearer ${process.env.GEO_API_KEY}`
        },
        params: {
          lat: req.query.lat || defaultCoordinates.lat,
          lng: req.query.lng || defaultCoordinates.lng
        }
      });
      
      res.json({
        country: response.data.country,
        city: response.data.city,
        coordinates: response.data.coordinates
      });
    } catch (error) {
      res.status(500).send('Error determining location');
    }
  });
}
// {/fact}