// Import necessary modules
const express = require('express');
const http = require('http');
const https = require('https');
const bodyParser = require('body-parser');
const multer = require('multer');
const Koa = require('koa');
const koaBodyParser = require('koa-bodyparser');
const restify = require('restify');
const fastify = require('fastify');
const axios = require('axios');
const request = require('request');
const fs = require('fs');

// TRUE POSITIVES (Vulnerable Code Examples)

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // No limit on JSON body size
  // ruleid: javascript-limit-on-request-content-length
  app.use(bodyParser.json());
  
  app.post('/api/data', (req, res) => {
    // Process potentially large JSON payload
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  // Extremely high limit that effectively removes any practical constraint
  // ruleid: javascript-limit-on-request-content-length
  app.use(bodyParser.json({ limit: '10gb' }));
  
  app.post('/api/upload', (req, res) => {
    res.send('Upload successful');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // No limit on URL-encoded data
  // ruleid: javascript-limit-on-request-content-length
  app.use(bodyParser.urlencoded({ extended: true }));
  
  app.post('/api/form', (req, res) => {
    res.send('Form processed');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4() {
  const upload = multer({
    // No file size limit for uploads
    // ruleid: javascript-limit-on-request-content-length
    storage: multer.diskStorage({
      destination: './uploads/',
      filename: (req, file, cb) => {
        cb(null, file.originalname);
      }
    })
  });
  
  const app = express();
  app.post('/upload', upload.single('file'), (req, res) => {
    res.send('File uploaded');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5() {
  const app = new Koa();
  
  // No limit on Koa body parser
  // ruleid: javascript-limit-on-request-content-length
  app.use(koaBodyParser());
  
  app.use(async ctx => {
    if (ctx.method === 'POST') {
      ctx.body = { received: true };
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6() {
  const server = restify.createServer();
  
  // No limit on body parser
  // ruleid: javascript-limit-on-request-content-length
  server.use(restify.plugins.bodyParser());
  
  server.post('/api/data', (req, res, next) => {
    res.send(200, { success: true });
    return next();
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7() {
  const server = fastify();
  
  // Extremely high body limit
  // ruleid: javascript-limit-on-request-content-length
  server.register(require('fastify-formbody'), {
    bodyLimit: 1073741824 // 1GB
  });
  
  server.post('/api/form', (request, reply) => {
    reply.send({ success: true });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      
      // No limit on data collection
      // ruleid: javascript-limit-on-request-content-length
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      });
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // Different routes with inconsistent limits
  app.post('/api/small', bodyParser.json({ limit: '1mb' }), (req, res) => {
    res.json({ success: true });
  });
  
  // ruleid: javascript-limit-on-request-content-length
  app.post('/api/large', bodyParser.json(), (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  // Raw body parser with no limits
  // ruleid: javascript-limit-on-request-content-length
  app.use(bodyParser.raw({ type: 'application/octet-stream' }));
  
  app.post('/api/binary', (req, res) => {
    // Process binary data
    res.send('Binary data received');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  // Text body parser with no limits
  // ruleid: javascript-limit-on-request-content-length
  app.use(bodyParser.text({ type: 'text/plain' }));
  
  app.post('/api/text', (req, res) => {
    res.send('Text received');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  // Setting an unreasonably high limit for all routes
  // ruleid: javascript-limit-on-request-content-length
  app.use(express.json({ limit: '5gb' }));
  app.use(express.urlencoded({ extended: true, limit: '5gb' }));
  
  app.post('/api/data', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13() {
  // Creating a proxy server with no request size limits
  const proxy = http.createServer((req, res) => {
    // ruleid: javascript-limit-on-request-content-length
    const options = {
      hostname: 'target-server.com',
      port: 80,
      path: req.url,
      method: req.method,
      headers: req.headers
    };
    
    const proxyReq = http.request(options, proxyRes => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });
    
    req.pipe(proxyReq);
  });
  
  proxy.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  // Using middleware that doesn't limit request size
  app.use((req, res, next) => {
    // Custom body parser with no limits
    if (req.method === 'POST') {
      let data = '';
      
      // ruleid: javascript-limit-on-request-content-length
      req.on('data', chunk => {
        data += chunk;
      });
      
      req.on('end', () => {
        req.body = JSON.parse(data);
        next();
      });
    } else {
      next();
    }
  });
  
  app.post('/api/custom', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // Using express.raw() with no limits
  // ruleid: javascript-limit-on-request-content-length
  app.use(express.raw({ type: '*/*' }));
  
  app.post('/api/any', (req, res) => {
    res.send('Data received');
  });
  
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // Setting a reasonable limit for JSON body size
  // ok: javascript-limit-on-request-content-length
  app.use(bodyParser.json({ limit: '1mb' }));
  
  app.post('/api/data', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // Setting reasonable limits for different content types
  // ok: javascript-limit-on-request-content-length
  app.use(bodyParser.json({ limit: '1mb' }));
  app.use(bodyParser.urlencoded({ extended: true, limit: '1mb' }));
  
  app.post('/api/form', (req, res) => {
    res.send('Form processed');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3() {
  const upload = multer({
    // Setting file size limits for uploads
    limits: {
      // ok: javascript-limit-on-request-content-length
      fileSize: 5 * 1024 * 1024 // 5MB
    },
    storage: multer.diskStorage({
      destination: './uploads/',
      filename: (req, file, cb) => {
        cb(null, file.originalname);
      }
    })
  });
  
  const app = express();
  app.post('/upload', upload.single('file'), (req, res) => {
    res.send('File uploaded');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4() {
  const app = new Koa();
  
  // Setting a reasonable limit for Koa body parser
  // ok: javascript-limit-on-request-content-length
  app.use(koaBodyParser({
    jsonLimit: '1mb',
    formLimit: '1mb',
    textLimit: '1mb'
  }));
  
  app.use(async ctx => {
    if (ctx.method === 'POST') {
      ctx.body = { received: true };
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5() {
  const server = restify.createServer();
  
  // Setting a reasonable limit for body parser
  // ok: javascript-limit-on-request-content-length
  server.use(restify.plugins.bodyParser({
    maxBodySize: 1024 * 1024 // 1MB
  }));
  
  server.post('/api/data', (req, res, next) => {
    res.send(200, { success: true });
    return next();
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6() {
  const server = fastify();
  
  // Setting a reasonable body limit
  // ok: javascript-limit-on-request-content-length
  server.register(require('fastify-formbody'), {
    bodyLimit: 1048576 // 1MB
  });
  
  server.post('/api/form', (request, reply) => {
    reply.send({ success: true });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      let size = 0;
      const maxSize = 1024 * 1024; // 1MB
      
      req.on('data', chunk => {
        size += chunk.length;
        
        // ok: javascript-limit-on-request-content-length
        if (size > maxSize) {
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Request entity too large' }));
          req.destroy();
          return;
        }
        
        body += chunk.toString();
      });
      
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      });
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // Setting consistent limits across different routes
  // ok: javascript-limit-on-request-content-length
  const jsonParser = bodyParser.json({ limit: '1mb' });
  
  app.post('/api/route1', jsonParser, (req, res) => {
    res.json({ success: true });
  });
  
  app.post('/api/route2', jsonParser, (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // Raw body parser with reasonable limits
  // ok: javascript-limit-on-request-content-length
  app.use(bodyParser.raw({ 
    type: 'application/octet-stream',
    limit: '2mb'
  }));
  
  app.post('/api/binary', (req, res) => {
    // Process binary data
    res.send('Binary data received');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // Text body parser with reasonable limits
  // ok: javascript-limit-on-request-content-length
  app.use(bodyParser.text({ 
    type: 'text/plain',
    limit: '500kb'
  }));
  
  app.post('/api/text', (req, res) => {
    res.send('Text received');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // Setting reasonable limits for express built-in parsers
  // ok: javascript-limit-on-request-content-length
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));
  
  app.post('/api/data', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12() {
  // Creating a proxy server with request size limits
  const proxy = http.createServer((req, res) => {
    let size = 0;
    const maxSize = 1024 * 1024; // 1MB
    
    // ok: javascript-limit-on-request-content-length
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxSize) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Request entity too large' }));
        req.destroy();
        return;
      }
    });
    
    const options = {
      hostname: 'target-server.com',
      port: 80,
      path: req.url,
      method: req.method,
      headers: req.headers
    };
    
    const proxyReq = http.request(options, proxyRes => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });
    
    req.pipe(proxyReq);
  });
  
  proxy.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // Using middleware that limits request size
  app.use((req, res, next) => {
    // Custom body parser with limits
    if (req.method === 'POST') {
      let data = '';
      let size = 0;
      const maxSize = 1024 * 1024; // 1MB
      
      req.on('data', chunk => {
        size += chunk.length;
        
        // ok: javascript-limit-on-request-content-length
        if (size > maxSize) {
          res.status(413).json({ error: 'Request entity too large' });
          req.destroy();
          return;
        }
        
        data += chunk;
      });
      
      req.on('end', () => {
        req.body = JSON.parse(data);
        next();
      });
    } else {
      next();
    }
  });
  
  app.post('/api/custom', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // Using express.raw() with reasonable limits
  // ok: javascript-limit-on-request-content-length
  app.use(express.raw({ 
    type: '*/*',
    limit: '2mb'
  }));
  
  app.post('/api/any', (req, res) => {
    res.send('Data received');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15() {
  // Setting up an HTTP server with content-length validation
  const server = http.createServer((req, res) => {
    // ok: javascript-limit-on-request-content-length
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    const maxSize = 1024 * 1024; // 1MB
    
    if (contentLength > maxSize) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Request entity too large' }));
      return;
    }
    
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      });
    }
  });
  
  server.listen(3000);
}
// {/fact}