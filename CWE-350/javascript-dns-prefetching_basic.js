// This file contains examples of secure and insecure usage of X-DNS-Prefetch-Control header
// in various JavaScript frameworks and environments

const express = require('express');
const helmet = require('helmet');
const http = require('http');
const https = require('https');
const fastify = require('fastify');
const Koa = require('koa');
const Hapi = require('@hapi/hapi');
const restify = require('restify');
const connect = require('connect');

// True Positive Examples (Insecure configurations)

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use((req, res, next) => {
    // ruleid: javascript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'on');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/user', (req, res) => {
    // ruleid: javascript-dns-prefetching
    res.header('X-DNS-Prefetch-Control', 'on');
    res.send('User profile');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_3() {
  const server = http.createServer((req, res) => {
    // ruleid: javascript-dns-prefetching
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'X-DNS-Prefetch-Control': 'on'
    });
    res.end('<html><body>Hello World</body></html>');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.use(helmet({
    dnsPrefetchControl: { 
      // ruleid: javascript-dns-prefetching
      allow: true 
    }
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_5() {
  const app = fastify();
  
  app.get('/', (request, reply) => {
    // ruleid: javascript-dns-prefetching
    reply.header('X-DNS-Prefetch-Control', 'on');
    reply.send({ hello: 'world' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_6() {
  const app = new Koa();
  
  app.use(async ctx => {
    // ruleid: javascript-dns-prefetching
    ctx.set('X-DNS-Prefetch-Control', 'on');
    ctx.body = 'Hello World';
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_7() {
  const server = Hapi.server({
    port: 3000,
    host: 'localhost'
  });
  
  server.route({
    method: 'GET',
    path: '/',
    handler: (request, h) => {
      // ruleid: javascript-dns-prefetching
      return h.response('Hello World').header('X-DNS-Prefetch-Control', 'on');
    }
  });
  
  server.start();
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_8() {
  const server = restify.createServer();
  
  server.get('/', function(req, res, next) {
    // ruleid: javascript-dns-prefetching
    res.header('X-DNS-Prefetch-Control', 'on');
    res.send('Hello World');
    next();
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_9() {
  const app = connect();
  
  app.use(function(req, res, next) {
    // ruleid: javascript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'on');
    res.end('Hello World');
  });
  
  http.createServer(app).listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  const headers = {
    'X-DNS-Prefetch-Control': 'on',
    'Content-Type': 'application/json'
  };
  
  app.get('/api', (req, res) => {
    // ruleid: javascript-dns-prefetching
    Object.keys(headers).forEach(header => {
      res.setHeader(header, headers[header]);
    });
    res.send({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const securityHeaders = new Map();
  securityHeaders.set('X-Frame-Options', 'DENY');
  // ruleid: javascript-dns-prefetching
  securityHeaders.set('X-DNS-Prefetch-Control', 'on');
  
  app.use((req, res, next) => {
    securityHeaders.forEach((value, key) => {
      res.setHeader(key, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  const headerValue = process.env.NODE_ENV === 'development' ? 'on' : 'on';
  
  app.use((req, res, next) => {
    // ruleid: javascript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', headerValue);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  function setSecurityHeaders(res) {
    // ruleid: javascript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'on');
    res.setHeader('X-XSS-Protection', '1; mode=block');
  }
  
  app.use((req, res, next) => {
    setSecurityHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_14() {
  const https = require('https');
  const fs = require('fs');
  
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
  };
  
  https.createServer(options, (req, res) => {
    // ruleid: javascript-dns-prefetching
    res.writeHead(200, { 'X-DNS-Prefetch-Control': 'on' });
    res.end('Hello World\n');
  }).listen(8000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  const enableDnsPrefetch = true;
  
  app.use((req, res, next) => {
    // ruleid: javascript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', enableDnsPrefetch ? 'on' : 'off');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// True Negative Examples (Secure configurations)

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use((req, res, next) => {
    // ok: javascript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/user', (req, res) => {
    // ok: javascript-dns-prefetching
    res.header('X-DNS-Prefetch-Control', 'off');
    res.send('User profile');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_3() {
  const server = http.createServer((req, res) => {
    // ok: javascript-dns-prefetching
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'X-DNS-Prefetch-Control': 'off'
    });
    res.end('<html><body>Hello World</body></html>');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.use(helmet({
    dnsPrefetchControl: { 
      // ok: javascript-dns-prefetching
      allow: false 
    }
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // ok: javascript-dns-prefetching
  app.use(helmet.dnsPrefetchControl({ allow: false }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_6() {
  const app = fastify();
  
  app.get('/', (request, reply) => {
    // ok: javascript-dns-prefetching
    reply.header('X-DNS-Prefetch-Control', 'off');
    reply.send({ hello: 'world' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_7() {
  const app = new Koa();
  
  app.use(async ctx => {
    // ok: javascript-dns-prefetching
    ctx.set('X-DNS-Prefetch-Control', 'off');
    ctx.body = 'Hello World';
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_8() {
  const server = Hapi.server({
    port: 3000,
    host: 'localhost'
  });
  
  server.route({
    method: 'GET',
    path: '/',
    handler: (request, h) => {
      // ok: javascript-dns-prefetching
      return h.response('Hello World').header('X-DNS-Prefetch-Control', 'off');
    }
  });
  
  server.start();
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_9() {
  const server = restify.createServer();
  
  server.get('/', function(req, res, next) {
    // ok: javascript-dns-prefetching
    res.header('X-DNS-Prefetch-Control', 'off');
    res.send('Hello World');
    next();
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // ok: javascript-dns-prefetching
  // Using helmet's default configuration which sets X-DNS-Prefetch-Control to off
  app.use(helmet());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const headers = {
    'X-DNS-Prefetch-Control': 'off',
    'Content-Type': 'application/json'
  };
  
  app.get('/api', (req, res) => {
    // ok: javascript-dns-prefetching
    Object.keys(headers).forEach(header => {
      res.setHeader(header, headers[header]);
    });
    res.send({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_12() {
  const app = express();
  const securityHeaders = new Map();
  securityHeaders.set('X-Frame-Options', 'DENY');
  // ok: javascript-dns-prefetching
  securityHeaders.set('X-DNS-Prefetch-Control', 'off');
  
  app.use((req, res, next) => {
    securityHeaders.forEach((value, key) => {
      res.setHeader(key, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  function setSecurityHeaders(res) {
    // ok: javascript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.setHeader('X-XSS-Protection', '1; mode=block');
  }
  
  app.use((req, res, next) => {
    setSecurityHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // ok: javascript-dns-prefetching
  // Not setting X-DNS-Prefetch-Control at all (browser default is typically off)
  app.get('/', (req, res) => {
    res.send('Hello World');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_15() {
  const app = express();
  const enableDnsPrefetch = false;
  
  app.use((req, res, next) => {
    // ok: javascript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', enableDnsPrefetch ? 'on' : 'off');
    next();
  });
  
  app.listen(3000);
}
// {/fact}