// File: xss_protection_header_examples.js
const express = require('express');
const http = require('http');
const https = require('https');
const helmet = require('helmet');
const app = express();
const koa = require('koa');
const fastify = require('fastify')();
const restify = require('restify');
const hapi = require('@hapi/hapi');

// True Positives (Vulnerable Code Examples)

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use((req, res, next) => {
    // ruleid: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '0');
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_2() {
  const server = http.createServer((req, res) => {
    // ruleid: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', 0);
    res.end('Hello World!');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/api/data', (req, res) => {
    const userData = { name: req.query.name };
    // ruleid: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', 'false');
    res.json(userData);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.use((req, res, next) => {
    const headers = {
      'Content-Type': 'application/json',
      // ruleid: javascript-incorrect-xss-protection-header
      'X-XSS-Protection': '0'
    };
    
    for (const [key, value] of Object.entries(headers)) {
      res.setHeader(key, value);
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_5() {
  const koaApp = new koa();
  
  koaApp.use(async (ctx) => {
    // ruleid: javascript-incorrect-xss-protection-header
    ctx.set('X-XSS-Protection', '0');
    ctx.body = 'Hello World';
  });
  
  koaApp.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_6() {
  fastify.get('/', (request, reply) => {
    // ruleid: javascript-incorrect-xss-protection-header
    reply.header('X-XSS-Protection', '0');
    reply.send({ hello: 'world' });
  });
  
  fastify.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_7() {
  const server = restify.createServer();
  
  server.get('/hello/:name', (req, res, next) => {
    // ruleid: javascript-incorrect-xss-protection-header
    res.header('X-XSS-Protection', 'false');
    res.send(`Hello ${req.params.name}`);
    next();
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_8() {
  const init = async () => {
    const server = hapi.server({
      port: 3000,
      host: 'localhost'
    });

    server.route({
      method: 'GET',
      path: '/',
      handler: (request, h) => {
        // ruleid: javascript-incorrect-xss-protection-header
        return h.response('Hello World').header('X-XSS-Protection', '0');
      }
    });

    await server.start();
  };
  
  init();
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.use((req, res, next) => {
    const xssProtectionValue = req.secure ? '1' : '0';
    // ruleid: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', xssProtectionValue);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  const securityHeaders = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'",
    // ruleid: javascript-incorrect-xss-protection-header
    'X-XSS-Protection': '0',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff'
  };
  
  app.use((req, res, next) => {
    Object.entries(securityHeaders).forEach(([header, value]) => {
      res.setHeader(header, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  function setSecurityHeaders(res) {
    // ruleid: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('X-Frame-Options', 'DENY');
  }
  
  app.use((req, res, next) => {
    setSecurityHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  app.use((req, res, next) => {
    // ruleid: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', isDevelopment ? '0' : '1');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.use((req, res, next) => {
    const headerValue = 0;
    // ruleid: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', headerValue);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  const configureHeaders = (res) => {
    const headers = {
      'X-Frame-Options': 'DENY',
      // ruleid: javascript-incorrect-xss-protection-header
      'X-XSS-Protection': '0',
      'X-Content-Type-Options': 'nosniff'
    };
    
    for (const [key, value] of Object.entries(headers)) {
      res.setHeader(key, value);
    }
  };
  
  app.use((req, res, next) => {
    configureHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.use(helmet({
    xssFilter: false
  }));
  
  app.use((req, res, next) => {
    // ruleid: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '0');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// True Negatives (Safe Code Examples)

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use((req, res, next) => {
    // ok: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '1');
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_2() {
  const server = http.createServer((req, res) => {
    // ok: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.end('Hello World!');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/api/data', (req, res) => {
    const userData = { name: req.query.name };
    // ok: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '1');
    res.json(userData);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.use((req, res, next) => {
    const headers = {
      'Content-Type': 'application/json',
      // ok: javascript-incorrect-xss-protection-header
      'X-XSS-Protection': '1; mode=block'
    };
    
    for (const [key, value] of Object.entries(headers)) {
      res.setHeader(key, value);
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_5() {
  const koaApp = new koa();
  
  koaApp.use(async (ctx) => {
    // ok: javascript-incorrect-xss-protection-header
    ctx.set('X-XSS-Protection', '1');
    ctx.body = 'Hello World';
  });
  
  koaApp.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_6() {
  fastify.get('/', (request, reply) => {
    // ok: javascript-incorrect-xss-protection-header
    reply.header('X-XSS-Protection', '1; mode=block');
    reply.send({ hello: 'world' });
  });
  
  fastify.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_7() {
  const server = restify.createServer();
  
  server.get('/hello/:name', (req, res, next) => {
    // ok: javascript-incorrect-xss-protection-header
    res.header('X-XSS-Protection', '1');
    res.send(`Hello ${req.params.name}`);
    next();
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_8() {
  const init = async () => {
    const server = hapi.server({
      port: 3000,
      host: 'localhost'
    });

    server.route({
      method: 'GET',
      path: '/',
      handler: (request, h) => {
        // ok: javascript-incorrect-xss-protection-header
        return h.response('Hello World').header('X-XSS-Protection', '1; mode=block');
      }
    });

    await server.start();
  };
  
  init();
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // Using helmet middleware which sets proper security headers by default
  // ok: javascript-incorrect-xss-protection-header
  app.use(helmet());
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  const securityHeaders = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'",
    // ok: javascript-incorrect-xss-protection-header
    'X-XSS-Protection': '1; mode=block',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff'
  };
  
  app.use((req, res, next) => {
    Object.entries(securityHeaders).forEach(([header, value]) => {
      res.setHeader(header, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  function setSecurityHeaders(res) {
    // ok: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '1');
    res.setHeader('X-Frame-Options', 'DENY');
  }
  
  app.use((req, res, next) => {
    setSecurityHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // Using helmet's xssFilter middleware specifically
  // ok: javascript-incorrect-xss-protection-header
  app.use(helmet.xssFilter());
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.use((req, res, next) => {
    const headerValue = '1';
    // ok: javascript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', headerValue);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  const configureHeaders = (res) => {
    const headers = {
      'X-Frame-Options': 'DENY',
      // ok: javascript-incorrect-xss-protection-header
      'X-XSS-Protection': '1; mode=block',
      'X-Content-Type-Options': 'nosniff'
    };
    
    for (const [key, value] of Object.entries(headers)) {
      res.setHeader(key, value);
    }
  };
  
  app.use((req, res, next) => {
    configureHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // Using Content-Security-Policy as a modern alternative to X-XSS-Protection
  app.use((req, res, next) => {
    // ok: javascript-incorrect-xss-protection-header
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
    next();
  });
  
  app.listen(3000);
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