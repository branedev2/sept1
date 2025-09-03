import express from 'express';
import http from 'http';
import bodyParser from 'body-parser';
import multer from 'multer';
import { Request, Response, NextFunction } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import Koa from 'koa';
import koaBodyParser from 'koa-bodyparser';
import fastify from 'fastify';
import Hapi from '@hapi/hapi';
import restify from 'restify';
import * as http2 from 'http2';

// TRUE POSITIVES (Vulnerable code)

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // ruleid: typescript-limit-on-request-content-length
  app.use(bodyParser.json()); // No limit specified, uses default which may be too large
  
  app.post('/api/data', (req, res) => {
    // Process request data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  // ruleid: typescript-limit-on-request-content-length
  app.use(bodyParser.urlencoded({ extended: true })); // No limit specified
  
  app.post('/api/form', (req, res) => {
    // Process form data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // ruleid: typescript-limit-on-request-content-length
  app.use(bodyParser.raw()); // No limit specified
  
  app.post('/api/binary', (req, res) => {
    // Process raw data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  // ruleid: typescript-limit-on-request-content-length
  app.use(bodyParser.text()); // No limit specified
  
  app.post('/api/text', (req, res) => {
    // Process text data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // ruleid: typescript-limit-on-request-content-length
  const upload = multer(); // No limits configured
  
  app.post('/api/upload', upload.single('file'), (req, res) => {
    // Process uploaded file
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_6() {
  const app = new Koa();
  
  // ruleid: typescript-limit-on-request-content-length
  app.use(koaBodyParser()); // No limit specified
  
  app.use(async ctx => {
    if (ctx.path === '/api/data' && ctx.method === 'POST') {
      // Process request data
      ctx.body = { success: true };
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_7() {
  const server = fastify();
  
  // ruleid: typescript-limit-on-request-content-length
  server.register(require('fastify-formbody')); // No limit specified
  
  server.post('/api/data', async (request, reply) => {
    // Process request data
    return { success: true };
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_8() {
  const server = restify.createServer();
  
  // ruleid: typescript-limit-on-request-content-length
  server.use(restify.plugins.bodyParser()); // No limit specified
  
  server.post('/api/data', (req, res, next) => {
    // Process request data
    res.send({ success: true });
    next();
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_9() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      
      // ruleid: typescript-limit-on-request-content-length
      req.on('data', chunk => {
        body += chunk.toString(); // No limit check, accumulates data indefinitely
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

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_10() {
  const init = async () => {
    const server = Hapi.server({
      port: 3000,
      host: 'localhost'
    });
    
    // ruleid: typescript-limit-on-request-content-length
    await server.register({
      plugin: require('@hapi/inert')
    }); // No payload limits configured
    
    server.route({
      method: 'POST',
      path: '/api/data',
      handler: (request, h) => {
        return { success: true };
      }
    });
    
    await server.start();
  };
  
  init();
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  // ruleid: typescript-limit-on-request-content-length
  app.use(express.json({ limit: '1gb' })); // Limit is set but extremely high
  
  app.post('/api/data', (req, res) => {
    // Process request data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  // ruleid: typescript-limit-on-request-content-length
  app.use(express.raw({ limit: '500mb' })); // Limit is set but very high
  
  app.post('/api/binary', (req, res) => {
    // Process raw data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_13() {
  const http2Server = http2.createServer();
  
  http2Server.on('stream', (stream, headers) => {
    if (headers[':method'] === 'POST') {
      let data = Buffer.alloc(0);
      
      // ruleid: typescript-limit-on-request-content-length
      stream.on('data', (chunk) => {
        data = Buffer.concat([data, chunk]); // No size limit check
      });
      
      stream.on('end', () => {
        stream.respond({
          'content-type': 'application/json',
          ':status': 200
        });
        stream.end(JSON.stringify({ success: true }));
      });
    }
  });
  
  http2Server.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  // Custom middleware without size limits
  function customBodyParser(req: Request, res: Response, next: NextFunction) {
    let body = '';
    
    // ruleid: typescript-limit-on-request-content-length
    req.on('data', chunk => {
      body += chunk.toString(); // No limit check
    });
    
    req.on('end', () => {
      req.body = JSON.parse(body);
      next();
    });
  }
  
  app.use(customBodyParser);
  
  app.post('/api/data', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // ruleid: typescript-limit-on-request-content-length
  const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
      cb(null, file.originalname);
    }
  });
  
  const upload = multer({ storage }); // No limits configured
  
  app.post('/api/upload', upload.array('files', 10), (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES (Secure code)

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // ok: typescript-limit-on-request-content-length
  app.use(bodyParser.json({ limit: '1mb' })); // Reasonable limit specified
  
  app.post('/api/data', (req, res) => {
    // Process request data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // ok: typescript-limit-on-request-content-length
  app.use(bodyParser.urlencoded({ extended: true, limit: '1mb' })); // Reasonable limit specified
  
  app.post('/api/form', (req, res) => {
    // Process form data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // ok: typescript-limit-on-request-content-length
  app.use(bodyParser.raw({ limit: '2mb' })); // Reasonable limit specified
  
  app.post('/api/binary', (req, res) => {
    // Process raw data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  // ok: typescript-limit-on-request-content-length
  app.use(bodyParser.text({ limit: '500kb' })); // Reasonable limit specified
  
  app.post('/api/text', (req, res) => {
    // Process text data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // ok: typescript-limit-on-request-content-length
  const upload = multer({
    limits: {
      fileSize: 5 * 1024 * 1024 // 5MB limit
    }
  });
  
  app.post('/api/upload', upload.single('file'), (req, res) => {
    // Process uploaded file
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_6() {
  const app = new Koa();
  
  // ok: typescript-limit-on-request-content-length
  app.use(koaBodyParser({
    jsonLimit: '1mb',
    formLimit: '1mb',
    textLimit: '1mb'
  }));
  
  app.use(async ctx => {
    if (ctx.path === '/api/data' && ctx.method === 'POST') {
      // Process request data
      ctx.body = { success: true };
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_7() {
  const server = fastify();
  
  // ok: typescript-limit-on-request-content-length
  server.register(require('fastify-formbody'), {
    bodyLimit: 1048576 // 1MB limit
  });
  
  server.post('/api/data', async (request, reply) => {
    // Process request data
    return { success: true };
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_8() {
  const server = restify.createServer();
  
  // ok: typescript-limit-on-request-content-length
  server.use(restify.plugins.bodyParser({
    maxBodySize: 1024 * 1024 // 1MB limit
  }));
  
  server.post('/api/data', (req, res, next) => {
    // Process request data
    res.send({ success: true });
    next();
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_9() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      let size = 0;
      const maxSize = 1024 * 1024; // 1MB limit
      
      req.on('data', chunk => {
        size += chunk.length;
        
        // ok: typescript-limit-on-request-content-length
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

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_10() {
  const init = async () => {
    // ok: typescript-limit-on-request-content-length
    const server = Hapi.server({
      port: 3000,
      host: 'localhost',
      routes: {
        payload: {
          maxBytes: 1048576 // 1MB limit
        }
      }
    });
    
    await server.register({
      plugin: require('@hapi/inert')
    });
    
    server.route({
      method: 'POST',
      path: '/api/data',
      handler: (request, h) => {
        return { success: true };
      }
    });
    
    await server.start();
  };
  
  init();
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // ok: typescript-limit-on-request-content-length
  app.use(express.json({ limit: '100kb' })); // Strict limit
  
  app.post('/api/data', (req, res) => {
    // Process request data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // ok: typescript-limit-on-request-content-length
  app.use(express.raw({ limit: '500kb' })); // Reasonable limit
  
  app.post('/api/binary', (req, res) => {
    // Process raw data
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_13() {
  const http2Server = http2.createServer();
  
  http2Server.on('stream', (stream, headers) => {
    if (headers[':method'] === 'POST') {
      let data = Buffer.alloc(0);
      let size = 0;
      const maxSize = 1024 * 1024; // 1MB limit
      
      stream.on('data', (chunk) => {
        size += chunk.length;
        
        // ok: typescript-limit-on-request-content-length
        if (size > maxSize) {
          stream.respond({
            'content-type': 'application/json',
            ':status': 413
          });
          stream.end(JSON.stringify({ error: 'Request entity too large' }));
          stream.destroy();
          return;
        }
        
        data = Buffer.concat([data, chunk]);
      });
      
      stream.on('end', () => {
        stream.respond({
          'content-type': 'application/json',
          ':status': 200
        });
        stream.end(JSON.stringify({ success: true }));
      });
    }
  });
  
  http2Server.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // Custom middleware with size limits
  function customBodyParser(req: Request, res: Response, next: NextFunction) {
    let body = '';
    let size = 0;
    const maxSize = 1024 * 1024; // 1MB limit
    
    req.on('data', chunk => {
      size += chunk.length;
      
      // ok: typescript-limit-on-request-content-length
      if (size > maxSize) {
        res.status(413).json({ error: 'Request entity too large' });
        req.destroy();
        return;
      }
      
      body += chunk.toString();
    });
    
    req.on('end', () => {
      try {
        req.body = JSON.parse(body);
        next();
      } catch (e) {
        res.status(400).json({ error: 'Invalid JSON' });
      }
    });
  }
  
  app.use(customBodyParser);
  
  app.post('/api/data', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // ok: typescript-limit-on-request-content-length
  const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
      cb(null, file.originalname);
    }
  });
  
  const upload = multer({
    storage,
    limits: {
      fileSize: 2 * 1024 * 1024, // 2MB file size limit
      files: 5 // Maximum 5 files
    }
  });
  
  app.post('/api/upload', upload.array('files'), (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}