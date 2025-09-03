import express from 'express';
import cors from 'cors';
import { Request, Response } from 'express';
import http from 'http';
import https from 'https';
import { IncomingMessage, ServerResponse } from 'http';
import { NextFunction } from 'connect';
import { Application } from 'express-serve-static-core';

// TRUE POSITIVES (Vulnerable Code)

// Bad case 1: Setting Access-Control-Allow-Origin to * in Express
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
  });
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ sensitive: 'data' });
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 2: Using cors middleware with wildcard
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  // ruleid: typescript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: '*',
    methods: ['GET', 'POST']
  }));
  
  app.get('/api/users', (req: Request, res: Response) => {
    res.json([{ id: 1, name: 'User' }]);
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 3: Setting CORS headers directly in a route handler
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/api/sensitive', (req: Request, res: Response) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');
    res.json({ key: 'sensitive-api-key-12345' });
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 4: Using http module with wildcard CORS
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_4() {
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    
    if (req.url === '/api/data' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: 'sensitive information' }));
    }
  });
  
  server.listen(3000);
}
// {/fact}

// Bad case 5: Using a variable that contains wildcard
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  const corsOrigin = '*';
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', corsOrigin);
    res.header('Access-Control-Allow-Methods', 'GET, POST');
    next();
  });
  
  app.get('/api/accounts', (req: Request, res: Response) => {
    res.json({ account: 'details' });
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 6: Setting CORS in a conditional but still using wildcard
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api/')) {
      // ruleid: typescript-do-not-allow-unrestricted-cors
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST');
    }
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 7: Using a function that returns wildcard
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  function getCorsOrigin() {
    return '*';
  }
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', getCorsOrigin());
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 8: Setting CORS in an API route with wildcard
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/api/payments', (req: Request, res: Response) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', '*');
    res.json({ payment: 'processed' });
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 9: Using template literal with wildcard
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  const origin = '*';
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', `${origin}`);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 10: Setting CORS with wildcard in an HTTPS server
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_10() {
  const options = {
    key: Buffer.from('key'),
    cert: Buffer.from('cert')
  };
  
  const server = https.createServer(options, (req: IncomingMessage, res: ServerResponse) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    if (req.url === '/api/secure-data') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ secure: 'data' }));
    }
  });
  
  server.listen(3000);
}
// {/fact}

// Bad case 11: Using cors middleware with options object containing wildcard
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const corsOptions = {
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204
  };
  
  // ruleid: typescript-do-not-allow-unrestricted-cors
  app.use(cors(corsOptions));
  
  app.get('/api/user-data', (req: Request, res: Response) => {
    res.json({ user: 'data' });
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 12: Setting wildcard CORS in a specific route with cors middleware
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  // ruleid: typescript-do-not-allow-unrestricted-cors
  app.options('/api/transactions', cors({ origin: '*' }));
  app.get('/api/transactions', cors({ origin: '*' }), (req: Request, res: Response) => {
    res.json({ transactions: [] });
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 13: Setting CORS with wildcard in a middleware function
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  function setCorsHeaders(req: Request, res: Response, next: NextFunction) {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST');
    next();
  }
  
  app.use(setCorsHeaders);
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Bad case 14: Setting CORS with wildcard in a route-specific middleware
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/api/admin', 
    (req: Request, res: Response, next: NextFunction) => {
      // ruleid: typescript-do-not-allow-unrestricted-cors
      res.header('Access-Control-Allow-Origin', '*');
      next();
    },
    (req: Request, res: Response) => {
      res.json({ admin: 'data' });
    }
  );
  
  app.listen(3000);
}
// {/fact}

// Bad case 15: Using a dynamic value that resolves to wildcard
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  const config = {
    cors: {
      origin: '*'
    }
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', config.cors.origin);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// Good case 1: Setting specific origin in Express
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', 'https://trusted-site.com');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
  });
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 2: Using cors middleware with specific origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // ok: typescript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: 'https://trusted-site.com',
    methods: ['GET', 'POST']
  }));
  
  app.get('/api/users', (req: Request, res: Response) => {
    res.json([{ id: 1, name: 'User' }]);
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 3: Using an array of allowed origins
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // ok: typescript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: ['https://trusted-site.com', 'https://another-trusted-site.com'],
    methods: ['GET', 'POST']
  }));
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 4: Using a function to determine origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_4() {
  const app = express();
  const allowedOrigins = ['https://trusted-site.com', 'https://another-trusted-site.com'];
  
  // ok: typescript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: function(origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
      if (!origin || allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST']
  }));
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 5: Setting CORS headers based on request origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_5() {
  const app = express();
  const allowedOrigins = ['https://trusted-site.com', 'https://another-trusted-site.com'];
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      // ok: typescript-do-not-allow-unrestricted-cors
      res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Methods', 'GET, POST');
    next();
  });
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 6: Using environment variables for CORS configuration
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_6() {
  const app = express();
  // Simulating environment variables
  const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://trusted-site.com';
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    res.header('Access-Control-Allow-Methods', 'GET, POST');
    next();
  });
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 7: Using http module with specific origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_7() {
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // ok: typescript-do-not-allow-unrestricted-cors
    res.setHeader('Access-Control-Allow-Origin', 'https://trusted-site.com');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    
    if (req.url === '/api/data' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: 'value' }));
    }
  });
  
  server.listen(3000);
}
// {/fact}

// Good case 8: Setting CORS for specific routes only
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/api/public-data', (req: Request, res: Response) => {
    // ok: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', 'https://trusted-site.com');
    res.json({ public: 'data' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 9: Using a configuration object with specific origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_9() {
  const app = express();
  const corsConfig = {
    origin: 'https://trusted-site.com',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE'
  };
  
  // ok: typescript-do-not-allow-unrestricted-cors
  app.use(cors(corsConfig));
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 10: Using regex for origin validation
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // ok: typescript-do-not-allow-unrestricted-cors
  app.use(cors({
    origin: /^https:\/\/.*\.trusted-domain\.com$/,
    methods: ['GET', 'POST']
  }));
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 11: Using a middleware function for CORS with specific origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  function corsMiddleware(req: Request, res: Response, next: NextFunction) {
    // ok: typescript-do-not-allow-unrestricted-cors
    res.header('Access-Control-Allow-Origin', 'https://trusted-site.com');
    res.header('Access-Control-Allow-Methods', 'GET, POST');
    next();
  }
  
  app.use(corsMiddleware);
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 12: Setting CORS with specific origin in HTTPS server
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_12() {
  const options = {
    key: Buffer.from('key'),
    cert: Buffer.from('cert')
  };
  
  const server = https.createServer(options, (req: IncomingMessage, res: ServerResponse) => {
    // ok: typescript-do-not-allow-unrestricted-cors
    res.setHeader('Access-Control-Allow-Origin', 'https://trusted-site.com');
    
    if (req.url === '/api/secure-data') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ secure: 'data' }));
    }
  });
  
  server.listen(3000);
}
// {/fact}

// Good case 13: Using a dynamic list of allowed origins
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  function getAllowedOrigins() {
    // This could come from a database or configuration file
    return ['https://trusted-site.com', 'https://another-trusted-site.com'];
  }
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin as string;
    const allowedOrigins = getAllowedOrigins();
    
    if (origin && allowedOrigins.includes(origin)) {
      // ok: typescript-do-not-allow-unrestricted-cors
      res.header('Access-Control-Allow-Origin', origin);
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 14: Setting route-specific CORS with specific origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // ok: typescript-do-not-allow-unrestricted-cors
  app.get('/api/data', cors({ origin: 'https://trusted-site.com' }), (req: Request, res: Response) => {
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}

// Good case 15: Not setting CORS headers at all (default same-origin policy)
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/api/data', (req: Request, res: Response) => {
    // ok: typescript-do-not-allow-unrestricted-cors
    // No CORS headers set, default same-origin policy applies
    res.json({ data: 'value' });
  });
  
  app.listen(3000);
}
// {/fact}