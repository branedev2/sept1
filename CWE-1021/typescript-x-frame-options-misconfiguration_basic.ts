import express from 'express';
import { Request, Response, NextFunction } from 'express';
import http from 'http';
import https from 'https';
import Koa from 'koa';
import Fastify from 'fastify';
import { IncomingMessage, ServerResponse } from 'http';
import helmet from 'helmet';
import { Server } from 'http';

// True Positive Examples (Vulnerable Code)

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', 'ALLOW');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/profile', (req: Request, res: Response) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.send('Profile page');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_3() {
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', '');
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    res.header('X-Frame-Options', 'ALLOW-FROM');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/dashboard', (req: Request, res: Response) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    res.header('X-Frame-Options', 'ALLOW-FROM https://example.com https://test.com');
    res.send('Dashboard');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_6() {
  const app = Koa();
  
  app.use(async (ctx) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    ctx.set('X-Frame-Options', 'allow');
    ctx.body = 'Hello World';
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_7() {
  const fastify = Fastify();
  
  fastify.get('/', (request, reply) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    reply.header('X-Frame-Options', 'ALLOW-FROM http://example.com/');
    reply.send({ hello: 'world' });
  });
  
  fastify.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const options = {
      value: 'ALLOW-FROM https://example.com/'
    };
    // ruleid: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', options.value);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  const securityHeaders = {
    // ruleid: typescript-x-frame-options-misconfiguration
    'X-Frame-Options': 'ALLOWFROM'
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    Object.entries(securityHeaders).forEach(([header, value]) => {
      res.setHeader(header, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.get('/admin', (req: Request, res: Response) => {
    const origin = req.query.origin as string;
    // ruleid: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', `ALLOW-FROM ${origin}`);
    res.send('Admin panel');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  const xFrameOptions = 'allow';
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', xFrameOptions);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  function setHeaders(res: Response) {
    // ruleid: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', 'ALLOW-FROM *');
  }
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    setHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.use(express.static('public', {
    setHeaders: (res: Response) => {
      // ruleid: typescript-x-frame-options-misconfiguration
      res.setHeader('X-Frame-Options', 'ALLOW');
    }
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  const headerValue = (origin: string) => `ALLOW-FROM ${origin}`;
  
  app.get('/content', (req: Request, res: Response) => {
    // ruleid: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', headerValue('https://example.com'));
    res.send('Content');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_15() {
  const server = https.createServer({}, (req: IncomingMessage, res: ServerResponse) => {
    const headers = {
      'Content-Type': 'text/html',
      // ruleid: typescript-x-frame-options-misconfiguration
      'X-Frame-Options': ''
    };
    
    res.writeHead(200, headers);
    res.end('<html><body>Hello World</body></html>');
  });
  
  server.listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/profile', (req: Request, res: Response) => {
    // ok: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.send('Profile page');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_3() {
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // ok: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', 'DENY');
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-x-frame-options-misconfiguration
    res.header('X-Frame-Options', 'SAMEORIGIN');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // Using helmet middleware for secure headers
  // ok: typescript-x-frame-options-misconfiguration
  app.use(helmet.frameguard({ action: 'deny' }));
  
  app.get('/dashboard', (req: Request, res: Response) => {
    res.send('Dashboard');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_6() {
  const app = Koa();
  
  app.use(async (ctx) => {
    // ok: typescript-x-frame-options-misconfiguration
    ctx.set('X-Frame-Options', 'DENY');
    ctx.body = 'Hello World';
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_7() {
  const fastify = Fastify();
  
  fastify.get('/', (request, reply) => {
    // ok: typescript-x-frame-options-misconfiguration
    reply.header('X-Frame-Options', 'SAMEORIGIN');
    reply.send({ hello: 'world' });
  });
  
  fastify.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const options = {
      value: 'DENY'
    };
    // ok: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', options.value);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  const securityHeaders = {
    // ok: typescript-x-frame-options-misconfiguration
    'X-Frame-Options': 'SAMEORIGIN'
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    Object.entries(securityHeaders).forEach(([header, value]) => {
      res.setHeader(header, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // Using helmet with custom configuration
  // ok: typescript-x-frame-options-misconfiguration
  app.use(helmet.frameguard({ action: 'sameorigin' }));
  
  app.get('/admin', (req: Request, res: Response) => {
    res.send('Admin panel');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  const xFrameOptions = 'DENY';
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', xFrameOptions);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  function setSecureHeaders(res: Response) {
    // ok: typescript-x-frame-options-misconfiguration
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  }
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    setSecureHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.use(express.static('public', {
    setHeaders: (res: Response) => {
      // ok: typescript-x-frame-options-misconfiguration
      res.setHeader('X-Frame-Options', 'DENY');
    }
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // Using a Content-Security-Policy header instead of X-Frame-Options
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-x-frame-options-misconfiguration
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_15() {
  const server = https.createServer({}, (req: IncomingMessage, res: ServerResponse) => {
    const headers = {
      'Content-Type': 'text/html',
      // ok: typescript-x-frame-options-misconfiguration
      'X-Frame-Options': 'SAMEORIGIN'
    };
    
    res.writeHead(200, headers);
    res.end('<html><body>Hello World</body></html>');
  });
  
  server.listen(3000);
}
// {/fact}