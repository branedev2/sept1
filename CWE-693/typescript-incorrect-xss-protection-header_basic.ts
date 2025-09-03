import express from 'express';
import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import http from 'http';
import https from 'https';
import Koa from 'koa';
import fastify from 'fastify';
import { IncomingMessage, ServerResponse } from 'http';

// True Positive Examples (Vulnerable Code)

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '0');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/api/data', (req: Request, res: Response) => {
    // ruleid: typescript-incorrect-xss-protection-header
    res.header('X-XSS-Protection', '0');
    res.json({ message: 'Hello World' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_3() {
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // ruleid: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', 'false');
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const headers = {
      'Content-Type': 'application/json',
      // ruleid: typescript-incorrect-xss-protection-header
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
  const app = new Koa();
  
  app.use(async (ctx) => {
    // ruleid: typescript-incorrect-xss-protection-header
    ctx.set('X-XSS-Protection', '0');
    ctx.body = 'Hello World';
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_6() {
  const server = fastify();
  
  server.get('/', (request, reply) => {
    // ruleid: typescript-incorrect-xss-protection-header
    reply.header('X-XSS-Protection', '0');
    reply.send({ hello: 'world' });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  const securityHeaders = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'",
    // ruleid: typescript-incorrect-xss-protection-header
    'X-XSS-Protection': '0'
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

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  const configureHeaders = (res: Response) => {
    // ruleid: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    configureHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const xssProtectionValue = '0';
    // ruleid: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', xssProtectionValue);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_10() {
  const server = http.createServer();
  
  server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    if (req.url === '/api') {
      // ruleid: typescript-incorrect-xss-protection-header
      res.setHeader('X-XSS-Protection', 'false');
      res.end(JSON.stringify({ data: 'API response' }));
    } else {
      res.end('Hello World');
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const disableXssFilter = true;
    if (disableXssFilter) {
      // ruleid: typescript-incorrect-xss-protection-header
      res.setHeader('X-XSS-Protection', '0');
    }
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  const headerValues = {
    xssProtection: '0',
    contentTypeOptions: 'nosniff'
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', headerValues.xssProtection);
    res.setHeader('X-Content-Type-Options', headerValues.contentTypeOptions);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/legacy-api', (req: Request, res: Response) => {
    // ruleid: typescript-incorrect-xss-protection-header
    res.header('X-XSS-Protection', '0');
    res.header('Access-Control-Allow-Origin', '*');
    res.json({ legacy: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  function setLegacyHeaders(res: Response) {
    // ruleid: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '0');
  }
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/old')) {
      setLegacyHeaders(res);
    }
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  const securityConfig = {
    headers: {
      xssProtection: '0',
      frameOptions: 'DENY'
    }
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', securityConfig.headers.xssProtection);
    res.setHeader('X-Frame-Options', securityConfig.headers.frameOptions);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '1');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/api/data', (req: Request, res: Response) => {
    // ok: typescript-incorrect-xss-protection-header
    res.header('X-XSS-Protection', '1; mode=block');
    res.json({ message: 'Hello World' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_3() {
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // ok: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', 'true');
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const headers = {
      'Content-Type': 'application/json',
      // ok: typescript-incorrect-xss-protection-header
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
  const app = new Koa();
  
  app.use(async (ctx) => {
    // ok: typescript-incorrect-xss-protection-header
    ctx.set('X-XSS-Protection', '1');
    ctx.body = 'Hello World';
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  // Using helmet which sets secure headers by default
  // ok: typescript-incorrect-xss-protection-header
  app.use(helmet());
  
  app.get('/', (req: Request, res: Response) => {
    res.send('Hello World');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // Using helmet with specific configuration
  // ok: typescript-incorrect-xss-protection-header
  app.use(helmet.xssFilter());
  
  app.get('/', (req: Request, res: Response) => {
    res.send('Hello World');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_8() {
  const server = fastify();
  
  server.get('/', (request, reply) => {
    // ok: typescript-incorrect-xss-protection-header
    reply.header('X-XSS-Protection', '1; mode=block');
    reply.send({ hello: 'world' });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  const securityHeaders = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'",
    // ok: typescript-incorrect-xss-protection-header
    'X-XSS-Protection': '1; mode=block'
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

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  const configureHeaders = (res: Response) => {
    // ok: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', '1');
    res.setHeader('X-Content-Type-Options', 'nosniff');
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    configureHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_11() {
  const server = http.createServer();
  
  server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    if (req.url === '/api') {
      // ok: typescript-incorrect-xss-protection-header
      res.setHeader('X-XSS-Protection', '1; report=https://example.com/report');
      res.end(JSON.stringify({ data: 'API response' }));
    } else {
      res.end('Hello World');
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  const headerValues = {
    xssProtection: '1; mode=block',
    contentTypeOptions: 'nosniff'
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', headerValues.xssProtection);
    res.setHeader('X-Content-Type-Options', headerValues.contentTypeOptions);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // Not setting X-XSS-Protection at all is better than setting it to 0
  // ok: typescript-incorrect-xss-protection-header
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // Using CSP instead of X-XSS-Protection is a modern approach
  // ok: typescript-incorrect-xss-protection-header
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  const securityConfig = {
    headers: {
      xssProtection: '1; mode=block',
      frameOptions: 'DENY'
    }
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-incorrect-xss-protection-header
    res.setHeader('X-XSS-Protection', securityConfig.headers.xssProtection);
    res.setHeader('X-Frame-Options', securityConfig.headers.frameOptions);
    next();
  });
  
  app.listen(3000);
}
// {/fact}