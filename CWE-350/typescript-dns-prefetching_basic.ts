import express from 'express';
import helmet from 'helmet';
import { NextFunction, Request, Response } from 'express';
import * as http from 'http';
import * as https from 'https';
import { IncomingMessage, ServerResponse } from 'http';
import { Server } from 'net';
import { RequestHandler } from 'express-serve-static-core';
import { Application } from 'express';
import { OutgoingHttpHeaders } from 'http';

// True Positive Examples (Vulnerable Code)

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'on');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/api/data', (req: Request, res: Response) => {
    // ruleid: typescript-dns-prefetching
    res.header('X-DNS-Prefetch-Control', 'on');
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_3() {
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // ruleid: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'on');
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  const securityHeaders: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-dns-prefetching
    res.set('X-DNS-Prefetch-Control', 'on');
    next();
  };
  
  app.use(securityHeaders);
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.use(helmet({
    // ruleid: typescript-dns-prefetching
    dnsPrefetchControl: { allow: true }
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  const headers: OutgoingHttpHeaders = {
    'Content-Type': 'application/json',
    // ruleid: typescript-dns-prefetching
    'X-DNS-Prefetch-Control': 'on'
  };
  
  app.get('/api/users', (req: Request, res: Response) => {
    res.writeHead(200, headers);
    res.end(JSON.stringify({ users: [] }));
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  const configureHeaders = (res: Response): void => {
    // ruleid: typescript-dns-prefetching
    res.header('X-DNS-Prefetch-Control', 'on');
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    configureHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_8() {
  const server = https.createServer({}, (req: IncomingMessage, res: ServerResponse) => {
    // ruleid: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'on');
    res.end('Secure Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  const securityConfig = {
    headers: {
      // ruleid: typescript-dns-prefetching
      'X-DNS-Prefetch-Control': 'on',
      'X-Frame-Options': 'DENY'
    }
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    Object.entries(securityConfig.headers).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.use(helmet.dnsPrefetchControl({
    // ruleid: typescript-dns-prefetching
    allow: true
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  const enableDnsPrefetch = true;
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (enableDnsPrefetch) {
      // ruleid: typescript-dns-prefetching
      res.setHeader('X-DNS-Prefetch-Control', 'on');
    }
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  const headerValue = 'on';
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', headerValue);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_13() {
  class SecurityMiddleware {
    public static applyHeaders(res: Response): void {
      // ruleid: typescript-dns-prefetching
      res.setHeader('X-DNS-Prefetch-Control', 'on');
    }
  }
  
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    SecurityMiddleware.applyHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  const getHeaderValue = (): string => {
    return 'on';
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', getHeaderValue());
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  const configureApp = (application: Application): void => {
    application.use((req: Request, res: Response, next: NextFunction) => {
      // ruleid: typescript-dns-prefetching
      res.setHeader('X-DNS-Prefetch-Control', 'on');
      next();
    });
  };
  
  configureApp(app);
  app.listen(3000);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/api/data', (req: Request, res: Response) => {
    // ok: typescript-dns-prefetching
    res.header('X-DNS-Prefetch-Control', 'off');
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_3() {
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // ok: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  const securityHeaders: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-dns-prefetching
    res.set('X-DNS-Prefetch-Control', 'off');
    next();
  };
  
  app.use(securityHeaders);
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.use(helmet({
    // ok: typescript-dns-prefetching
    dnsPrefetchControl: { allow: false }
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  const headers: OutgoingHttpHeaders = {
    'Content-Type': 'application/json',
    // ok: typescript-dns-prefetching
    'X-DNS-Prefetch-Control': 'off'
  };
  
  app.get('/api/users', (req: Request, res: Response) => {
    res.writeHead(200, headers);
    res.end(JSON.stringify({ users: [] }));
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: typescript-dns-prefetching
  app.use(helmet.dnsPrefetchControl());  // Default is { allow: false }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // ok: typescript-dns-prefetching
  app.use(helmet());  // Default includes dnsPrefetchControl with { allow: false }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_9() {
  const server = https.createServer({}, (req: IncomingMessage, res: ServerResponse) => {
    // ok: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.end('Secure Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  const securityConfig = {
    headers: {
      // ok: typescript-dns-prefetching
      'X-DNS-Prefetch-Control': 'off',
      'X-Frame-Options': 'DENY'
    }
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    Object.entries(securityConfig.headers).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // ok: typescript-dns-prefetching
  // Not setting the X-DNS-Prefetch-Control header at all
  // (modern browsers default to 'auto' which is generally safe)
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  const enableDnsPrefetch = false;
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!enableDnsPrefetch) {
      // ok: typescript-dns-prefetching
      res.setHeader('X-DNS-Prefetch-Control', 'off');
    }
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_13() {
  class SecurityMiddleware {
    public static applyHeaders(res: Response): void {
      // ok: typescript-dns-prefetching
      res.setHeader('X-DNS-Prefetch-Control', 'off');
    }
  }
  
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    SecurityMiddleware.applyHeaders(res);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  const getHeaderValue = (): string => {
    return 'off';
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-dns-prefetching
    res.setHeader('X-DNS-Prefetch-Control', getHeaderValue());
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=dns-prefetching@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  const configureApp = (application: Application): void => {
    application.use((req: Request, res: Response, next: NextFunction) => {
      // ok: typescript-dns-prefetching
      res.setHeader('X-DNS-Prefetch-Control', 'off');
      next();
    });
  };
  
  configureApp(app);
  app.listen(3000);
}
// {/fact}