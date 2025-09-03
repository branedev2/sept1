import express from 'express';
import { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import axios from 'axios';
import http from 'http';
import https from 'https';

// True Positives (Vulnerable Code)

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    
    // ruleid: typescript-unsanitized-input-in-origin-header
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.use((req: Request, res: Response) => {
    const requestOrigin = req.headers.origin as string;
    
    // ruleid: typescript-unsanitized-input-in-origin-header
    res.header('Access-Control-Allow-Origin', requestOrigin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    res.send('CORS enabled');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_3() {
  const corsOptions = {
    // ruleid: typescript-unsanitized-input-in-origin-header
    origin: (origin: string, callback: (err: Error | null, allow?: boolean) => void) => {
      callback(null, true); // Always allow any origin
    },
    credentials: true
  };
  
  const app = express();
  app.use(cors(corsOptions));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-unsanitized-input-in-origin-header
    const dynamicOrigin = req.get('origin');
    if (dynamicOrigin) {
      res.setHeader('Access-Control-Allow-Origin', dynamicOrigin);
    }
    next();
  });
  
  app.get('/api/data', (req: Request, res: Response) => {
    res.json({ message: 'Sensitive data' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_5() {
  const server = http.createServer((req, res) => {
    const origin = req.headers.origin as string;
    
    // ruleid: typescript-unsanitized-input-in-origin-header
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-unsanitized-input-in-origin-header
    if (req.headers.origin) {
      // Accepts any origin without validation
      res.header('Access-Control-Allow-Origin', req.headers.origin);
      res.header('Access-Control-Allow-Credentials', 'true');
    }
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: typescript-unsanitized-input-in-origin-header
  app.use(cors({
    origin: true, // Reflects the request origin
    credentials: true
  }));
  
  app.get('/api/sensitive', (req: Request, res: Response) => {
    res.json({ secretKey: 'sensitive-data' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/api/user-data', (req: Request, res: Response) => {
    const userOrigin = req.headers.origin as string;
    
    // ruleid: typescript-unsanitized-input-in-origin-header
    res.setHeader('Access-Control-Allow-Origin', userOrigin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    res.json({ username: 'admin', role: 'administrator' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // ruleid: typescript-unsanitized-input-in-origin-header
  const corsConfig = {
    origin: (origin: string, callback: Function) => {
      // No validation, just logging
      console.log(`Request from origin: ${origin}`);
      callback(null, true);
    },
    credentials: true
  };
  
  app.use(cors(corsConfig));
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_10() {
  const server = https.createServer({}, (req, res) => {
    // ruleid: typescript-unsanitized-input-in-origin-header
    const clientOrigin = req.headers.origin || '*';
    
    res.writeHead(200, {
      'Access-Control-Allow-Origin': clientOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
      'Content-Type': 'application/json'
    });
    
    res.end(JSON.stringify({ data: 'sensitive information' }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-unsanitized-input-in-origin-header
    const originHeader = req.headers.origin;
    
    if (originHeader && originHeader.toString().includes('.com')) {
      // Still vulnerable as any .com domain is allowed
      res.setHeader('Access-Control-Allow-Origin', originHeader);
    } else {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  // ruleid: typescript-unsanitized-input-in-origin-header
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    
    // Using either origin or referer without proper validation
    res.header('Access-Control-Allow-Origin', origin || referer || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // ruleid: typescript-unsanitized-input-in-origin-header
  const dynamicCors = (req: Request, res: Response, next: NextFunction) => {
    const requestOrigin = req.headers.origin as string;
    
    // Weak validation that can be bypassed
    if (!requestOrigin || requestOrigin.length > 5) {
      res.header('Access-Control-Allow-Origin', requestOrigin);
      res.header('Access-Control-Allow-Credentials', 'true');
    }
    
    next();
  };
  
  app.use(dynamicCors);
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const userAgent = req.headers['user-agent'];
    const origin = req.headers.origin as string;
    
    // ruleid: typescript-unsanitized-input-in-origin-header
    if (userAgent && userAgent.includes('Mozilla')) {
      // Still vulnerable as it accepts any origin for Mozilla browsers
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // ruleid: typescript-unsanitized-input-in-origin-header
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin as string;
    const host = req.headers.host;
    
    // Trying to be clever but still vulnerable
    if (origin && (!host || origin.includes(host.split(':')[0]))) {
      res.header('Access-Control-Allow-Origin', origin);
    } else {
      res.header('Access-Control-Allow-Origin', '*');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  const allowedOrigins = ['https://example.com', 'https://api.example.com'];
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin as string;
    
    // ok: typescript-unsanitized-input-in-origin-header
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
      res.setHeader('Access-Control-Allow-Origin', 'https://example.com');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // ok: typescript-unsanitized-input-in-origin-header
  app.use(cors({
    origin: 'https://trusted-site.com',
    methods: ['GET', 'POST'],
    credentials: true
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  const whitelist = ['https://example1.com', 'https://example2.com'];
  
  // ok: typescript-unsanitized-input-in-origin-header
  const corsOptions = {
    origin: function (origin: string | undefined, callback: Function) {
      if (!origin || whitelist.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  };
  
  app.use(cors(corsOptions));
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-unsanitized-input-in-origin-header
    res.setHeader('Access-Control-Allow-Origin', 'https://specific-origin.com');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  const validOrigins = new Set([
    'https://trusted1.example.com',
    'https://trusted2.example.com'
  ]);
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin as string;
    
    // ok: typescript-unsanitized-input-in-origin-header
    if (origin && validOrigins.has(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
    } else {
      res.header('Access-Control-Allow-Origin', 'https://trusted1.example.com');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_6() {
  const server = http.createServer((req, res) => {
    // ok: typescript-unsanitized-input-in-origin-header
    res.setHeader('Access-Control-Allow-Origin', 'https://fixed-origin.com');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  const allowedDomains = ['trusted1.com', 'trusted2.com', 'trusted3.com'];
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin as string;
    
    // ok: typescript-unsanitized-input-in-origin-header
    if (origin) {
      try {
        const hostname = new URL(origin).hostname;
        const domain = hostname.split('.').slice(-2).join('.');
        
        if (allowedDomains.includes(domain)) {
          res.header('Access-Control-Allow-Origin', origin);
        } else {
          res.header('Access-Control-Allow-Origin', 'https://trusted1.com');
        }
      } catch {
        res.header('Access-Control-Allow-Origin', 'https://trusted1.com');
      }
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // ok: typescript-unsanitized-input-in-origin-header
  const corsOptions = {
    origin: ['https://allowed1.com', 'https://allowed2.com'],
    methods: ['GET', 'POST', 'PUT'],
    credentials: true
  };
  
  app.use(cors(corsOptions));
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  const allowedOriginRegex = /^https:\/\/([\w-]+\.)?example\.com$/;
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin as string;
    
    // ok: typescript-unsanitized-input-in-origin-header
    if (origin && allowedOriginRegex.test(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    } else {
      res.header('Access-Control-Allow-Origin', 'https://example.com');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // Environment-based configuration
  const environment = process.env.NODE_ENV || 'development';
  const allowedOrigins = {
    development: ['http://localhost:3000', 'http://localhost:8080'],
    production: ['https://production.example.com', 'https://api.example.com']
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin as string;
    const currentAllowedOrigins = environment === 'production' ? 
      allowedOrigins.production : allowedOrigins.development;
    
    // ok: typescript-unsanitized-input-in-origin-header
    if (origin && currentAllowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    } else {
      res.header('Access-Control-Allow-Origin', currentAllowedOrigins[0]);
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // ok: typescript-unsanitized-input-in-origin-header
  app.use((req: Request, res: Response, next: NextFunction) => {
    // No CORS headers set at all - default same-origin policy applies
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  const trustedOrigins = new Map([
    ['api', 'https://api.example.com'],
    ['web', 'https://web.example.com'],
    ['admin', 'https://admin.example.com']
  ]);
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const clientType = req.query.client as string;
    
    // ok: typescript-unsanitized-input-in-origin-header
    if (clientType && trustedOrigins.has(clientType)) {
      res.header('Access-Control-Allow-Origin', trustedOrigins.get(clientType));
    } else {
      res.header('Access-Control-Allow-Origin', trustedOrigins.get('web'));
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // ok: typescript-unsanitized-input-in-origin-header
  app.use(cors({
    origin: false, // Disables CORS
    methods: ['GET', 'POST']
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  const validateOrigin = (origin: string): boolean => {
    const validOrigins = ['https://app.example.com', 'https://admin.example.com'];
    return validOrigins.includes(origin);
  };
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin as string;
    
    // ok: typescript-unsanitized-input-in-origin-header
    if (origin && validateOrigin(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
    } else {
      res.header('Access-Control-Allow-Origin', 'https://app.example.com');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // Using a configuration file or environment variables for allowed origins
  const configuredOrigins = ['https://main.example.com', 'https://dev.example.com'];
  
  // ok: typescript-unsanitized-input-in-origin-header
  app.use(cors({
    origin: (origin: string | undefined, callback: Function) => {
      if (!origin || configuredOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('CORS policy violation'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
  }));
  
  app.listen(3000);
}
// {/fact}