import express from 'express';
import helmet from 'helmet';

// TRUE POSITIVES (Vulnerable/Insecure Code)

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: false, // Disabling CSP header
  }));
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet({
    xssFilter: false, // Disabling XSS protection
  }));
  
  app.get('/profile', (req, res) => {
    res.send(`Welcome ${req.query.name}`);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet({
    frameguard: false, // Disabling clickjacking protection
  }));
  
  app.post('/submit', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet({
    hsts: false, // Disabling HTTP Strict Transport Security
  }));
  
  app.get('/secure', (req, res) => {
    res.send('Secure content');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet({
    noSniff: false, // Disabling X-Content-Type-Options
  }));
  
  app.get('/download', (req, res) => {
    res.download('file.pdf');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(
    helmet.contentSecurityPolicy(false)
  );
  
  app.get('/content', (req, res) => {
    res.send('<script>alert("hello")</script>');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(
    helmet.xssFilter({ setOnOldIE: false })
  );
  
  app.get('/legacy', (req, res) => {
    res.send(`<div>${req.query.content}</div>`);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  const helmetConfig = {
    frameguard: false,
    xssFilter: false
  };
  
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet(helmetConfig));
  
  app.get('/dashboard', (req, res) => {
    res.render('dashboard');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet.frameguard({ action: 'ALLOW-FROM', domain: 'https://example.com' })); // Deprecated option
  
  app.get('/iframe-content', (req, res) => {
    res.send('<h1>Content for iframe</h1>');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  const securityConfig = {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"], // Overly restrictive
        scriptSrc: ["'unsafe-inline'", "'unsafe-eval'"] // Unsafe directives
      }
    }
  };
  
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet(securityConfig));
  
  app.get('/app', (req, res) => {
    res.send('Application content');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet.dnsPrefetchControl({ allow: true })); // Allowing DNS prefetching
  
  app.get('/sensitive', (req, res) => {
    res.send('Sensitive data');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet.permittedCrossDomainPolicies({ permittedPolicies: 'all' })); // Too permissive
  
  app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  // ruleid: typescript-helmet-security-header-disabled
  app.use(helmet.referrerPolicy({ policy: 'unsafe-url' })); // Unsafe referrer policy
  
  app.get('/redirect', (req, res) => {
    res.redirect('https://example.com');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const options = {
    contentSecurityPolicy: true,
    xssFilter: true,
    // ruleid: typescript-helmet-security-header-disabled
    frameguard: false
  };
  
  app.use(helmet(options));
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  // Not using helmet at all
  // ruleid: typescript-helmet-security-header-disabled
  app.use((req, res, next) => {
    // Custom middleware without security headers
    next();
  });
  
  app.get('/unprotected', (req, res) => {
    res.send('Unprotected content');
  });
  
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES (Safe/Secure Code)

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet()); // Using helmet with default settings
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_2() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'trusted-cdn.com']
      }
    }
  }));
  
  app.get('/profile', (req, res) => {
    res.send(`Welcome ${req.query.name}`);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_3() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.contentSecurityPolicy());
  app.use(helmet.xssFilter());
  app.use(helmet.frameguard());
  
  app.post('/submit', (req, res) => {
    res.json({ success: true });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_4() {
  const app = express();
  const secureConfig = {
    contentSecurityPolicy: true,
    xssFilter: true,
    frameguard: true
  };
  
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet(secureConfig));
  
  app.get('/secure', (req, res) => {
    res.send('Secure content');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_5() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.frameguard({ action: 'deny' }));
  
  app.get('/protected', (req, res) => {
    res.send('Protected content');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_6() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.hsts({
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }));
  
  app.get('/banking', (req, res) => {
    res.send('Banking information');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_7() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.noSniff());
  
  app.get('/download', (req, res) => {
    res.download('file.pdf');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_8() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.dnsPrefetchControl());
  
  app.get('/sensitive', (req, res) => {
    res.send('Sensitive data');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_9() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.permittedCrossDomainPolicies());
  
  app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_10() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.referrerPolicy());
  
  app.get('/redirect', (req, res) => {
    res.redirect('https://example.com');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const options = {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: []
      }
    }
  };
  
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet(options));
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_12() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'https://api.example.com']
    }
  }));
  
  app.get('/app', (req, res) => {
    res.send('Application content');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_13() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet({
    frameguard: {
      action: 'sameorigin'
    }
  }));
  
  app.get('/iframe-content', (req, res) => {
    res.send('<h1>Content for iframe</h1>');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_14() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet.referrerPolicy({
    policy: 'strict-origin-when-cross-origin'
  }));
  
  app.get('/articles', (req, res) => {
    res.send('Article content');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_15() {
  const app = express();
  // ok: typescript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'script-src': ["'self'", 'trusted-scripts.com'],
        'style-src': ["'self'", 'trusted-styles.com'],
        'img-src': ["'self'", 'trusted-images.com'],
        'connect-src': ["'self'", 'trusted-api.com']
      }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: true,
    originAgentCluster: true
  }));
  
  app.get('/', (req, res) => {
    res.send('Fully protected content');
  });
  
  app.listen(3000);
}
// {/fact}