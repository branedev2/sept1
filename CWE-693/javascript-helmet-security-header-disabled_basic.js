// This file contains test cases for the javascript-helmet-security-header-disabled rule
// The rule detects when security headers are disabled in Helmet middleware

const express = require('express');
const helmet = require('helmet');

// TRUE POSITIVES (Vulnerable Code Examples)

// Bad Case 1: Disabling Content Security Policy
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: false
  }));
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 2: Disabling X-Frame-Options protection (clickjacking protection)
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    frameguard: false
  }));
  
  app.get('/dashboard', (req, res) => {
    res.send('Dashboard content');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 3: Disabling XSS protection
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    xssFilter: false
  }));
  
  app.get('/profile', (req, res) => {
    const username = req.query.username;
    res.send(`Welcome, ${username}!`);
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 4: Disabling HSTS (HTTP Strict Transport Security)
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    hsts: false
  }));
  
  app.get('/secure', (req, res) => {
    res.send('Secure content');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 5: Disabling noSniff protection
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    noSniff: false
  }));
  
  app.get('/download', (req, res) => {
    res.send('File content');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 6: Disabling DNS Prefetch Control
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    dnsPrefetchControl: false
  }));
  
  app.get('/', (req, res) => {
    res.send('Main page');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 7: Disabling IE No Open protection
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    ieNoOpen: false
  }));
  
  app.get('/documents', (req, res) => {
    res.send('Document content');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 8: Disabling multiple security features
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: false,
    xssFilter: false,
    frameguard: false
  }));
  
  app.get('/vulnerable', (req, res) => {
    res.send('Vulnerable page');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 9: Disabling Referrer Policy
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    referrerPolicy: false
  }));
  
  app.get('/sensitive', (req, res) => {
    res.send('Sensitive information');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 10: Disabling Expect-CT
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    expectCt: false
  }));
  
  app.get('/certificates', (req, res) => {
    res.send('Certificate Transparency info');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 11: Disabling Permissions Policy
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    permittedCrossDomainPolicies: false
  }));
  
  app.get('/media', (req, res) => {
    res.send('Media content');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 12: Using individual helmet module with disabled protection
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  const contentSecurityPolicy = require('helmet-csp');
  
  app.use(helmet());
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(contentSecurityPolicy({
    directives: {
      defaultSrc: ["'none'"]
    },
    reportOnly: true // This makes CSP report-only mode, effectively disabling protection
  }));
  
  app.listen(3000);
}
// {/fact}

// Bad Case 13: Disabling CSP with empty directives
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {} // Empty directives effectively disable CSP
    }
  }));
  
  app.get('/content', (req, res) => {
    res.send('Content page');
  });
  
  app.listen(3000);
}
// {/fact}

// Bad Case 14: Disabling security headers in a conditional block
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const isDevEnvironment = process.env.NODE_ENV === 'development';
  
  if (isDevEnvironment) {
    // ruleid: javascript-helmet-security-header-disabled
    app.use(helmet({
      contentSecurityPolicy: false,
      xssFilter: false
    }));
  } else {
    app.use(helmet());
  }
  
  app.listen(3000);
}
// {/fact}

// Bad Case 15: Disabling security headers with object configuration
// {fact rule=protection-mechanism-failure@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  const securityConfig = {
    frameguard: false,
    xssFilter: false,
    noSniff: false
  };
  
  // ruleid: javascript-helmet-security-header-disabled
  app.use(helmet(securityConfig));
  
  app.get('/', (req, res) => {
    res.send('Home page');
  });
  
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// Good Case 1: Using helmet with default settings
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet());
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 2: Configuring CSP properly
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'trusted-cdn.com']
      }
    }
  }));
  
  app.get('/dashboard', (req, res) => {
    res.send('Dashboard content');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 3: Configuring frameguard with proper options
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    frameguard: {
      action: 'deny'
    }
  }));
  
  app.get('/profile', (req, res) => {
    res.send('Profile page');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 4: Setting HSTS with proper configuration
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }));
  
  app.get('/secure', (req, res) => {
    res.send('Secure content');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 5: Using multiple security features with proper configuration
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"]
      }
    },
    referrerPolicy: {
      policy: 'same-origin'
    }
  }));
  
  app.get('/', (req, res) => {
    res.send('Main page');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 6: Using individual helmet modules correctly
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const csp = require('helmet-csp');
  
  // ok: javascript-helmet-security-header-disabled
  app.use(csp({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'trusted-styles.com']
    }
  }));
  
  app.get('/documents', (req, res) => {
    res.send('Document content');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 7: Setting referrer policy properly
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    referrerPolicy: {
      policy: 'no-referrer'
    }
  }));
  
  app.get('/sensitive', (req, res) => {
    res.send('Sensitive information');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 8: Using Expect-CT with proper configuration
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    expectCt: {
      maxAge: 86400,
      enforce: true,
      reportUri: 'https://example.com/report'
    }
  }));
  
  app.get('/certificates', (req, res) => {
    res.send('Certificate Transparency info');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 9: Using Permissions Policy properly
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    permittedCrossDomainPolicies: {
      permittedPolicies: 'none'
    }
  }));
  
  app.get('/media', (req, res) => {
    res.send('Media content');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 10: Using helmet with environment-specific configurations
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_10() {
  const app = express();
  const isProduction = process.env.NODE_ENV === 'production';
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: isProduction ? ["'self'"] : ["'self'", "'unsafe-eval'"]
      }
    }
  }));
  
  app.get('/', (req, res) => {
    res.send('Home page');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 11: Using helmet with all security features explicitly enabled
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: true,
    xssFilter: true,
    frameguard: true,
    hsts: true,
    noSniff: true,
    dnsPrefetchControl: true,
    ieNoOpen: true,
    referrerPolicy: true,
    expectCt: true
  }));
  
  app.get('/content', (req, res) => {
    res.send('Content page');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 12: Using helmet with detailed CSP configuration
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'trusted-scripts.com'],
        styleSrc: ["'self'", 'trusted-styles.com'],
        imgSrc: ["'self'", 'trusted-images.com', 'data:'],
        connectSrc: ["'self'", 'api.trusted-domain.com'],
        fontSrc: ["'self'", 'trusted-fonts.com'],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    }
  }));
  
  app.listen(3000);
}
// {/fact}

// Good Case 13: Using helmet with proper HSTS and frameguard configuration
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet({
    hsts: {
      maxAge: 15552000, // 180 days
      includeSubDomains: true,
      preload: true
    },
    frameguard: {
      action: 'sameorigin'
    }
  }));
  
  app.get('/secure-frame', (req, res) => {
    res.send('Secure frame content');
  });
  
  app.listen(3000);
}
// {/fact}

// Good Case 14: Using helmet with proper configuration in an Express router
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_14() {
  const app = express();
  const router = express.Router();
  
  // ok: javascript-helmet-security-header-disabled
  router.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"]
      }
    },
    xssFilter: true,
    noSniff: true
  }));
  
  router.get('/admin', (req, res) => {
    res.send('Admin panel');
  });
  
  app.use('/dashboard', router);
  app.listen(3000);
}
// {/fact}

// Good Case 15: Using helmet with proper configuration in a modular setup
// {fact rule=protection-mechanism-failure@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  const helmetConfig = {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'cdn.example.com'],
        styleSrc: ["'self'", 'cdn.example.com'],
        imgSrc: ["'self'", 'img.example.com', 'data:'],
        connectSrc: ["'self'", 'api.example.com']
      }
    },
    frameguard: {
      action: 'deny'
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true
    },
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin'
    }
  };
  
  // ok: javascript-helmet-security-header-disabled
  app.use(helmet(helmetConfig));
  
  app.get('/', (req, res) => {
    res.send('Home page with proper security headers');
  });
  
  app.listen(3000);
}
// {/fact}