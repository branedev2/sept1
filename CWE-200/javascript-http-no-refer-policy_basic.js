const express = require('express');
const helmet = require('helmet');

// True Positive Examples (Vulnerable Code)

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: javascript-http-no-refer-policy
  app.use(helmet({
    referrerPolicy: false, // Disabling referrer policy completely
  }));
  
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: 'no-referrer-when-downgrade' // Using insecure policy
  }));
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  // ruleid: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: 'unsafe-url' // Using explicitly unsafe policy
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  const helmetConfig = {
    contentSecurityPolicy: true,
    xssFilter: true,
    // ruleid: javascript-http-no-refer-policy
    referrerPolicy: false
  };
  
  app.use(helmet(helmetConfig));
  app.get('/api', (req, res) => res.json({ success: true }));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  let securityConfig = {};
  
  if (process.env.NODE_ENV === 'production') {
    securityConfig = {
      // ruleid: javascript-http-no-refer-policy
      referrerPolicy: { policy: 'no-referrer-when-downgrade' }
    };
  }
  
  app.use(helmet(securityConfig));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const policies = ['strict-origin', 'unsafe-url'];
  const selectedPolicy = process.env.STRICT_MODE ? policies[0] : policies[1];
  
  // ruleid: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: selectedPolicy // Can be unsafe-url
  }));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  const config = require('./config');
  
  // ruleid: javascript-http-no-refer-policy
  app.use(helmet({
    referrerPolicy: {
      policy: config.referrerPolicy || 'unsafe-url' // Default to unsafe
    }
  }));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  function configureHelmet() {
    // ruleid: javascript-http-no-refer-policy
    return {
      referrerPolicy: false,
      contentSecurityPolicy: true
    };
  }
  
  app.use(helmet(configureHelmet()));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  const options = { policy: 'no-referrer-when-downgrade' };
  
  // ruleid: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy(options));
  
  app.get('/user/:id', (req, res) => {
    res.send(`User ID: ${req.params.id}`);
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  if (process.env.LEGACY_SUPPORT) {
    // ruleid: javascript-http-no-refer-policy
    app.use(helmet({
      referrerPolicy: {
        policy: ['unsafe-url']
      }
    }));
  } else {
    app.use(helmet());
  }
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const helmetMiddleware = helmet({
    // ruleid: javascript-http-no-refer-policy
    referrerPolicy: false
  });
  
  app.use(helmetMiddleware);
  app.use(express.json());
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  const policies = {
    secure: 'strict-origin-when-cross-origin',
    // ruleid: javascript-http-no-refer-policy
    insecure: 'unsafe-url'
  };
  
  app.use(helmet.referrerPolicy({
    policy: process.env.DEBUG ? policies.insecure : policies.secure
  }));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  const middlewares = [
    express.json(),
    express.urlencoded({ extended: true }),
    // ruleid: javascript-http-no-refer-policy
    helmet.referrerPolicy({ policy: 'no-referrer-when-downgrade' })
  ];
  
  middlewares.forEach(middleware => app.use(middleware));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const referrerPolicyOptions = {};
  
  // Empty options defaults to no-referrer-when-downgrade
  // ruleid: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy(referrerPolicyOptions));
  
  app.listen(8080);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  const helmetOptions = {};
  
  if (process.env.DISABLE_SECURITY) {
    // ruleid: javascript-http-no-refer-policy
    helmetOptions.referrerPolicy = false;
  }
  
  app.use(helmet(helmetOptions));
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: javascript-http-no-refer-policy
  app.use(helmet({
    referrerPolicy: { policy: 'no-referrer' }
  }));
  
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_2() {
  const app = express();
  // ok: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: 'same-origin'
  }));
  
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_3() {
  const app = express();
  // ok: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: 'strict-origin'
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_4() {
  const app = express();
  const helmetConfig = {
    contentSecurityPolicy: true,
    xssFilter: true,
    // ok: javascript-http-no-refer-policy
    referrerPolicy: { policy: 'origin' }
  };
  
  app.use(helmet(helmetConfig));
  app.get('/api', (req, res) => res.json({ success: true }));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_5() {
  const app = express();
  let securityConfig = {};
  
  if (process.env.NODE_ENV === 'production') {
    securityConfig = {
      // ok: javascript-http-no-refer-policy
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
    };
  }
  
  app.use(helmet(securityConfig));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const policies = ['strict-origin', 'same-origin'];
  const selectedPolicy = process.env.STRICT_MODE ? policies[0] : policies[1];
  
  // ok: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: selectedPolicy // Both options are secure
  }));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_7() {
  const app = express();
  const config = require('./config');
  
  // ok: javascript-http-no-refer-policy
  app.use(helmet({
    referrerPolicy: {
      policy: config.referrerPolicy || 'no-referrer' // Default to secure
    }
  }));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  function configureHelmet() {
    // ok: javascript-http-no-refer-policy
    return {
      referrerPolicy: { policy: 'origin-when-cross-origin' },
      contentSecurityPolicy: true
    };
  }
  
  app.use(helmet(configureHelmet()));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_9() {
  const app = express();
  const options = { policy: 'strict-origin-when-cross-origin' };
  
  // ok: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy(options));
  
  app.get('/user/:id', (req, res) => {
    res.send(`User ID: ${req.params.id}`);
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  if (process.env.LEGACY_SUPPORT) {
    // ok: javascript-http-no-refer-policy
    app.use(helmet({
      referrerPolicy: {
        policy: ['origin', 'same-origin']
      }
    }));
  } else {
    app.use(helmet());
  }
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const helmetMiddleware = helmet({
    // ok: javascript-http-no-refer-policy
    referrerPolicy: { policy: 'no-referrer' }
  });
  
  app.use(helmetMiddleware);
  app.use(express.json());
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_12() {
  const app = express();
  const policies = {
    secure: 'strict-origin-when-cross-origin',
    moreSecure: 'no-referrer'
  };
  
  // ok: javascript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: process.env.DEBUG ? policies.secure : policies.moreSecure
  }));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_13() {
  const app = express();
  const middlewares = [
    express.json(),
    express.urlencoded({ extended: true }),
    // ok: javascript-http-no-refer-policy
    helmet.referrerPolicy({ policy: ['no-referrer', 'strict-origin'] })
  ];
  
  middlewares.forEach(middleware => app.use(middleware));
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_14() {
  const app = express();
  // Using default helmet configuration which includes secure referrer policy
  // ok: javascript-http-no-refer-policy
  app.use(helmet());
  
  app.listen(8080);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_15() {
  const app = express();
  // ok: javascript-http-no-refer-policy
  app.use(helmet());
  app.use(express.json());
  
  // Adding additional security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
  });
}
// {/fact}