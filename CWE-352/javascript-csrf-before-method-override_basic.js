const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const methodOverride = require('method-override');
const csrf = require('csurf');

// True Positive Examples (Vulnerable Code)

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser('secret'));
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // ruleid: javascript-csrf-before-method-override
  app.use(csrf({ cookie: true }));
  app.use(methodOverride('_method'));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  // Basic middleware setup
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'session secret', resave: false, saveUninitialized: false }));
  
  // ruleid: javascript-csrf-before-method-override
  app.use(csrf());
  app.use(methodOverride(function(req, res) {
    if (req.body && typeof req.body === 'object' && '_method' in req.body) {
      const method = req.body._method;
      delete req.body._method;
      return method;
    }
  }));
  
  app.listen(8080);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  const csrfProtection = csrf({ cookie: true });
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  
  // ruleid: javascript-csrf-before-method-override
  app.use(csrfProtection);
  app.use(methodOverride('X-HTTP-Method-Override'));
  
  app.post('/api/users', function(req, res) {
    res.send('User created');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  // Configure middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.use(session({
    secret: 'session key',
    resave: false,
    saveUninitialized: false
  }));
  
  // ruleid: javascript-csrf-before-method-override
  app.use(csrf({ cookie: { secure: true, httpOnly: true } }));
  app.use(methodOverride(function(req) {
    if (req.headers['x-http-method']) {
      return req.headers['x-http-method'];
    }
    return null;
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  const router = express.Router();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
  
  // ruleid: javascript-csrf-before-method-override
  router.use(csrf());
  router.use(methodOverride('_method'));
  
  app.use('/api', router);
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // ruleid: javascript-csrf-before-method-override
  app.use('/admin', csrf({ cookie: true }));
  app.use('/admin', methodOverride('_method'));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  const csrfMiddleware = csrf({ cookie: true });
  const methodOverrideMiddleware = methodOverride('_method');
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret key', resave: false, saveUninitialized: true }));
  
  // ruleid: javascript-csrf-before-method-override
  app.use(csrfMiddleware);
  app.use(methodOverrideMiddleware);
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
  
  const middlewares = [
    // ruleid: javascript-csrf-before-method-override
    csrf({ cookie: true }),
    methodOverride('_method')
  ];
  
  app.use(middlewares);
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  if (process.env.NODE_ENV === 'production') {
    // ruleid: javascript-csrf-before-method-override
    app.use(csrf());
    app.use(methodOverride('_method'));
  }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
  
  function setupSecurity() {
    // ruleid: javascript-csrf-before-method-override
    app.use(csrf({ cookie: true }));
    app.use(methodOverride(function(req) {
      if (req.body && typeof req.body === 'object' && '_method' in req.body) {
        return req.body._method;
      }
    }));
  }
  
  setupSecurity();
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const router1 = express.Router();
  const router2 = express.Router();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
  
  // ruleid: javascript-csrf-before-method-override
  router1.use(csrf());
  router1.use(methodOverride('X-HTTP-Method'));
  
  app.use('/api/v1', router1);
  app.use('/api/v2', router2);
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
  
  const csrfProtection = csrf({ cookie: true });
  const methodOverrider = methodOverride('_method');
  
  // ruleid: javascript-csrf-before-method-override
  app.use('/admin', [csrfProtection, methodOverrider]);
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  const securityMiddleware = [
    // ruleid: javascript-csrf-before-method-override
    csrf({ cookie: { secure: true } }),
    methodOverride('_method')
  ];
  
  app.use('/secure', securityMiddleware);
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret key', resave: false, saveUninitialized: false }));
  
  const configureMiddleware = (app) => {
    // ruleid: javascript-csrf-before-method-override
    app.use(csrf());
    app.use(methodOverride('_method'));
  };
  
  configureMiddleware(app);
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  const csrfOpts = { cookie: true };
  const methodOpts = '_method';
  
  // ruleid: javascript-csrf-before-method-override
  app.use(csrf(csrfOpts));
  app.use(methodOverride(methodOpts));
  
  app.listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser('secret'));
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // ok: javascript-csrf-before-method-override
  app.use(methodOverride('_method'));
  app.use(csrf({ cookie: true }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // Basic middleware setup
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'session secret', resave: false, saveUninitialized: false }));
  
  // ok: javascript-csrf-before-method-override
  app.use(methodOverride(function(req, res) {
    if (req.body && typeof req.body === 'object' && '_method' in req.body) {
      const method = req.body._method;
      delete req.body._method;
      return method;
    }
  }));
  app.use(csrf());
  
  app.listen(8080);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_3() {
  const app = express();
  const csrfProtection = csrf({ cookie: true });
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  
  // ok: javascript-csrf-before-method-override
  app.use(methodOverride('X-HTTP-Method-Override'));
  app.use(csrfProtection);
  
  app.post('/api/users', function(req, res) {
    res.send('User created');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  // Configure middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.use(session({
    secret: 'session key',
    resave: false,
    saveUninitialized: false
  }));
  
  // ok: javascript-csrf-before-method-override
  app.use(methodOverride(function(req) {
    if (req.headers['x-http-method']) {
      return req.headers['x-http-method'];
    }
    return null;
  }));
  app.use(csrf({ cookie: { secure: true, httpOnly: true } }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_5() {
  const app = express();
  const router = express.Router();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
  
  // ok: javascript-csrf-before-method-override
  router.use(methodOverride('_method'));
  router.use(csrf());
  
  app.use('/api', router);
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // ok: javascript-csrf-before-method-override
  app.use('/admin', methodOverride('_method'));
  app.use('/admin', csrf({ cookie: true }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_7() {
  const app = express();
  const csrfMiddleware = csrf({ cookie: true });
  const methodOverrideMiddleware = methodOverride('_method');
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret key', resave: false, saveUninitialized: true }));
  
  // ok: javascript-csrf-before-method-override
  app.use(methodOverrideMiddleware);
  app.use(csrfMiddleware);
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
  
  const middlewares = [
    // ok: javascript-csrf-before-method-override
    methodOverride('_method'),
    csrf({ cookie: true })
  ];
  
  app.use(middlewares);
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  if (process.env.NODE_ENV === 'production') {
    // ok: javascript-csrf-before-method-override
    app.use(methodOverride('_method'));
    app.use(csrf());
  }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
  
  function setupSecurity() {
    // ok: javascript-csrf-before-method-override
    app.use(methodOverride(function(req) {
      if (req.body && typeof req.body === 'object' && '_method' in req.body) {
        return req.body._method;
      }
    }));
    app.use(csrf({ cookie: true }));
  }
  
  setupSecurity();
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // Using a different approach - not using methodOverride at all
  // ok: javascript-csrf-before-method-override
  app.use(csrf({ cookie: true }));
  
  // Manually handle method overrides in routes
  app.post('/resource', function(req, res) {
    const method = req.body._method || 'post';
    if (method.toLowerCase() === 'put') {
      // Handle PUT logic
      res.send('Resource updated');
    } else if (method.toLowerCase() === 'delete') {
      // Handle DELETE logic
      res.send('Resource deleted');
    } else {
      // Handle POST logic
      res.send('Resource created');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
  
  // ok: javascript-csrf-before-method-override
  // Using separate routers with correct middleware order
  const apiRouter = express.Router();
  apiRouter.use(methodOverride('_method'));
  apiRouter.use(csrf({ cookie: true }));
  
  app.use('/api', apiRouter);
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // ok: javascript-csrf-before-method-override
  // Using a different pattern - separate middleware for different routes
  app.use('/api', methodOverride('_method'));
  app.use('/api', csrf({ cookie: true }));
  
  app.use('/admin', methodOverride('X-HTTP-Method'));
  app.use('/admin', csrf({ cookie: { secure: true } }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret key', resave: false, saveUninitialized: false }));
  
  // ok: javascript-csrf-before-method-override
  // Using a different approach - custom middleware that handles both method override and CSRF
  app.use(function(req, res, next) {
    // First handle method override
    if (req.body && typeof req.body === 'object' && '_method' in req.body) {
      req.method = req.body._method.toUpperCase();
      delete req.body._method;
    }
    
    // Then proceed to next middleware (which can include CSRF)
    next();
  });
  
  app.use(csrf());
  app.listen(3000);
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // ok: javascript-csrf-before-method-override
  // Using a combined middleware approach with correct order
  const securityMiddleware = [
    methodOverride('_method'),
    csrf({ cookie: true })
  ];
  
  app.use(securityMiddleware);
  app.listen(3000);
}
// {/fact}