import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import methodOverride from 'method-override';

// True Positive Examples (Vulnerable Code)

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser('secret'));
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // ruleid: typescript-csrf-before-method-override
  app.use(express.csrf());
  app.use(express.methodOverride());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.use(session({ secret: 'some secret', resave: false, saveUninitialized: false }));
  
  // ruleid: typescript-csrf-before-method-override
  app.use(express.csrf());
  app.use(methodOverride('_method'));
  
  app.listen(8080);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  const router = express.Router();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'session secret' }));
  
  // ruleid: typescript-csrf-before-method-override
  app.use(express.csrf());
  setTimeout(() => {
    app.use(express.methodOverride());
  }, 0);
  
  app.use('/', router);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.use(express.static('public'));
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  
  // ruleid: typescript-csrf-before-method-override
  app.use(express.csrf());
  
  if (process.env.NODE_ENV === 'production') {
    app.use(express.methodOverride());
  } else {
    app.use(methodOverride());
  }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  const csrfProtection = express.csrf();
  const parseForm = bodyParser.urlencoded({ extended: false });
  
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat' }));
  
  // ruleid: typescript-csrf-before-method-override
  app.use(csrfProtection);
  app.use(express.methodOverride());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret key' }));
  
  const middlewares = [
    express.csrf(),
    // ruleid: typescript-csrf-before-method-override
    express.methodOverride()
  ];
  
  app.use(middlewares);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ruleid: typescript-csrf-before-method-override
  app.use('/api', express.csrf());
  app.use('/api', express.methodOverride());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  const router = express.Router();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ruleid: typescript-csrf-before-method-override
  router.use(express.csrf());
  router.use(express.methodOverride());
  
  app.use('/admin', router);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  const setupMiddleware = () => {
    // ruleid: typescript-csrf-before-method-override
    app.use(express.csrf());
    app.use(express.methodOverride());
  };
  
  setupMiddleware();
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  const csrfMiddleware = express.csrf();
  const methodOverrideMiddleware = express.methodOverride();
  
  // ruleid: typescript-csrf-before-method-override
  app.use(csrfMiddleware);
  app.use(methodOverrideMiddleware);
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  const middlewares = {
    csrf: express.csrf(),
    methodOverride: express.methodOverride()
  };
  
  // ruleid: typescript-csrf-before-method-override
  app.use(middlewares.csrf);
  app.use(middlewares.methodOverride);
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ruleid: typescript-csrf-before-method-override
  [express.csrf(), express.methodOverride()].forEach(middleware => {
    app.use(middleware);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  const applyMiddleware = (app: express.Application) => {
    // ruleid: typescript-csrf-before-method-override
    app.use(express.csrf());
    app.use(express.methodOverride());
  };
  
  applyMiddleware(app);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  if (process.env.ENABLE_SECURITY === 'true') {
    // ruleid: typescript-csrf-before-method-override
    app.use(express.csrf());
  }
  
  app.use(express.methodOverride());
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  const securityMiddlewares = [express.csrf()];
  const utilityMiddlewares = [express.methodOverride()];
  
  // ruleid: typescript-csrf-before-method-override
  securityMiddlewares.forEach(middleware => app.use(middleware));
  utilityMiddlewares.forEach(middleware => app.use(middleware));
  
  app.listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser('secret'));
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
  
  // ok: typescript-csrf-before-method-override
  app.use(express.methodOverride());
  app.use(express.csrf());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.use(session({ secret: 'some secret', resave: false, saveUninitialized: false }));
  
  // ok: typescript-csrf-before-method-override
  app.use(methodOverride('_method'));
  app.use(express.csrf());
  
  app.listen(8080);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_3() {
  const app = express();
  const router = express.Router();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'session secret' }));
  
  // ok: typescript-csrf-before-method-override
  app.use(express.methodOverride());
  app.use(express.csrf());
  
  app.use('/', router);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.use(express.static('public'));
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  
  // ok: typescript-csrf-before-method-override
  app.use(methodOverride());
  app.use(express.csrf());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_5() {
  const app = express();
  const csrfProtection = express.csrf();
  const parseForm = bodyParser.urlencoded({ extended: false });
  const methodOverrideMiddleware = express.methodOverride();
  
  app.use(cookieParser());
  app.use(session({ secret: 'keyboard cat' }));
  
  // ok: typescript-csrf-before-method-override
  app.use(methodOverrideMiddleware);
  app.use(csrfProtection);
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret key' }));
  
  const middlewares = [
    express.methodOverride(),
    // ok: typescript-csrf-before-method-override
    express.csrf()
  ];
  
  app.use(middlewares);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: typescript-csrf-before-method-override
  app.use('/api', express.methodOverride());
  app.use('/api', express.csrf());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_8() {
  const app = express();
  const router = express.Router();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: typescript-csrf-before-method-override
  router.use(express.methodOverride());
  router.use(express.csrf());
  
  app.use('/admin', router);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // Using a different CSRF middleware that doesn't have this issue
  app.use(express.methodOverride());
  // ok: typescript-csrf-before-method-override
  app.use(require('csurf')());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: typescript-csrf-before-method-override
  app.use(express.methodOverride());
  // Using a different approach for CSRF protection
  app.use((req, res, next) => {
    const token = req.csrfToken();
    res.locals.csrfToken = token;
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // Not using express.csrf() at all, using a different CSRF protection
  // ok: typescript-csrf-before-method-override
  app.use(express.methodOverride());
  app.use(require('csurf')({ cookie: true }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.use(express.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  const setupMiddleware = () => {
    // ok: typescript-csrf-before-method-override
    app.use(express.methodOverride());
    app.use(express.csrf());
  };
  
  setupMiddleware();
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  const csrfMiddleware = express.csrf();
  const methodOverrideMiddleware = express.methodOverride();
  
  // ok: typescript-csrf-before-method-override
  app.use(methodOverrideMiddleware);
  app.use(csrfMiddleware);
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // ok: typescript-csrf-before-method-override
  app.use(express.methodOverride());
  
  if (process.env.ENABLE_SECURITY === 'true') {
    app.use(express.csrf());
  }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'secret' }));
  
  // Using a completely different approach for CSRF protection
  // ok: typescript-csrf-before-method-override
  app.use(express.methodOverride());
  app.use((req, res, next) => {
    // Custom CSRF implementation
    const requestToken = req.headers['x-csrf-token'];
    const sessionToken = req.session.csrfToken;
    
    if (requestToken !== sessionToken) {
      return res.status(403).send('CSRF token validation failed');
    }
    
    next();
  });
  
  app.listen(3000);
}
// {/fact}