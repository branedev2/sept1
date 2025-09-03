import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import csurf from 'csurf';
import bodyParser from 'body-parser';
import { Request, Response, NextFunction } from 'express';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import cors from 'cors';
import { CsrfToken } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';

// True Positives (Vulnerable Code)

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true
  }));
  
  // ruleid: typescript-csrf-disabled
  app.use(csurf({ cookie: true, ignoreMethods: ['POST', 'PUT', 'DELETE'] }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: false }));
  
  const csrfProtection = csurf({ cookie: true });
  
  app.get('/form', csrfProtection, (req: Request, res: Response) => {
    res.render('form', { csrfToken: req.csrfToken() });
  });
  
  // ruleid: typescript-csrf-disabled
  app.post('/process', (req: Request, res: Response) => {
    // CSRF protection disabled for this route
    res.send('Data processed');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  const csurfMiddleware = csurf({ cookie: true, ignoreMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'] });
  
  app.use(csurfMiddleware);
  app.use(express.json());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
async function bad_case_4() {
  const app = await NestFactory.create(AppModule);
  
  // ruleid: typescript-csrf-disabled
  app.use(helmet({ csrf: false }));
  
  await app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  app.use(bodyParser.json());
  
  const csrfMiddleware = csurf({ cookie: true });
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-csrf-disabled
    if (req.path.startsWith('/api/')) {
      next(); // Skip CSRF for API routes
    } else {
      csrfMiddleware(req, res, next);
    }
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const config = {
    enableCsrf: false
  };
  
  // ruleid: typescript-csrf-disabled
  if (!config.enableCsrf) {
    console.log('CSRF protection disabled');
  } else {
    app.use(csurf({ cookie: true }));
  }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
async function bad_case_7() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  
  // ruleid: typescript-csrf-disabled
  const csrfEnabled = configService.get('CSRF_ENABLED', 'false') === 'true';
  
  if (csrfEnabled) {
    app.use(csurf());
  }
  
  await app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  const csrfOptions = {
    cookie: {
      secure: false,
      httpOnly: false
    },
    ignoreMethods: ['POST']
  };
  
  app.use(csurf(csrfOptions));
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Bypass CSRF token validation
    req.csrfToken = () => 'fake-csrf-token';
    next();
  });
  
  app.use(csurf({ cookie: true }));
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  const disableCsrf = process.env.NODE_ENV === 'development';
  
  if (!disableCsrf) {
    app.use(csurf({ cookie: true }));
  }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  app.use(cors({
    origin: '*',
    credentials: true
  }));
  
  // No CSRF protection added
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  const csrfProtection = {
    enabled: false,
    options: { cookie: true }
  };
  
  if (csrfProtection.enabled) {
    app.use(csurf(csrfProtection.options));
  }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  app.disable('csrf-protection');
  
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  const csrfMiddleware = csurf({ 
    cookie: true,
    value: (req: Request) => {
      return req.headers['x-custom-csrf-token'] as string || '';
    }
  });
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.headers['bypass-csrf'] === 'true') {
      next();
    } else {
      csrfMiddleware(req, res, next);
    }
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // ruleid: typescript-csrf-disabled
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.cookie('XSRF-TOKEN', 'static-token', { httpOnly: false });
    next();
  });
  
  // No actual CSRF validation implemented
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true
  }));
  
  // ok: typescript-csrf-disabled
  app.use(csurf({ cookie: true }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_2() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: false }));
  
  // ok: typescript-csrf-disabled
  const csrfProtection = csurf({ cookie: true });
  
  app.get('/form', csrfProtection, (req: Request, res: Response) => {
    res.render('form', { csrfToken: req.csrfToken() });
  });
  
  app.post('/process', csrfProtection, (req: Request, res: Response) => {
    res.send('Data processed with CSRF protection');
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // ok: typescript-csrf-disabled
  app.use(csurf({ cookie: { sameSite: 'strict', secure: true } }));
  app.use(express.json());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
async function good_case_4() {
  const app = await NestFactory.create(AppModule);
  
  // ok: typescript-csrf-disabled
  app.use(helmet());
  app.use(csurf());
  
  await app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_5() {
  const app = express();
  app.use(bodyParser.json());
  
  // ok: typescript-csrf-disabled
  const csrfMiddleware = csurf({ cookie: true });
  app.use(csrfMiddleware);
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.locals.csrfToken = req.csrfToken();
    next();
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const config = {
    enableCsrf: true
  };
  
  // ok: typescript-csrf-disabled
  if (config.enableCsrf) {
    app.use(csurf({ cookie: true }));
  }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
async function good_case_7() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  
  // ok: typescript-csrf-disabled
  const csrfEnabled = configService.get('CSRF_ENABLED', 'true') === 'true';
  
  if (csrfEnabled) {
    app.use(csurf());
  }
  
  await app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // ok: typescript-csrf-disabled
  const csrfOptions = {
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: 'strict'
    }
  };
  
  app.use(csurf(csrfOptions));
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.use(cookieParser());
  
  // ok: typescript-csrf-disabled
  app.use(csurf({ cookie: true }));
  
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err.code === 'EBADCSRFTOKEN') {
      return res.status(403).send('Invalid CSRF token');
    }
    next(err);
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // ok: typescript-csrf-disabled
  const enableCsrf = process.env.NODE_ENV !== 'test';
  
  if (enableCsrf) {
    app.use(csurf({ cookie: true }));
  }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // ok: typescript-csrf-disabled
  app.use(cors({
    origin: 'https://trusted-domain.com',
    credentials: true
  }));
  
  app.use(csurf({ cookie: true }));
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // ok: typescript-csrf-disabled
  const csrfProtection = {
    enabled: true,
    options: { 
      cookie: { 
        secure: true,
        sameSite: 'strict'
      }
    }
  };
  
  if (csrfProtection.enabled) {
    app.use(csurf(csrfProtection.options));
  }
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // ok: typescript-csrf-disabled
  app.enable('csrf-protection');
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(csurf());
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // ok: typescript-csrf-disabled
  app.use(csurf({
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    }
  }));
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.locals.csrfToken = req.csrfToken();
    next();
  });
}
// {/fact}

// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_15() {
  const app = express();
  app.use(cookieParser());
  
  // ok: typescript-csrf-disabled
  const csrfProtection = csurf({ cookie: true });
  
  app.all('/api/*', csrfProtection, (req: Request, res: Response, next: NextFunction) => {
    next();
  });
  
  app.get('/csrf-token', csrfProtection, (req: Request, res: Response) => {
    res.json({ csrfToken: req.csrfToken() });
  });
}
// {/fact}