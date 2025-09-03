import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { Request, Response } from 'express';
import * as http from 'http';
import * as https from 'https';
import { CookieOptions } from 'express';
import { NextFunction } from 'express';

// True Positive Examples (Vulnerable Code)

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(cookieParser());
  
  app.get('/login', (req: Request, res: Response) => {
    // ruleid: typescript-same-site-cookie
    res.cookie('authToken', 'abc123', {
      httpOnly: true,
      secure: true
      // Missing sameSite attribute for sensitive cookie
    });
    res.send('Logged in');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.post('/authenticate', (req: Request, res: Response) => {
    // ruleid: typescript-same-site-cookie
    res.cookie('sessionId', '12345', {
      maxAge: 3600000,
      secure: true,
      httpOnly: true,
      sameSite: 'none' // Using 'none' without proper justification is insecure
    });
    res.json({ status: 'success' });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/dashboard', (req: Request, res: Response) => {
    const cookieOptions: CookieOptions = {
      httpOnly: true,
      secure: true
    };
    // ruleid: typescript-same-site-cookie
    res.cookie('userAuth', req.query.token as string, cookieOptions);
    res.send('Dashboard loaded');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/api/login') {
      // ruleid: typescript-same-site-cookie
      res.cookie('apiKey', generateApiKey(), {
        maxAge: 86400000,
        secure: true
      });
    }
    next();
  });
  
  function generateApiKey(): string {
    return Math.random().toString(36).substring(2);
  }
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/payment', (req: Request, res: Response) => {
    // ruleid: typescript-same-site-cookie
    res.cookie('paymentSession', 'payment_' + Date.now(), {
      httpOnly: true,
      secure: true,
      sameSite: undefined // Explicitly set to undefined, which defaults to no sameSite protection
    });
    res.redirect('/confirmation');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: {
      // ruleid: typescript-same-site-cookie
      secure: true,
      httpOnly: true
      // Missing sameSite attribute in session cookie configuration
    }
  }));
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/remember-me', (req: Request, res: Response) => {
    const userId = '12345';
    // ruleid: typescript-same-site-cookie
    res.cookie('rememberMe', userId, {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      // Missing sameSite
    });
    res.send('Preference saved');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.post('/oauth/callback', (req: Request, res: Response) => {
    // ruleid: typescript-same-site-cookie
    res.cookie('oauth_token', req.body.token, {
      secure: true,
      sameSite: 'none', // Using 'none' for sensitive authentication token
      httpOnly: true
    });
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/set-preferences', (req: Request, res: Response) => {
    const cookieConfig = {
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
      secure: true,
      httpOnly: true
    };
    // ruleid: typescript-same-site-cookie
    res.cookie('userPrefs', JSON.stringify({ theme: 'dark', fontSize: 'large' }), cookieConfig);
    res.send('Preferences updated');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/2fa/verify', (req: Request, res: Response) => {
    if (verifyTwoFactor(req.body.code)) {
      // ruleid: typescript-same-site-cookie
      res.cookie('twoFactorVerified', 'true', {
        maxAge: 3600000,
        secure: true,
        httpOnly: true
        // Missing sameSite for security-critical cookie
      });
      res.json({ verified: true });
    }
  });
  
  function verifyTwoFactor(code: string): boolean {
    return code === '123456'; // Simplified for example
  }
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/api/user-data', (req: Request, res: Response) => {
    const userData = { name: 'John', role: 'admin' };
    // ruleid: typescript-same-site-cookie
    res.cookie('userData', JSON.stringify(userData), {
      secure: true,
      httpOnly: false // Allows JavaScript access, but still needs sameSite protection
    });
    res.json(userData);
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.post('/reset-password', (req: Request, res: Response) => {
    const token = generateResetToken();
    // ruleid: typescript-same-site-cookie
    res.cookie('resetToken', token, {
      maxAge: 3600000, // 1 hour
      secure: true,
      httpOnly: true
      // Missing sameSite for security-sensitive operation
    });
    res.redirect('/reset-password-form');
  });
  
  function generateResetToken(): string {
    return 'reset_' + Date.now();
  }
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/checkout', (req: Request, res: Response) => {
    // ruleid: typescript-same-site-cookie
    res.cookie('cartId', req.query.cartId as string, {
      secure: true,
      httpOnly: true,
      sameSite: 'none' // Using 'none' for a shopping cart ID
    });
    res.render('checkout');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const originalSetCookie = res.cookie;
    res.cookie = function(name: string, value: string, options?: CookieOptions) {
      const secureOptions = { ...options, secure: true, httpOnly: true };
      // ruleid: typescript-same-site-cookie
      return originalSetCookie.call(this, name, value, secureOptions);
      // Custom wrapper doesn't add sameSite protection
    };
    next();
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.post('/subscribe', (req: Request, res: Response) => {
    // ruleid: typescript-same-site-cookie
    res.cookie('subscriptionId', 'sub_' + Date.now(), {
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
      secure: true,
      httpOnly: true,
      sameSite: '' // Empty string is equivalent to no sameSite protection
    });
    res.send('Subscription successful');
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(cookieParser());
  
  app.get('/login', (req: Request, res: Response) => {
    // ok: typescript-same-site-cookie
    res.cookie('authToken', 'abc123', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' // Properly set sameSite to strict for authentication
    });
    res.send('Logged in');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/authenticate', (req: Request, res: Response) => {
    // ok: typescript-same-site-cookie
    res.cookie('sessionId', '12345', {
      maxAge: 3600000,
      secure: true,
      httpOnly: true,
      sameSite: 'lax' // Using 'lax' which is a good default for most applications
    });
    res.json({ status: 'success' });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/dashboard', (req: Request, res: Response) => {
    const cookieOptions: CookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' // Properly set sameSite to strict
    };
    // ok: typescript-same-site-cookie
    res.cookie('userAuth', req.query.token as string, cookieOptions);
    res.send('Dashboard loaded');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/api/login') {
      // ok: typescript-same-site-cookie
      res.cookie('apiKey', generateApiKey(), {
        maxAge: 86400000,
        secure: true,
        httpOnly: true,
        sameSite: 'strict'
      });
    }
    next();
  });
  
  function generateApiKey(): string {
    return Math.random().toString(36).substring(2);
  }
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/payment', (req: Request, res: Response) => {
    // ok: typescript-same-site-cookie
    res.cookie('paymentSession', 'payment_' + Date.now(), {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' // Using strict for payment-related cookies
    });
    res.redirect('/confirmation');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_6() {
  const app = express();
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: {
      // ok: typescript-same-site-cookie
      secure: true,
      httpOnly: true,
      sameSite: 'lax' // Properly set sameSite in session cookie configuration
    }
  }));
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/remember-me', (req: Request, res: Response) => {
    const userId = '12345';
    // ok: typescript-same-site-cookie
    res.cookie('rememberMe', userId, {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax' // Using lax for better user experience with security
    });
    res.send('Preference saved');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.post('/oauth/callback', (req: Request, res: Response) => {
    // For cross-origin OAuth flows, 'none' might be necessary but should be used with secure: true
    // ok: typescript-same-site-cookie
    res.cookie('oauth_token', req.body.token, {
      secure: true, // Must be true when sameSite is 'none'
      sameSite: 'none',
      httpOnly: true
    });
    
    // Additional security measures to mitigate CSRF risk
    const csrfToken = generateCsrfToken();
    res.cookie('csrf_token', csrfToken, {
      secure: true,
      httpOnly: false, // Accessible to JavaScript for CSRF validation
      sameSite: 'none'
    });
    
    res.redirect('/dashboard?csrf=' + csrfToken);
  });
  
  function generateCsrfToken(): string {
    return 'csrf_' + Date.now();
  }
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/set-preferences', (req: Request, res: Response) => {
    const cookieConfig = {
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
      secure: true,
      httpOnly: true,
      sameSite: 'lax' // Using lax for user preferences
    };
    // ok: typescript-same-site-cookie
    res.cookie('userPrefs', JSON.stringify({ theme: 'dark', fontSize: 'large' }), cookieConfig);
    res.send('Preferences updated');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/2fa/verify', (req: Request, res: Response) => {
    if (verifyTwoFactor(req.body.code)) {
      // ok: typescript-same-site-cookie
      res.cookie('twoFactorVerified', 'true', {
        maxAge: 3600000,
        secure: true,
        httpOnly: true,
        sameSite: 'strict' // Using strict for security-critical cookie
      });
      res.json({ verified: true });
    }
  });
  
  function verifyTwoFactor(code: string): boolean {
    return code === '123456'; // Simplified for example
  }
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // Using a non-sensitive cookie that doesn't need protection
  app.get('/api/public-data', (req: Request, res: Response) => {
    // ok: typescript-same-site-cookie
    res.cookie('lastVisit', new Date().toISOString(), {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: false,
      secure: false
      // sameSite not needed for non-sensitive, public information
    });
    res.json({ publicData: 'This is public information' });
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.post('/reset-password', (req: Request, res: Response) => {
    const token = generateResetToken();
    // ok: typescript-same-site-cookie
    res.cookie('resetToken', token, {
      maxAge: 3600000, // 1 hour
      secure: true,
      httpOnly: true,
      sameSite: 'strict' // Using strict for security-sensitive operation
    });
    res.redirect('/reset-password-form');
  });
  
  function generateResetToken(): string {
    return 'reset_' + Date.now();
  }
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/checkout', (req: Request, res: Response) => {
    // ok: typescript-same-site-cookie
    res.cookie('cartId', req.query.cartId as string, {
      secure: true,
      httpOnly: true,
      sameSite: 'lax' // Using 'lax' for a shopping cart ID is appropriate
    });
    res.render('checkout');
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    const originalSetCookie = res.cookie;
    res.cookie = function(name: string, value: string, options?: CookieOptions) {
      const secureOptions = { 
        ...options, 
        secure: true, 
        httpOnly: true,
        sameSite: options?.sameSite || 'lax' // Default to 'lax' if not specified
      };
      // ok: typescript-same-site-cookie
      return originalSetCookie.call(this, name, value, secureOptions);
    };
    next();
  });
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.post('/subscribe', (req: Request, res: Response) => {
    // ok: typescript-same-site-cookie
    res.cookie('subscriptionId', 'sub_' + Date.now(), {
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
      secure: true,
      httpOnly: true,
      sameSite: 'lax' // Properly set sameSite
    });
    res.send('Subscription successful');
  });
}
// {/fact}