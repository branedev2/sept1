// Import necessary libraries
import express from 'express';
import { Request, Response } from 'express';
import { CookieOptions } from 'express';
import * as http from 'http';
import * as cookie from 'cookie';
import cookieParser from 'cookie-parser';
import { NextFunction } from 'express';
import { ServerResponse } from 'http';

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.get('/set-cookie', (req: Request, res: Response) => {
    // ruleid: typescript-non-httponly-cookie
    res.cookie('sessionId', 'abc123', { maxAge: 900000 });
    res.send('Cookie has been set');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  app.get('/login', (req: Request, res: Response) => {
    // Authentication logic here
    // ruleid: typescript-non-httponly-cookie
    res.cookie('authToken', 'xyz789', { 
      secure: true,
      maxAge: 3600000
    });
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  app.post('/remember-me', (req: Request, res: Response) => {
    const rememberMe = req.body.rememberMe === 'true';
    if (rememberMe) {
      // ruleid: typescript-non-httponly-cookie
      res.cookie('rememberUser', 'true', { 
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });
    }
    res.send('Preferences updated');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  app.get('/theme', (req: Request, res: Response) => {
    const theme = req.query.theme || 'light';
    // ruleid: typescript-non-httponly-cookie
    res.cookie('userTheme', theme as string, {
      path: '/',
      maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
    });
    res.send(`Theme set to ${theme}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  app.get('/set-language', (req: Request, res: Response) => {
    const lang = req.query.lang || 'en';
    // ruleid: typescript-non-httponly-cookie
    res.cookie('language', lang as string, { 
      secure: true,
      sameSite: 'strict'
    });
    res.redirect('/home');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  const options: CookieOptions = {
    maxAge: 86400000, // 24 hours
    secure: true,
    sameSite: 'lax'
  };
  
  const app = express();
  app.get('/tracking', (req: Request, res: Response) => {
    // ruleid: typescript-non-httponly-cookie
    res.cookie('trackingId', generateTrackingId(), options);
    res.send('Tracking enabled');
  });
  
  function generateTrackingId(): string {
    return Math.random().toString(36).substring(2, 15);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const response = new ServerResponse({} as any);
  // ruleid: typescript-non-httponly-cookie
  response.setHeader('Set-Cookie', 'sessionId=123456; Path=/; Secure');
  response.end('Cookie set');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  app.use(cookieParser());
  
  app.get('/cart', (req: Request, res: Response) => {
    const cartId = req.cookies.cartId || createNewCart();
    // ruleid: typescript-non-httponly-cookie
    res.cookie('cartId', cartId, {
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    res.send('Cart updated');
  });
  
  function createNewCart(): string {
    return `cart_${Date.now()}`;
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/api/settings', (req: Request, res: Response) => {
    const userId = authenticateUser(req);
    if (userId) {
      // ruleid: typescript-non-httponly-cookie
      res.cookie('userId', userId, { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Unauthorized' });
    }
  });
  
  function authenticateUser(req: Request): string | null {
    // Authentication logic
    return 'user123';
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/logout', (req: Request, res: Response) => {
    // ruleid: typescript-non-httponly-cookie
    res.cookie('sessionId', '', { 
      expires: new Date(0)
    });
    res.redirect('/login');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/visit', (req: Request, res: Response) => {
    const visitCount = parseInt(req.cookies.visits || '0') + 1;
    // ruleid: typescript-non-httponly-cookie
    res.cookie('visits', visitCount.toString(), {
      maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
    });
    res.send(`You've visited this site ${visitCount} times`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ruleid: typescript-non-httponly-cookie
    res.cookie('requestId', generateRequestId(), {
      maxAge: 3600000 // 1 hour
    });
    next();
  });
  
  function generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/survey', (req: Request, res: Response) => {
    const cookieOptions: CookieOptions = {
      maxAge: 30 * 60 * 1000, // 30 minutes
      httpOnly: false, // Explicitly set to false
      secure: true
    };
    
    // ruleid: typescript-non-httponly-cookie
    res.cookie('surveyShown', 'true', cookieOptions);
    res.send('Survey data saved');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/promo', (req: Request, res: Response) => {
    const promoCode = req.query.code || 'DEFAULT';
    const cookieOpts = {};
    
    // ruleid: typescript-non-httponly-cookie
    res.cookie('promoCode', promoCode as string, cookieOpts);
    res.send('Promo applied');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/analytics', (req: Request, res: Response) => {
    const cookieValue = JSON.stringify({
      referrer: req.headers.referer || '',
      timestamp: Date.now()
    });
    
    // ruleid: typescript-non-httponly-cookie
    res.cookie('analyticsData', cookieValue, {
      secure: true,
      sameSite: 'none'
    });
    res.send('Analytics tracking enabled');
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.get('/set-cookie', (req: Request, res: Response) => {
    // ok: typescript-non-httponly-cookie
    res.cookie('sessionId', 'abc123', { 
      httpOnly: true,
      maxAge: 900000 
    });
    res.send('Cookie has been set securely');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const app = express();
  app.get('/login', (req: Request, res: Response) => {
    // Authentication logic here
    // ok: typescript-non-httponly-cookie
    res.cookie('authToken', 'xyz789', { 
      httpOnly: true,
      secure: true,
      maxAge: 3600000
    });
    res.redirect('/dashboard');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  const app = express();
  app.post('/remember-me', (req: Request, res: Response) => {
    const rememberMe = req.body.rememberMe === 'true';
    if (rememberMe) {
      // ok: typescript-non-httponly-cookie
      res.cookie('rememberUser', 'true', { 
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });
    }
    res.send('Preferences updated securely');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const app = express();
  app.get('/theme', (req: Request, res: Response) => {
    const theme = req.query.theme || 'light';
    
    // For theme preference, we need JavaScript access, so we set a non-httpOnly cookie for UI
    res.cookie('userThemeDisplay', theme as string);
    
    // But we also set a secure cookie for server-side verification
    // ok: typescript-non-httponly-cookie
    res.cookie('userThemeVerified', theme as string, {
      httpOnly: true,
      path: '/',
      maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
    });
    
    res.send(`Theme set to ${theme}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const app = express();
  app.get('/set-language', (req: Request, res: Response) => {
    const lang = req.query.lang || 'en';
    // ok: typescript-non-httponly-cookie
    res.cookie('language', lang as string, { 
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    });
    res.redirect('/home');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  const options: CookieOptions = {
    httpOnly: true,
    maxAge: 86400000, // 24 hours
    secure: true,
    sameSite: 'lax'
  };
  
  const app = express();
  app.get('/tracking', (req: Request, res: Response) => {
    // ok: typescript-non-httponly-cookie
    res.cookie('trackingId', generateTrackingId(), options);
    res.send('Tracking enabled securely');
  });
  
  function generateTrackingId(): string {
    return Math.random().toString(36).substring(2, 15);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const response = new ServerResponse({} as any);
  // ok: typescript-non-httponly-cookie
  response.setHeader('Set-Cookie', 'sessionId=123456; Path=/; Secure; HttpOnly');
  response.end('Cookie set securely');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  const app = express();
  app.use(cookieParser());
  
  app.get('/cart', (req: Request, res: Response) => {
    const cartId = req.cookies.cartId || createNewCart();
    // ok: typescript-non-httponly-cookie
    res.cookie('cartId', cartId, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    res.send('Cart updated securely');
  });
  
  function createNewCart(): string {
    return `cart_${Date.now()}`;
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/api/settings', (req: Request, res: Response) => {
    const userId = authenticateUser(req);
    if (userId) {
      // ok: typescript-non-httponly-cookie
      res.cookie('userId', userId, { 
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Unauthorized' });
    }
  });
  
  function authenticateUser(req: Request): string | null {
    // Authentication logic
    return 'user123';
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/logout', (req: Request, res: Response) => {
    // ok: typescript-non-httponly-cookie
    res.cookie('sessionId', '', { 
      httpOnly: true,
      expires: new Date(0)
    });
    res.redirect('/login');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/visit', (req: Request, res: Response) => {
    const visitCount = parseInt(req.cookies.visits || '0') + 1;
    
    // For display purposes (client-side access needed)
    res.cookie('visitsDisplay', visitCount.toString());
    
    // For server-side tracking (secure)
    // ok: typescript-non-httponly-cookie
    res.cookie('visitsSecure', visitCount.toString(), {
      httpOnly: true,
      maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
    });
    
    res.send(`You've visited this site ${visitCount} times`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    // ok: typescript-non-httponly-cookie
    res.cookie('requestId', generateRequestId(), {
      httpOnly: true,
      maxAge: 3600000 // 1 hour
    });
    next();
  });
  
  function generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/survey', (req: Request, res: Response) => {
    const cookieOptions: CookieOptions = {
      httpOnly: true,
      maxAge: 30 * 60 * 1000, // 30 minutes
      secure: true
    };
    
    // ok: typescript-non-httponly-cookie
    res.cookie('surveyShown', 'true', cookieOptions);
    res.send('Survey data saved securely');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/promo', (req: Request, res: Response) => {
    const promoCode = req.query.code || 'DEFAULT';
    const cookieOpts: CookieOptions = {
      httpOnly: true,
      secure: true
    };
    
    // ok: typescript-non-httponly-cookie
    res.cookie('promoCode', promoCode as string, cookieOpts);
    res.send('Promo applied securely');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/analytics', (req: Request, res: Response) => {
    const cookieValue = JSON.stringify({
      referrer: req.headers.referer || '',
      timestamp: Date.now()
    });
    
    // ok: typescript-non-httponly-cookie
    res.cookie('analyticsData', cookieValue, {
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    });
    res.send('Analytics tracking enabled securely');
  });
}
// {/fact}