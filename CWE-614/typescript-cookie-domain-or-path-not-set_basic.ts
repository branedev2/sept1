import * as express from 'express';
import * as cookieParser from 'cookie-parser';
import * as http from 'http';
import * as https from 'https';
import * as cookie from 'cookie';
import { Request, Response } from 'express';

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1(req: express.Request, res: express.Response) {
    // Setting a cookie without domain or path
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('sessionId', 'abc123', { httpOnly: true, secure: true });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2(req: express.Request, res: express.Response) {
    // Setting a cookie with only secure and httpOnly flags
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('authToken', 'xyz789', { 
        httpOnly: true, 
        secure: true,
        maxAge: 3600000
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3(req: express.Request, res: express.Response) {
    // Setting multiple cookies without domain or path
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('userId', '12345');
    
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('role', 'admin');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4(req: express.Request, res: express.Response) {
    const options = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
    };
    
    // Missing domain and path despite other security settings
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('csrfToken', 'token123', options);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5(req: express.Request, res: express.Response) {
    // Using cookie serialization without domain or path
    const cookieStr = cookie.serialize('sessionId', 'abc123', {
        httpOnly: true,
        secure: true
    });
    
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.setHeader('Set-Cookie', cookieStr);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6(req: express.Request, res: express.Response) {
    // Setting cookie directly in header without domain or path
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.setHeader('Set-Cookie', 'authToken=xyz789; HttpOnly; Secure');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7(req: express.Request, res: express.Response) {
    // Setting cookie with expiration but no domain or path
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 1);
    
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('rememberMe', 'true', {
        expires: expiryDate,
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    app.use(cookieParser());
    
    app.get('/login', (req: Request, res: Response) => {
        // Setting authentication cookie without domain or path
        // ruleid: typescript-cookie-domain-or-path-not-set
        res.cookie('authToken', 'token123', { 
            httpOnly: true, 
            secure: true 
        });
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9(req: express.Request, res: express.Response) {
    // Conditional cookie setting without domain or path
    const isSecure = req.protocol === 'https';
    
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('preference', 'darkMode', {
        httpOnly: true,
        secure: isSecure
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10(req: express.Request, res: express.Response) {
    // Setting cookie with dynamic value but no domain or path
    const userId = req.params.id;
    
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('lastVisited', userId, {
        maxAge: 86400000,
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11(req: express.Request, res: express.Response) {
    // Setting cookie with sameSite but no domain or path
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('sessionId', 'abc123', {
        httpOnly: true,
        secure: true,
        sameSite: 'lax'
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12(req: express.Request, res: express.Response) {
    // Setting signed cookie without domain or path
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('userId', '12345', {
        signed: true,
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.post('/api/logout', (req: Request, res: Response) => {
        // Clearing cookie without domain or path
        // ruleid: typescript-cookie-domain-or-path-not-set
        res.clearCookie('sessionId');
        res.send('Logged out');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
    // Using array of cookies without domain or path
    const cookies = [
        cookie.serialize('userId', '12345', { httpOnly: true, secure: true }),
        cookie.serialize('role', 'user', { httpOnly: true, secure: true })
    ];
    
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.setHeader('Set-Cookie', cookies);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
    // Setting cookie with only one of maxAge or expires
    // ruleid: typescript-cookie-domain-or-path-not-set
    res.cookie('sessionTimeout', '3600', {
        maxAge: 3600000,
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1(req: express.Request, res: express.Response) {
    // Setting cookie with both domain and path
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('sessionId', 'abc123', {
        domain: 'example.com',
        path: '/app',
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2(req: express.Request, res: express.Response) {
    // Setting cookie with domain only (which is sufficient)
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('authToken', 'xyz789', {
        domain: 'api.example.com',
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3(req: express.Request, res: express.Response) {
    // Setting cookie with path only (which is sufficient)
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('userId', '12345', {
        path: '/dashboard',
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4(req: express.Request, res: express.Response) {
    const options = {
        domain: 'example.com',
        path: '/admin',
        httpOnly: true,
        secure: true
    };
    
    // Using options object with domain and path
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('csrfToken', 'token123', options);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5(req: express.Request, res: express.Response) {
    // Using cookie serialization with domain and path
    const cookieStr = cookie.serialize('sessionId', 'abc123', {
        domain: 'example.com',
        path: '/',
        httpOnly: true,
        secure: true
    });
    
    // ok: typescript-cookie-domain-or-path-not-set
    res.setHeader('Set-Cookie', cookieStr);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6(req: express.Request, res: express.Response) {
    // Setting cookie directly in header with domain and path
    // ok: typescript-cookie-domain-or-path-not-set
    res.setHeader('Set-Cookie', 'authToken=xyz789; Domain=example.com; Path=/api; HttpOnly; Secure');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7(req: express.Request, res: express.Response) {
    // Setting cookie with expiration and domain/path
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 1);
    
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('rememberMe', 'true', {
        domain: 'example.com',
        path: '/account',
        expires: expiryDate,
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
    const app = express();
    app.use(cookieParser());
    
    app.get('/login', (req: Request, res: Response) => {
        // Setting authentication cookie with domain and path
        // ok: typescript-cookie-domain-or-path-not-set
        res.cookie('authToken', 'token123', {
            domain: 'auth.example.com',
            path: '/session',
            httpOnly: true,
            secure: true
        });
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9(req: express.Request, res: express.Response) {
    // Conditional cookie setting with domain and path
    const isSecure = req.protocol === 'https';
    const domain = isSecure ? 'secure.example.com' : 'example.com';
    
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('preference', 'darkMode', {
        domain: domain,
        path: '/preferences',
        httpOnly: true,
        secure: isSecure
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10(req: express.Request, res: express.Response) {
    // Setting cookie with dynamic value and domain/path
    const userId = req.params.id;
    
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('lastVisited', userId, {
        domain: 'user.example.com',
        path: `/profile/${userId}`,
        maxAge: 86400000,
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11(req: express.Request, res: express.Response) {
    // Setting cookie with sameSite and domain/path
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('sessionId', 'abc123', {
        domain: 'example.com',
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12(req: express.Request, res: express.Response) {
    // Setting signed cookie with domain and path
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('userId', '12345', {
        domain: 'api.example.com',
        path: '/user',
        signed: true,
        httpOnly: true,
        secure: true
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.post('/api/logout', (req: Request, res: Response) => {
        // Clearing cookie with domain and path
        // ok: typescript-cookie-domain-or-path-not-set
        res.clearCookie('sessionId', {
            domain: 'auth.example.com',
            path: '/session'
        });
        res.send('Logged out');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
    // Using array of cookies with domain and path
    const cookies = [
        cookie.serialize('userId', '12345', { 
            domain: 'example.com', 
            path: '/user', 
            httpOnly: true, 
            secure: true 
        }),
        cookie.serialize('role', 'user', { 
            domain: 'example.com', 
            path: '/permissions', 
            httpOnly: true, 
            secure: true 
        })
    ];
    
    // ok: typescript-cookie-domain-or-path-not-set
    res.setHeader('Set-Cookie', cookies);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15(req: express.Request, res: express.Response) {
    // Setting cookie with domain, path and all security attributes
    // ok: typescript-cookie-domain-or-path-not-set
    res.cookie('sessionTimeout', '3600', {
        domain: 'secure.example.com',
        path: '/session',
        maxAge: 3600000,
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        signed: true
    });
}
// {/fact}