import * as express from 'express';
import * as cookieParser from 'cookie-parser';
import * as http from 'http';
import * as https from 'https';
import * as session from 'express-session';
import * as cookie from 'cookie';

// True Positives (Vulnerable/Insecure Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    app.use(cookieParser());
    
    app.get('/login', (req, res) => {
        // ruleid: typescript-in-secure-cookie
        res.cookie('sessionId', 'abc123', { 
            maxAge: 3600000,
            httpOnly: true
            // Missing secure flag
        });
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/auth', (req, res) => {
        // ruleid: typescript-in-secure-cookie
        res.cookie('authToken', 'xyz789', {
            expires: new Date(Date.now() + 86400000),
            path: '/'
            // Missing secure and httpOnly flags
        });
        res.redirect('/dashboard');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/remember-me', (req, res) => {
        // ruleid: typescript-in-secure-cookie
        res.cookie('rememberMe', 'true', {
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            secure: false // Explicitly set to false
        });
        res.send('Preference saved');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    app.use(cookieParser());
    
    app.post('/set-preferences', (req, res) => {
        const userPrefs = { theme: 'dark', fontSize: 'large' };
        // ruleid: typescript-in-secure-cookie
        res.cookie('userPreferences', JSON.stringify(userPrefs), {
            maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
            // Missing secure flag
        });
        res.send('Preferences updated');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.use(session({
        secret: 'keyboard cat',
        resave: false,
        saveUninitialized: true,
        // ruleid: typescript-in-secure-cookie
        cookie: { 
            maxAge: 60000
            // Missing secure flag
        }
    }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/api/set-token', (req, res) => {
        // ruleid: typescript-in-secure-cookie
        res.cookie('apiToken', 'token123', {
            httpOnly: true,
            sameSite: 'strict'
            // Missing secure flag
        });
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
    const response = {
        writeHead: (status: number, headers: any) => {},
        end: () => {}
    };
    
    // ruleid: typescript-in-secure-cookie
    const cookieOptions = { httpOnly: true, maxAge: 3600000 }; // Missing secure flag
    const cookieString = cookie.serialize('sessionId', 'abc123', cookieOptions);
    
    response.writeHead(200, {
        'Set-Cookie': cookieString,
        'Content-Type': 'text/plain'
    });
    response.end('Cookie set');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/login', (req, res) => {
        // ruleid: typescript-in-secure-cookie
        const cookieOptions = {
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            path: '/',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production' ? true : false // Conditionally secure
        };
        
        if (process.env.NODE_ENV !== 'production') {
            // This will make the cookie insecure in non-production environments
            res.cookie('sessionId', 'abc123', cookieOptions);
        }
        
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
    const server = http.createServer((req, res) => {
        // ruleid: typescript-in-secure-cookie
        res.setHeader('Set-Cookie', [
            'sessionId=abc123; Path=/; HttpOnly',
            'userId=123; Path=/; Max-Age=3600'
        ]); // Missing secure flag in header cookies
        res.end('Cookies set');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.post('/login', (req, res) => {
        const isSecure = false; // For testing purposes
        
        // ruleid: typescript-in-secure-cookie
        res.cookie('authToken', 'token123', {
            maxAge: 3600000,
            httpOnly: true,
            secure: isSecure // Explicitly set to false
        });
        
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/api/data', (req, res) => {
        const userData = { id: 123, name: 'John' };
        
        // ruleid: typescript-in-secure-cookie
        res.cookie('userData', JSON.stringify(userData), {
            expires: new Date(Date.now() + 86400000),
            httpOnly: false // Not httpOnly and missing secure flag
        });
        
        res.json(userData);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.use((req, res, next) => {
        const originalSetCookie = res.cookie;
        
        res.cookie = function(name, value, options) {
            options = options || {};
            // ruleid: typescript-in-secure-cookie
            // Overriding cookie function but not enforcing secure flag
            return originalSetCookie.call(this, name, value, options);
        };
        
        next();
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    const setCookieWithOptions = (res: express.Response, name: string, value: string) => {
        // ruleid: typescript-in-secure-cookie
        res.cookie(name, value, {
            maxAge: 3600000,
            path: '/'
            // Missing secure flag
        });
    };
    
    app.get('/set-cookie', (req, res) => {
        setCookieWithOptions(res, 'sessionId', 'abc123');
        res.send('Cookie set');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/login', (req, res) => {
        const cookieParams = {
            maxAge: 3600000,
            httpOnly: true
            // Missing secure flag
        };
        
        // ruleid: typescript-in-secure-cookie
        res.cookie('sessionId', 'abc123', cookieParams);
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.post('/api/auth', (req, res) => {
        let cookieOptions;
        
        if (req.body.rememberMe) {
            cookieOptions = {
                maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
                httpOnly: true
                // Missing secure flag
            };
        } else {
            cookieOptions = {
                httpOnly: true
                // Missing secure flag
            };
        }
        
        // ruleid: typescript-in-secure-cookie
        res.cookie('authToken', 'token123', cookieOptions);
        res.json({ success: true });
    });
}
// {/fact}

// True Negatives (Safe/Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
    const app = express();
    app.use(cookieParser());
    
    app.get('/login', (req, res) => {
        // ok: typescript-in-secure-cookie
        res.cookie('sessionId', 'abc123', { 
            maxAge: 3600000,
            httpOnly: true,
            secure: true // Secure flag is set
        });
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/auth', (req, res) => {
        // ok: typescript-in-secure-cookie
        res.cookie('authToken', 'xyz789', {
            expires: new Date(Date.now() + 86400000),
            path: '/',
            secure: true, // Secure flag is set
            httpOnly: true
        });
        res.redirect('/dashboard');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/remember-me', (req, res) => {
        // ok: typescript-in-secure-cookie
        res.cookie('rememberMe', 'true', {
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            secure: true, // Secure flag is set
            sameSite: 'strict'
        });
        res.send('Preference saved');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
    const app = express();
    app.use(cookieParser());
    
    app.post('/set-preferences', (req, res) => {
        const userPrefs = { theme: 'dark', fontSize: 'large' };
        // ok: typescript-in-secure-cookie
        res.cookie('userPreferences', JSON.stringify(userPrefs), {
            maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
            secure: true // Secure flag is set
        });
        res.send('Preferences updated');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.use(session({
        secret: 'keyboard cat',
        resave: false,
        saveUninitialized: true,
        // ok: typescript-in-secure-cookie
        cookie: { 
            maxAge: 60000,
            secure: true // Secure flag is set
        }
    }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.get('/api/set-token', (req, res) => {
        // ok: typescript-in-secure-cookie
        res.cookie('apiToken', 'token123', {
            httpOnly: true,
            secure: true, // Secure flag is set
            sameSite: 'strict'
        });
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
    const response = {
        writeHead: (status: number, headers: any) => {},
        end: () => {}
    };
    
    // ok: typescript-in-secure-cookie
    const cookieOptions = { 
        httpOnly: true, 
        maxAge: 3600000,
        secure: true // Secure flag is set
    };
    const cookieString = cookie.serialize('sessionId', 'abc123', cookieOptions);
    
    response.writeHead(200, {
        'Set-Cookie': cookieString,
        'Content-Type': 'text/plain'
    });
    response.end('Cookie set');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
    const server = https.createServer({}, (req, res) => {
        // ok: typescript-in-secure-cookie
        res.setHeader('Set-Cookie', [
            'sessionId=abc123; Path=/; HttpOnly; Secure',
            'userId=123; Path=/; Max-Age=3600; Secure'
        ]); // Secure flag is included in header cookies
        res.end('Cookies set');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.post('/login', (req, res) => {
        // ok: typescript-in-secure-cookie
        res.cookie('authToken', 'token123', {
            maxAge: 3600000,
            httpOnly: true,
            secure: true, // Secure flag is set
            sameSite: 'lax'
        });
        
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/api/data', (req, res) => {
        const userData = { id: 123, name: 'John' };
        
        // ok: typescript-in-secure-cookie
        res.cookie('userData', JSON.stringify(userData), {
            expires: new Date(Date.now() + 86400000),
            httpOnly: true,
            secure: true // Secure flag is set
        });
        
        res.json(userData);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.use((req, res, next) => {
        const originalSetCookie = res.cookie;
        
        res.cookie = function(name, value, options = {}) {
            // ok: typescript-in-secure-cookie
            options.secure = true; // Enforcing secure flag
            options.httpOnly = options.httpOnly !== false;
            
            return originalSetCookie.call(this, name, value, options);
        };
        
        next();
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    const setCookieWithOptions = (res: express.Response, name: string, value: string) => {
        // ok: typescript-in-secure-cookie
        res.cookie(name, value, {
            maxAge: 3600000,
            path: '/',
            secure: true, // Secure flag is set
            httpOnly: true
        });
    };
    
    app.get('/set-cookie', (req, res) => {
        setCookieWithOptions(res, 'sessionId', 'abc123');
        res.send('Cookie set');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/login', (req, res) => {
        const cookieParams = {
            maxAge: 3600000,
            httpOnly: true,
            secure: true, // Secure flag is set
            sameSite: 'strict'
        };
        
        // ok: typescript-in-secure-cookie
        res.cookie('sessionId', 'abc123', cookieParams);
        res.send('Logged in');
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.post('/api/auth', (req, res) => {
        let cookieOptions;
        
        if (req.body.rememberMe) {
            cookieOptions = {
                maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
                httpOnly: true,
                secure: true // Secure flag is set
            };
        } else {
            cookieOptions = {
                httpOnly: true,
                secure: true // Secure flag is set
            };
        }
        
        // ok: typescript-in-secure-cookie
        res.cookie('authToken', 'token123', cookieOptions);
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    // Using a non-sensitive cookie for local development only
    app.get('/debug-info', (req, res) => {
        if (process.env.NODE_ENV === 'development') {
            // ok: typescript-in-secure-cookie
            // This is acceptable because:
            // 1. It's only used in development
            // 2. It doesn't contain sensitive information
            // 3. It's explicitly meant for local debugging
            res.cookie('debugMode', 'enabled', {
                maxAge: 3600000,
                path: '/'
            });
        }
        res.send('Debug info');
    });
}
// {/fact}