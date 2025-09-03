// Demonstrating HTTP Basic Authentication vulnerabilities in JavaScript
// Rule ID: javascript-httpbasic-authentication

// Required imports for examples
const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;
const ClientCertStrategy = require('passport-client-cert').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const OAuth2Strategy = require('passport-oauth2').Strategy;
const auth = require('basic-auth');
const bcrypt = require('bcrypt');

// True Positive Examples (Vulnerable Code)

// Example 1: Basic Express server with HTTP basic authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.use((req, res, next) => {
        const user = auth(req);
        
        if (!user || user.name !== 'admin' || user.pass !== 'password123') {
            res.set('WWW-Authenticate', 'Basic realm="example"');
            return res.status(401).send('Authentication required');
        }
        
        // ruleid: javascript-httpbasic-authentication
        next(); // Allowing access with basic auth
    });
    
    app.get('/admin', (req, res) => {
        res.send('Admin dashboard');
    });
    
    http.createServer(app).listen(3000);
}
// {/fact}

// Example 2: Using passport with basic authentication strategy
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    passport.use(new BasicStrategy(
        function(username, password, done) {
            if (username === 'admin' && password === 'secret') {
                return done(null, { name: 'admin' });
            } else {
                return done(null, false);
            }
        }
    ));
    
    // ruleid: javascript-httpbasic-authentication
    app.get('/api/data', passport.authenticate('basic', { session: false }),
        function(req, res) {
            res.json({ message: 'Sensitive data accessed with basic auth' });
        }
    );
    
    app.listen(3000);
}
// {/fact}

// Example 3: Direct HTTP basic auth header construction
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/protected', (req, res) => {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Basic ')) {
            res.set('WWW-Authenticate', 'Basic realm="private"');
            return res.status(401).send('Authentication required');
        }
        
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
        const [username, password] = credentials.split(':');
        
        // ruleid: javascript-httpbasic-authentication
        if (username === 'user' && password === 'pass') {
            res.send('Welcome to protected resource');
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
    
    http.createServer(app).listen(8080);
}
// {/fact}

// Example 4: Using basic auth in an API client
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_4() {
    function fetchData() {
        const username = 'apiuser';
        const password = 'apipass';
        const auth = 'Basic ' + Buffer.from(username + ':' + password).toString('base64');
        
        const options = {
            hostname: 'api.example.com',
            port: 80,
            path: '/data',
            method: 'GET',
            headers: {
                // ruleid: javascript-httpbasic-authentication
                'Authorization': auth
            }
        };
        
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                console.log(data);
            });
        });
        
        req.end();
    }
    
    fetchData();
}
// {/fact}

// Example 5: Basic auth middleware implementation
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    function basicAuthMiddleware(req, res, next) {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Basic ')) {
            res.set('WWW-Authenticate', 'Basic realm="secure area"');
            return res.status(401).send('Access denied');
        }
        
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [username, password] = credentials.split(':');
        
        // ruleid: javascript-httpbasic-authentication
        if (username === 'admin' && password === 'adminpass') {
            req.user = { username };
            next();
        } else {
            res.status(401).send('Invalid credentials');
        }
    }
    
    app.use('/secure', basicAuthMiddleware);
    app.get('/secure/data', (req, res) => {
        res.json({ message: 'Secure data', user: req.user });
    });
    
    app.listen(3000);
}
// {/fact}

// Example 6: Using basic auth with Node.js http module directly
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_6() {
    const server = http.createServer((req, res) => {
        const authHeader = req.headers.authorization || '';
        
        if (!authHeader.startsWith('Basic ')) {
            res.writeHead(401, {
                'WWW-Authenticate': 'Basic realm="Access to site"'
            });
            return res.end('Authentication required');
        }
        
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [username, password] = credentials.split(':');
        
        // ruleid: javascript-httpbasic-authentication
        if (username === 'user' && password === 'password') {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Welcome to the protected area');
        } else {
            res.writeHead(401);
            res.end('Invalid credentials');
        }
    });
    
    server.listen(8080);
}
// {/fact}

// Example 7: Basic auth in Express with database check
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    const users = [
        { username: 'admin', passwordHash: '$2b$10$rPiEAgQNIT1TcJ8kkWZ6beej3u.bqjXdHxJbIV5QXjrIFZ/TOMTKW' } // hash for 'adminpass'
    ];
    
    app.use(async (req, res, next) => {
        const credentials = auth(req);
        
        if (!credentials) {
            res.set('WWW-Authenticate', 'Basic realm="example"');
            return res.status(401).send('Authentication required');
        }
        
        const user = users.find(u => u.username === credentials.name);
        if (user && await bcrypt.compare(credentials.pass, user.passwordHash)) {
            // ruleid: javascript-httpbasic-authentication
            req.user = { username: user.username };
            next();
        } else {
            res.set('WWW-Authenticate', 'Basic realm="example"');
            res.status(401).send('Invalid credentials');
        }
    });
    
    app.get('/dashboard', (req, res) => {
        res.send(`Welcome ${req.user.username}`);
    });
    
    http.createServer(app).listen(3000);
}
// {/fact}

// Example 8: Basic auth for API endpoints
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    function checkApiCredentials(req, res, next) {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Basic ')) {
            return res.status(401).json({ error: 'API key required' });
        }
        
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [apiKey, apiSecret] = credentials.split(':');
        
        // ruleid: javascript-httpbasic-authentication
        if (apiKey === 'api_12345' && apiSecret === 'secret_67890') {
            req.apiClient = { id: apiKey };
            next();
        } else {
            res.status(401).json({ error: 'Invalid API credentials' });
        }
    }
    
    app.use('/api/v1', checkApiCredentials);
    
    app.get('/api/v1/users', (req, res) => {
        res.json({ users: ['user1', 'user2', 'user3'] });
    });
    
    app.listen(3000);
}
// {/fact}

// Example 9: Basic auth with custom realm
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/reports', (req, res) => {
        const credentials = auth(req);
        
        if (!credentials) {
            res.set('WWW-Authenticate', 'Basic realm="Financial Reports"');
            return res.status(401).send('Authentication required');
        }
        
        // ruleid: javascript-httpbasic-authentication
        if (credentials.name === 'finance' && credentials.pass === 'quarterly') {
            res.send('Financial reports data');
        } else {
            res.set('WWW-Authenticate', 'Basic realm="Financial Reports"');
            res.status(401).send('Invalid credentials');
        }
    });
    
    http.createServer(app).listen(3000);
}
// {/fact}

// Example 10: Basic auth with role-based access control
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    const users = [
        { username: 'admin', password: 'admin123', role: 'admin' },
        { username: 'user', password: 'user123', role: 'user' }
    ];
    
    function authenticate(req, res, next) {
        const credentials = auth(req);
        
        if (!credentials) {
            res.set('WWW-Authenticate', 'Basic realm="RBAC System"');
            return res.status(401).send('Authentication required');
        }
        
        const user = users.find(u => 
            u.username === credentials.name && 
            u.password === credentials.pass
        );
        
        if (user) {
            // ruleid: javascript-httpbasic-authentication
            req.user = { username: user.username, role: user.role };
            next();
        } else {
            res.set('WWW-Authenticate', 'Basic realm="RBAC System"');
            res.status(401).send('Invalid credentials');
        }
    }
    
    app.use(authenticate);
    
    app.get('/admin', (req, res) => {
        if (req.user.role === 'admin') {
            res.send('Admin panel');
        } else {
            res.status(403).send('Access denied');
        }
    });
    
    app.listen(3000);
}
// {/fact}

// Example 11: Basic auth with proxy server
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.use((req, res, next) => {
        const credentials = auth(req);
        
        if (!credentials) {
            res.set('WWW-Authenticate', 'Basic realm="Proxy"');
            return res.status(407).send('Proxy authentication required');
        }
        
        // ruleid: javascript-httpbasic-authentication
        if (credentials.name === 'proxyuser' && credentials.pass === 'proxypass') {
            next();
        } else {
            res.set('WWW-Authenticate', 'Basic realm="Proxy"');
            res.status(407).send('Invalid proxy credentials');
        }
    });
    
    app.use((req, res) => {
        // Proxy logic here
        res.send('Request proxied');
    });
    
    app.listen(8080);
}
// {/fact}

// Example 12: Basic auth with multiple valid credentials
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    const validCredentials = [
        { username: 'user1', password: 'pass1' },
        { username: 'user2', password: 'pass2' },
        { username: 'user3', password: 'pass3' }
    ];
    
    app.get('/content', (req, res) => {
        const credentials = auth(req);
        
        if (!credentials) {
            res.set('WWW-Authenticate', 'Basic realm="Content"');
            return res.status(401).send('Authentication required');
        }
        
        // ruleid: javascript-httpbasic-authentication
        const isValid = validCredentials.some(
            vc => vc.username === credentials.name && vc.password === credentials.pass
        );
        
        if (isValid) {
            res.send('Protected content');
        } else {
            res.set('WWW-Authenticate', 'Basic realm="Content"');
            res.status(401).send('Invalid credentials');
        }
    });
    
    http.createServer(app).listen(3000);
}
// {/fact}

// Example 13: Basic auth with time-limited access
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/temporary-access', (req, res) => {
        const credentials = auth(req);
        const currentHour = new Date().getHours();
        
        if (!credentials) {
            res.set('WWW-Authenticate', 'Basic realm="Temporary Access"');
            return res.status(401).send('Authentication required');
        }
        
        // ruleid: javascript-httpbasic-authentication
        if (credentials.name === 'tempuser' && credentials.pass === 'temppass') {
            // Only allow access during business hours (9 AM to 5 PM)
            if (currentHour >= 9 && currentHour < 17) {
                res.send('Temporary access granted');
            } else {
                res.status(403).send('Access only available during business hours');
            }
        } else {
            res.set('WWW-Authenticate', 'Basic realm="Temporary Access"');
            res.status(401).send('Invalid credentials');
        }
    });
    
    http.createServer(app).listen(3000);
}
// {/fact}

// Example 14: Basic auth with IP restriction
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    const allowedIPs = ['192.168.1.1', '192.168.1.2', '127.0.0.1'];
    
    app.get('/restricted', (req, res) => {
        const clientIP = req.ip || req.connection.remoteAddress;
        const credentials = auth(req);
        
        if (!allowedIPs.includes(clientIP)) {
            return res.status(403).send('IP not allowed');
        }
        
        if (!credentials) {
            res.set('WWW-Authenticate', 'Basic realm="IP Restricted"');
            return res.status(401).send('Authentication required');
        }
        
        // ruleid: javascript-httpbasic-authentication
        if (credentials.name === 'internal' && credentials.pass === 'access123') {
            res.send('Internal system access granted');
        } else {
            res.set('WWW-Authenticate', 'Basic realm="IP Restricted"');
            res.status(401).send('Invalid credentials');
        }
    });
    
    http.createServer(app).listen(3000);
}
// {/fact}

// Example 15: Basic auth for WebDAV server
// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.use((req, res, next) => {
        const credentials = auth(req);
        
        if (!credentials) {
            res.set('WWW-Authenticate', 'Basic realm="WebDAV Server"');
            return res.status(401).send('Authentication required');
        }
        
        // ruleid: javascript-httpbasic-authentication
        if (credentials.name === 'webdav' && credentials.pass === 'fileaccess') {
            next();
        } else {
            res.set('WWW-Authenticate', 'Basic realm="WebDAV Server"');
            res.status(401).send('Invalid credentials');
        }
    });
    
    app.all('/webdav/*', (req, res) => {
        // WebDAV implementation
        res.send('WebDAV operation processed');
    });
    
    http.createServer(app).listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Using HTTPS with client certificate authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    const options = {
        key: fs.readFileSync('server-key.pem'),
        cert: fs.readFileSync('server-cert.pem'),
        ca: [fs.readFileSync('client-ca.pem')],
        requestCert: true,
        rejectUnauthorized: true
    };
    
    app.get('/secure', (req, res) => {
        // ok: javascript-httpbasic-authentication
        const cert = req.socket.getPeerCertificate();
        
        if (req.client.authorized) {
            res.send(`Hello ${cert.subject.CN}, your certificate was issued by ${cert.issuer.CN}!`);
        } else {
            res.status(401).send('Sorry, but you need a valid client certificate to access this');
        }
    });
    
    https.createServer(options, app).listen(443);
}
// {/fact}

// Example 2: Using JWT authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    const jwtOptions = {
        jwtFromRequest: req => {
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                return authHeader.substring(7);
            }
            return null;
        },
        secretOrKey: 'your_jwt_secret'
    };
    
    passport.use(new JwtStrategy(jwtOptions, (payload, done) => {
        // Verify the JWT payload
        if (payload.sub) {
            return done(null, { id: payload.sub });
        }
        return done(null, false);
    }));
    
    // ok: javascript-httpbasic-authentication
    app.get('/api/protected', passport.authenticate('jwt', { session: false }),
        (req, res) => {
            res.json({ message: 'Protected data accessed with JWT' });
        }
    );
    
    app.listen(3000);
}
// {/fact}

// Example 3: Using OAuth2 authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    passport.use(new OAuth2Strategy({
        authorizationURL: 'https://provider.example.com/oauth2/authorize',
        tokenURL: 'https://provider.example.com/oauth2/token',
        clientID: 'client_id',
        clientSecret: 'client_secret',
        callbackURL: 'https://myapp.example.com/auth/callback'
    },
    function(accessToken, refreshToken, profile, done) {
        // Verify the user
        return done(null, { id: profile.id });
    }));
    
    app.get('/auth', passport.authenticate('oauth2'));
    
    app.get('/auth/callback', 
        passport.authenticate('oauth2', { failureRedirect: '/login' }),
        (req, res) => {
            res.redirect('/');
        }
    );
    
    // ok: javascript-httpbasic-authentication
    app.get('/protected', (req, res) => {
        if (req.isAuthenticated()) {
            res.json({ message: 'Protected data accessed with OAuth2' });
        } else {
            res.redirect('/auth');
        }
    });
    
    app.listen(3000);
}
// {/fact}

// Example 4: Using HTTPS with session-based authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_4() {
    const app = express();
    const session = require('express-session');
    
    app.use(express.urlencoded({ extended: true }));
    app.use(session({
        secret: 'session_secret',
        resave: false,
        saveUninitialized: false,
        cookie: { secure: true }
    }));
    
    app.post('/login', (req, res) => {
        const { username, password } = req.body;
        
        // Validate credentials (in a real app, check against database)
        if (username === 'user' && password === 'pass') {
            req.session.authenticated = true;
            req.session.user = { username };
            res.redirect('/dashboard');
        } else {
            res.redirect('/login');
        }
    });
    
    // ok: javascript-httpbasic-authentication
    app.get('/dashboard', (req, res) => {
        if (req.session.authenticated) {
            res.send(`Welcome to your dashboard, ${req.session.user.username}`);
        } else {
            res.redirect('/login');
        }
    });
    
    const options = {
        key: fs.readFileSync('server-key.pem'),
        cert: fs.readFileSync('server-cert.pem')
    };
    
    https.createServer(options, app).listen(443);
}
// {/fact}

// Example 5: Using API keys with HTTPS
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    const apiKeys = {
        'api_key_12345': { clientName: 'Client A', permissions: ['read'] },
        'api_key_67890': { clientName: 'Client B', permissions: ['read', 'write'] }
    };
    
    function validateApiKey(req, res, next) {
        const apiKey = req.headers['x-api-key'];
        
        if (!apiKey || !apiKeys[apiKey]) {
            return res.status(401).json({ error: 'Invalid API key' });
        }
        
        req.client = apiKeys[apiKey];
        next();
    }
    
    // ok: javascript-httpbasic-authentication
    app.get('/api/data', validateApiKey, (req, res) => {
        if (req.client.permissions.includes('read')) {
            res.json({ data: 'Secure data accessed with API key' });
        } else {
            res.status(403).json({ error: 'Insufficient permissions' });
        }
    });
    
    const options = {
        key: fs.readFileSync('server-key.pem'),
        cert: fs.readFileSync('server-cert.pem')
    };
    
    https.createServer(options, app).listen(443);
}
// {/fact}

// Example 6: Using mutual TLS (mTLS) authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    const options = {
        key: fs.readFileSync('server-key.pem'),
        cert: fs.readFileSync('server-cert.pem'),
        ca: [fs.readFileSync('client-ca.pem')],
        requestCert: true,
        rejectUnauthorized: true
    };
    
    // ok: javascript-httpbasic-authentication
    app.use((req, res, next) => {
        if (!req.client.authorized) {
            return res.status(401).send('Invalid client certificate');
        }
        
        const cert = req.socket.getPeerCertificate();
        req.clientCN = cert.subject.CN;
        next();
    });
    
    app.get('/api/secure', (req, res) => {
        res.json({ message: `Hello ${req.clientCN}, you are authenticated via mTLS` });
    });
    
    https.createServer(options, app).listen(443);
}
// {/fact}

// Example 7: Using SAML authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_7() {
    const app = express();
    const passport = require('passport');
    const SamlStrategy = require('passport-saml').Strategy;
    
    passport.use(new SamlStrategy(
        {
            path: '/login/callback',
            entryPoint: 'https://idp.example.com/saml2/sso',
            issuer: 'passport-saml',
            cert: fs.readFileSync('idp-cert.pem', 'utf8')
        },
        (profile, done) => {
            return done(null, profile);
        }
    ));
    
    app.get('/login',
        passport.authenticate('saml', { failureRedirect: '/login', failureFlash: true }),
        (req, res) => {
            res.redirect('/');
        }
    );
    
    app.post('/login/callback',
        passport.authenticate('saml', { failureRedirect: '/login', failureFlash: true }),
        (req, res) => {
            res.redirect('/');
        }
    );
    
    // ok: javascript-httpbasic-authentication
    app.get('/secure-resource', (req, res) => {
        if (req.isAuthenticated()) {
            res.json({ message: 'Secure data accessed with SAML authentication' });
        } else {
            res.redirect('/login');
        }
    });
    
    app.listen(3000);
}
// {/fact}

// Example 8: Using OpenID Connect authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_8() {
    const app = express();
    const passport = require('passport');
    const OpenIDConnectStrategy = require('passport-openidconnect').Strategy;
    
    passport.use(new OpenIDConnectStrategy({
        issuer: 'https://accounts.example.com',
        authorizationURL: 'https://accounts.example.com/auth',
        tokenURL: 'https://accounts.example.com/token',
        userInfoURL: 'https://accounts.example.com/userinfo',
        clientID: 'client_id',
        clientSecret: 'client_secret',
        callbackURL: 'https://myapp.example.com/auth/callback',
        scope: 'openid profile email'
    },
    (issuer, profile, done) => {
        return done(null, profile);
    }));
    
    app.get('/auth', passport.authenticate('openidconnect'));
    
    app.get('/auth/callback',
        passport.authenticate('openidconnect', { failureRedirect: '/login' }),
        (req, res) => {
            res.redirect('/');
        }
    );
    
    // ok: javascript-httpbasic-authentication
    app.get('/profile', (req, res) => {
        if (req.isAuthenticated()) {
            res.json({ user: req.user, message: 'Profile accessed with OpenID Connect' });
        } else {
            res.redirect('/auth');
        }
    });
    
    app.listen(3000);
}
// {/fact}

// Example 9: Using HMAC-based authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_9() {
    const app = express();
    const crypto = require('crypto');
    
    function verifyHmacSignature(req, res, next) {
        const apiKey = req.headers['x-api-key'];
        const signature = req.headers['x-signature'];
        const timestamp = req.headers['x-timestamp'];
        const body = JSON.stringify(req.body);
        
        if (!apiKey || !signature || !timestamp) {
            return res.status(401).json({ error: 'Missing authentication headers' });
        }
        
        // Check if timestamp is recent (within 5 minutes)
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - parseInt(timestamp)) > 300) {
            return res.status(401).json({ error: 'Request expired' });
        }
        
        // In a real app, get the secret based on the API key from a secure store
        const clientSecret = 'client_secret_for_' + apiKey;
        
        const expectedSignature = crypto
            .createHmac('sha256', clientSecret)
            .update(`${timestamp}:${body}`)
            .digest('hex');
        
        if (crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
            next();
        } else {
            res.status(401).json({ error: 'Invalid signature' });
        }
    }
    
    // ok: javascript-httpbasic-authentication
    app.post('/api/data', express.json(), verifyHmacSignature, (req, res) => {
        res.json({ message: 'Data received with valid HMAC signature' });
    });
    
    app.listen(3000);
}
// {/fact}

// Example 10: Using token-based authentication with refresh tokens
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_10() {
    const app = express();
    const jwt = require('jsonwebtoken');
    
    app.use(express.json());
    
    const JWT_SECRET = 'your_jwt_secret';
    const REFRESH_SECRET = 'your_refresh_secret';
    
    app.post('/login', (req, res) => {
        const { username, password } = req.body;
        
        // Validate credentials (in a real app, check against database)
        if (username === 'user' && password === 'pass') {
            const accessToken = jwt.sign({ sub: username }, JWT_SECRET, { expiresIn: '15m' });
            const refreshToken = jwt.sign({ sub: username }, REFRESH_SECRET, { expiresIn: '7d' });
            
            res.json({ accessToken, refreshToken });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
    
    app.post('/refresh', (req, res) => {
        const { refreshToken } = req.body;
        
        if (!refreshToken) {
            return res.status(401).json({ error: 'Refresh token required' });
        }
        
        try {
            const payload = jwt.verify(refreshToken, REFRESH_SECRET);
            const accessToken = jwt.sign({ sub: payload.sub }, JWT_SECRET, { expiresIn: '15m' });
            
            res.json({ accessToken });
        } catch (err) {
            res.status(401).json({ error: 'Invalid refresh token' });
        }
    });
    
    function authenticateToken(req, res, next) {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Access token required' });
        }
        
        const token = authHeader.split(' ')[1];
        
        try {
            const payload = jwt.verify(token, JWT_SECRET);
            req.user = { username: payload.sub };
            next();
        } catch (err) {
            res.status(401).json({ error: 'Invalid access token' });
        }
    }
    
    // ok: javascript-httpbasic-authentication
    app.get('/api/protected', authenticateToken, (req, res) => {
        res.json({ message: 'Protected data', user: req.user.username });
    });
    
    app.listen(3000);
}
// {/fact}

// Example 11: Using two-factor authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_11() {
    const app = express();
    const speakeasy = require('speakeasy');
    
    app.use(express.json());
    
    // In a real app, store these in a database
    const users = {
        'user1': {
            password: 'password1',
            twoFactorSecret: speakeasy.generateSecret({ length: 20 }).base32
        }
    };
    
    app.post('/login', (req, res) => {
        const { username, password } = req.body;
        
        if (!users[username] || users[username].password !== password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // First factor passed, require second factor
        res.json({ 
            message: 'Password verified, please provide 2FA code',
            requireTwoFactor: true,
            username
        });
    });
    
    app.post('/verify-2fa', (req, res) => {
        const { username, twoFactorCode } = req.body;
        
        if (!users[username]) {
            return res.status(401).json({ error: 'Invalid user' });
        }
        
        // ok: javascript-httpbasic-authentication
        const verified = speakeasy.totp.verify({
            secret: users[username].twoFactorSecret,
            encoding: 'base32',
            token: twoFactorCode,
            window: 1 // Allow 1 period before/after for clock drift
        });
        
        if (verified) {
            // In a real app, generate a session or JWT here
            res.json({ message: 'Authentication successful', token: 'session_token_here' });
        } else {
            res.status(401).json({ error: 'Invalid 2FA code' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// Example 12: Using client certificate authentication with Node.js https module
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_12() {
    const options = {
        key: fs.readFileSync('server-key.pem'),
        cert: fs.readFileSync('server-cert.pem'),
        ca: [fs.readFileSync('client-ca.pem')],
        requestCert: true,
        rejectUnauthorized: true
    };
    
    // ok: javascript-httpbasic-authentication
    const server = https.createServer(options, (req, res) => {
        if (!req.socket.authorized) {
            res.writeHead(401);
            return res.end('Invalid client certificate');
        }
        
        const cert = req.socket.getPeerCertificate();
        
        res.writeHead(200);
        res.end(`Hello ${cert.subject.CN}, your certificate was issued by ${cert.issuer.CN}`);
    });
    
    server.listen(443);
}
// {/fact}

// Example 13: Using secure cookies with HTTPS
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_13() {
    const app = express();
    const cookieParser = require('cookie-parser');
    const crypto = require('crypto');
    
    app.use(express.urlencoded({ extended: true }));
    app.use(cookieParser('cookie_signing_secret'));
    
    app.post('/login', (req, res) => {
        const { username, password } = req.body;
        
        // Validate credentials (in a real app, check against database)
        if (username === 'user' && password === 'pass') {
            // Generate a secure session ID
            const sessionId = crypto.randomBytes(32).toString('hex');
            
            // ok: javascript-httpbasic-authentication
            res.cookie('session', sessionId, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 3600000 // 1 hour
            });
            
            res.redirect('/dashboard');
        } else {
            res.redirect('/login');
        }
    });
    
    const options = {
        key: fs.readFileSync('server-key.pem'),
        cert: fs.readFileSync('server-cert.pem')
    };
    
    https.createServer(options, app).listen(443);
}
// {/fact}

// Example 14: Using WebAuthn/FIDO2 for passwordless authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_14() {
    const app = express();
    const { Fido2Lib } = require('fido2-lib');
    
    app.use(express.json());
    
    const f2l = new Fido2Lib({
        timeout: 60000,
        rpId: "example.com",
        rpName: "Example Corporation",
        challengeSize: 32,
        attestation: "none",
        cryptoParams: [-7, -257]
    });
    
    // Store challenges and registrations in memory (use a database in production)
    const challenges = new Map();
    const registrations = new Map();
    
    app.post('/auth/register-request', async (req, res) => {
        const username = req.body.username;
        
        try {
            const registrationOptions = await f2l.attestationOptions();
            
            // Store challenge for verification
            challenges.set(username, registrationOptions.challenge);
            
            res.json(registrationOptions);
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });
    
    // ok: javascript-httpbasic-authentication
    app.post('/auth/register-response', async (req, res) => {
        const username = req.body.username;
        const attestation = req.body.attestation;
        
        try {
            const expectedChallenge = challenges.get(username);
            
            const regResult = await f2l.attestationResult(attestation, {
                challenge: expectedChallenge,
                origin: "https://example.com",
                factor: "either"
            });
            
            // Store user registration
            registrations.set(username, {
                credentialID: regResult.authnrData.get("credId"),
                publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
                counter: regResult.authnrData.get("counter")
            });
            
            challenges.delete(username);
            
            res.json({ status: "ok" });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// Example 15: Using Kerberos authentication
// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_15() {
    const app = express();
    const kerberos = require('kerberos');
    
    app.use(async (req, res, next) => {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Negotiate ')) {
            res.set('WWW-Authenticate', 'Negotiate');
            return res.status(401).send('Kerberos authentication required');
        }
        
        const token = authHeader.substring(10); // Remove 'Negotiate ' prefix
        
        try {
            // ok: javascript-httpbasic-authentication
            const server = await kerberos.initializeServer('HTTP/server.example.com@EXAMPLE.COM');
            const result = await server.step(token);
            
            if (result.contextComplete) {
                const username = result.username;
                req.user = { username };
                
                if (result.responseToken) {
                    res.set('WWW-Authenticate', `Negotiate ${result.responseToken}`);
                }
                
                next();
            } else {
                res.set('WWW-Authenticate', `Negotiate ${result.responseToken}`);
                res.status(401).send('Kerberos authentication incomplete');
            }
        } catch (err) {
            res.status(401).send('Kerberos authentication failed');
        }
    });
    
    app.get('/secure', (req, res) => {
        res.send(`Hello ${req.user.username}, you are authenticated via Kerberos`);
    });
    
    app.listen(3000);
}
// {/fact}