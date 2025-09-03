// File: unsanitized_origin_header_tests.js
const express = require('express');
const http = require('http');
const url = require('url');

// BAD CASES - Vulnerable code that should be detected

// Bad case 1: Direct use of origin header from request
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/api/data', (req, res) => {
        const origin = req.headers.origin;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
        res.json({ data: 'sensitive information' });
    });
}
// {/fact}

// Bad case 2: Using query parameter to set origin
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.get('/api/config', (req, res) => {
        const clientOrigin = req.query.origin;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', clientOrigin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.json({ config: 'application settings' });
    });
}
// {/fact}

// Bad case 3: Using request body parameter to set origin
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    app.use(express.json());
    
    app.post('/api/register', (req, res) => {
        const clientDomain = req.body.domain;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', clientDomain);
        res.json({ status: 'registered' });
    });
}
// {/fact}

// Bad case 4: Using URL parameter to set origin
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/api/user/:domain', (req, res) => {
        const domain = req.params.domain;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', domain);
        res.json({ user: 'data' });
    });
}
// {/fact}

// Bad case 5: Using a cookie value to set origin
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    app.use(require('cookie-parser')());
    
    app.get('/api/preferences', (req, res) => {
        const origin = req.cookies.preferredOrigin;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ preferences: 'user settings' });
    });
}
// {/fact}

// Bad case 6: Using referer header to set origin
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/api/stats', (req, res) => {
        const referer = req.headers.referer;
        const origin = referer ? new URL(referer).origin : '*';
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ stats: 'usage data' });
    });
}
// {/fact}

// Bad case 7: Using user agent to determine origin
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/api/device', (req, res) => {
        const userAgent = req.headers['user-agent'];
        const origin = userAgent.includes('Mobile') ? 'https://mobile.example.com' : req.query.desktop;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ device: 'info' });
    });
}
// {/fact}

// Bad case 8: Using custom header to set origin
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/api/custom', (req, res) => {
        const customOrigin = req.headers['x-custom-origin'];
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', customOrigin);
        res.json({ custom: 'data' });
    });
}
// {/fact}

// Bad case 9: Using a combination of inputs
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/api/combined', (req, res) => {
        const origin = req.query.origin || req.headers.origin || '*';
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ combined: 'data' });
    });
}
// {/fact}

// Bad case 10: Using input with string manipulation
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/api/subdomain', (req, res) => {
        const subdomain = req.query.sub;
        const origin = `https://${subdomain}.example.com`;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ subdomain: 'data' });
    });
}
// {/fact}

// Bad case 11: Using input with conditional logic
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/api/conditional', (req, res) => {
        let origin;
        if (req.query.env === 'prod') {
            origin = 'https://prod.example.com';
        } else {
            origin = req.query.origin;
        }
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ conditional: 'data' });
    });
}
// {/fact}

// Bad case 12: Using input in Node.js http module
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_12() {
    http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const origin = parsedUrl.query.origin;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: 'sensitive' }));
    }).listen(8080);
}
// {/fact}

// Bad case 13: Using input with array destructuring
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/api/destructure', (req, res) => {
        const [origin] = [req.query.origin];
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ destructured: 'data' });
    });
}
// {/fact}

// Bad case 14: Using input with object spread
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/api/spread', (req, res) => {
        const { origin } = { ...req.query };
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ spread: 'data' });
    });
}
// {/fact}

// Bad case 15: Using input with template literals
// {fact rule=insecure-cors-policy@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/api/template', (req, res) => {
        const domain = req.query.domain;
        const origin = `https://${domain}`;
        
        // ruleid: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ template: 'data' });
    });
}
// {/fact}

// GOOD CASES - Secure code that should not be detected

// Good case 1: Using a static, hardcoded origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/api/data', (req, res) => {
        // ok: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', 'https://trusted-site.com');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
        res.json({ data: 'sensitive information' });
    });
}
// {/fact}

// Good case 2: Using a whitelist to validate origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_2() {
    const app = express();
    const allowedOrigins = ['https://trusted1.com', 'https://trusted2.com'];
    
    app.get('/api/config', (req, res) => {
        const origin = req.headers.origin;
        
        // ok: javascript-unsanitized-input-in-origin-header
        if (origin && allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
            res.setHeader('Access-Control-Allow-Origin', 'https://default-trusted.com');
        }
        
        res.json({ config: 'application settings' });
    });
}
// {/fact}

// Good case 3: Using regex pattern matching for validation
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/api/user', (req, res) => {
        const origin = req.headers.origin;
        
        // ok: javascript-unsanitized-input-in-origin-header
        if (origin && /^https:\/\/.*\.trusted\.com$/.test(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
            res.setHeader('Access-Control-Allow-Origin', 'https://trusted.com');
        }
        
        res.json({ user: 'data' });
    });
}
// {/fact}

// Good case 4: Using environment variables for allowed origins
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_4() {
    const app = express();
    // Assume process.env.ALLOWED_ORIGINS is set securely by the deployment process
    const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',');
    
    app.get('/api/env', (req, res) => {
        const origin = req.headers.origin;
        
        // ok: javascript-unsanitized-input-in-origin-header
        if (origin && allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
            res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0]);
        }
        
        res.json({ env: 'data' });
    });
}
// {/fact}

// Good case 5: Using a configuration file for allowed origins
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_5() {
    const app = express();
    // Assume this is loaded from a secure configuration file
    const config = {
        allowedOrigins: ['https://app.example.com', 'https://admin.example.com']
    };
    
    app.get('/api/config', (req, res) => {
        const origin = req.headers.origin;
        
        // ok: javascript-unsanitized-input-in-origin-header
        if (origin && config.allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
            res.setHeader('Access-Control-Allow-Origin', config.allowedOrigins[0]);
        }
        
        res.json({ config: 'data' });
    });
}
// {/fact}

// Good case 6: Using a function to validate origin
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    function isValidOrigin(origin) {
        const validOrigins = ['https://app.example.com', 'https://api.example.com'];
        return validOrigins.includes(origin);
    }
    
    app.get('/api/function', (req, res) => {
        const origin = req.headers.origin;
        
        // ok: javascript-unsanitized-input-in-origin-header
        if (origin && isValidOrigin(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
            res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');
        }
        
        res.json({ function: 'data' });
    });
}
// {/fact}

// Good case 7: Using a map for domain validation
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_7() {
    const app = express();
    const allowedOrigins = new Map([
        ['app', 'https://app.example.com'],
        ['admin', 'https://admin.example.com'],
        ['api', 'https://api.example.com']
    ]);
    
    app.get('/api/map', (req, res) => {
        const originType = req.query.type;
        
        // ok: javascript-unsanitized-input-in-origin-header
        const origin = allowedOrigins.get(originType) || 'https://app.example.com';
        res.setHeader('Access-Control-Allow-Origin', origin);
        
        res.json({ map: 'data' });
    });
}
// {/fact}

// Good case 8: Using wildcard but with secure defaults
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/api/public', (req, res) => {
        // ok: javascript-unsanitized-input-in-origin-header
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET');
        // No credentials allowed with wildcard
        res.setHeader('Access-Control-Allow-Credentials', 'false');
        
        res.json({ public: 'data' });
    });
}
// {/fact}

// Good case 9: Using domain validation with URL parsing
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_9() {
    const app = express();
    const allowedDomains = ['example.com', 'trusted.org'];
    
    app.get('/api/url', (req, res) => {
        const origin = req.headers.origin;
        
        // ok: javascript-unsanitized-input-in-origin-header
        if (origin) {
            try {
                const hostname = new URL(origin).hostname;
                const domain = hostname.split('.').slice(-2).join('.');
                
                if (allowedDomains.includes(domain)) {
                    res.setHeader('Access-Control-Allow-Origin', origin);
                } else {
                    res.setHeader('Access-Control-Allow-Origin', 'https://example.com');
                }
            } catch (e) {
                res.setHeader('Access-Control-Allow-Origin', 'https://example.com');
            }
        } else {
            res.setHeader('Access-Control-Allow-Origin', 'https://example.com');
        }
        
        res.json({ url: 'data' });
    });
}
// {/fact}

// Good case 10: Using a switch statement for validation
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/api/switch', (req, res) => {
        const env = req.query.env;
        let origin;
        
        // ok: javascript-unsanitized-input-in-origin-header
        switch (env) {
            case 'prod':
                origin = 'https://prod.example.com';
                break;
            case 'staging':
                origin = 'https://staging.example.com';
                break;
            case 'dev':
                origin = 'https://dev.example.com';
                break;
            default:
                origin = 'https://example.com';
        }
        
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.json({ switch: 'data' });
    });
}
// {/fact}

// Good case 11: Using object lookup for validation
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/api/lookup', (req, res) => {
        const clientId = req.query.client;
        
        const originMap = {
            'client1': 'https://client1.example.com',
            'client2': 'https://client2.example.com',
            'client3': 'https://client3.example.com'
        };
        
        // ok: javascript-unsanitized-input-in-origin-header
        const origin = originMap[clientId] || 'https://default.example.com';
        res.setHeader('Access-Control-Allow-Origin', origin);
        
        res.json({ lookup: 'data' });
    });
}
// {/fact}

// Good case 12: Using a validation service
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    // Simulated validation service
    function validateOrigin(origin) {
        const validOrigins = ['https://app.example.com', 'https://admin.example.com'];
        return validOrigins.includes(origin) ? origin : 'https://default.example.com';
    }
    
    app.get('/api/service', (req, res) => {
        const origin = req.headers.origin;
        
        // ok: javascript-unsanitized-input-in-origin-header
        const validatedOrigin = validateOrigin(origin);
        res.setHeader('Access-Control-Allow-Origin', validatedOrigin);
        
        res.json({ service: 'data' });
    });
}
// {/fact}

// Good case 13: Using a database for allowed origins
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    // Simulated database of allowed origins
    const db = {
        getAllowedOrigins: function() {
            return ['https://app.example.com', 'https://admin.example.com'];
        }
    };
    
    app.get('/api/database', (req, res) => {
        const origin = req.headers.origin;
        const allowedOrigins = db.getAllowedOrigins();
        
        // ok: javascript-unsanitized-input-in-origin-header
        if (origin && allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
            res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0]);
        }
        
        res.json({ database: 'data' });
    });
}
// {/fact}

// Good case 14: Using a middleware for CORS
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_14() {
    const app = express();
    const cors = require('cors');
    
    // ok: javascript-unsanitized-input-in-origin-header
    const corsOptions = {
        origin: ['https://app.example.com', 'https://admin.example.com'],
        methods: 'GET,POST',
        credentials: true
    };
    
    app.use(cors(corsOptions));
    
    app.get('/api/middleware', (req, res) => {
        res.json({ middleware: 'data' });
    });
}
// {/fact}

// Good case 15: Using environment-specific configuration
// {fact rule=insecure-cors-policy@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    // Simulated environment configuration
    const env = process.env.NODE_ENV || 'development';
    const corsConfig = {
        development: {
            origin: 'https://dev.example.com'
        },
        staging: {
            origin: 'https://staging.example.com'
        },
        production: {
            origin: 'https://prod.example.com'
        }
    };
    
    app.get('/api/env-config', (req, res) => {
        // ok: javascript-unsanitized-input-in-origin-header
        const origin = corsConfig[env].origin;
        res.setHeader('Access-Control-Allow-Origin', origin);
        
        res.json({ env: 'data' });
    });
}
// {/fact}

module.exports = {
    bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
    bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
    bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
    good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
    good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
    good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};