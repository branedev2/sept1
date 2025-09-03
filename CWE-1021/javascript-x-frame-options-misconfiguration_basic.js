const express = require('express');
const http = require('http');
const https = require('https');
const helmet = require('helmet');

// True Positive Examples (Vulnerable Code)

// Example 1: Setting invalid X-Frame-Options value
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.use((req, res, next) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'ALLOWALL');
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Hello World!');
    });
    
    app.listen(3000);
}
// {/fact}

// Example 2: Setting empty X-Frame-Options value
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.use((req, res, next) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', '');
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Hello World!');
    });
    
    app.listen(3001);
}
// {/fact}

// Example 3: Setting X-Frame-Options with incorrect case
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/profile', (req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'deny');  // Incorrect case, should be uppercase
        res.send('Profile page');
    });
    
    app.listen(3002);
}
// {/fact}

// Example 4: Setting X-Frame-Options with typo
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/dashboard', (req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'SAME-ORIGIN');  // Incorrect hyphen
        res.send('Dashboard');
    });
    
    app.listen(3003);
}
// {/fact}

// Example 5: Using ALLOW-FROM without a URL
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.use((req, res, next) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'ALLOW-FROM');  // Missing URL
        next();
    });
    
    app.listen(3004);
}
// {/fact}

// Example 6: Using incorrect format with ALLOW-FROM
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/reports', (req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'ALLOW-FROM example.com');  // Missing protocol
        res.send('Reports');
    });
    
    app.listen(3005);
}
// {/fact}

// Example 7: Using multiple values (not supported by browsers)
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/analytics', (req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'DENY, SAMEORIGIN');  // Multiple values not supported
        res.send('Analytics');
    });
    
    app.listen(3006);
}
// {/fact}

// Example 8: Using a completely invalid value
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.use((req, res, next) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'SECURE');  // Invalid value
        next();
    });
    
    app.listen(3007);
}
// {/fact}

// Example 9: Using Node.js http module with invalid header
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_9() {
    const server = http.createServer((req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'ALLOW');  // Invalid value
        res.end('Hello World!');
    });
    
    server.listen(3008);
}
// {/fact}

// Example 10: Using lowercase header name
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.use((req, res, next) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('x-frame-options', 'SAMEORIGIN');  // Header name should be case-insensitive, but value is case-sensitive
        next();
    });
    
    app.listen(3009);
}
// {/fact}

// Example 11: Using ALLOW-FROM with multiple URLs
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/embed', (req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'ALLOW-FROM https://example.com https://test.com');  // Multiple URLs not supported
        res.send('Embeddable content');
    });
    
    app.listen(3010);
}
// {/fact}

// Example 12: Using incorrect spacing
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/content', (req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', ' DENY ');  // Extra spaces
        res.send('Content');
    });
    
    app.listen(3011);
}
// {/fact}

// Example 13: Using a numeric value
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.use((req, res, next) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', '1');  // Invalid numeric value
        next();
    });
    
    app.listen(3012);
}
// {/fact}

// Example 14: Using boolean value
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/api/data', (req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'true');  // Invalid boolean value
        res.json({ data: 'example' });
    });
    
    app.listen(3013);
}
// {/fact}

// Example 15: Using incorrect ALLOW-FROM syntax
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/iframe-content', (req, res) => {
        // ruleid: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'ALLOWFROM https://example.com');  // Missing hyphen
        res.send('Iframe content');
    });
    
    app.listen(3014);
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Using DENY correctly
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.use((req, res, next) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'DENY');
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Hello World!');
    });
    
    app.listen(4000);
}
// {/fact}

// Example 2: Using SAMEORIGIN correctly
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.use((req, res, next) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Hello World!');
    });
    
    app.listen(4001);
}
// {/fact}

// Example 3: Using ALLOW-FROM correctly
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/embeddable', (req, res) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'ALLOW-FROM https://trusted-site.com');
        res.send('Embeddable content');
    });
    
    app.listen(4002);
}
// {/fact}

// Example 4: Using helmet middleware for X-Frame-Options
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    // ok: javascript-x-frame-options-misconfiguration
    app.use(helmet.frameguard({ action: 'deny' }));
    
    app.get('/', (req, res) => {
        res.send('Protected by helmet');
    });
    
    app.listen(4003);
}
// {/fact}

// Example 5: Using helmet with SAMEORIGIN
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    // ok: javascript-x-frame-options-misconfiguration
    app.use(helmet.frameguard({ action: 'sameorigin' }));
    
    app.get('/', (req, res) => {
        res.send('Protected by helmet with SAMEORIGIN');
    });
    
    app.listen(4004);
}
// {/fact}

// Example 6: Using helmet with ALLOW-FROM
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    // ok: javascript-x-frame-options-misconfiguration
    app.use(helmet.frameguard({
        action: 'allow-from',
        domain: 'https://example.com'
    }));
    
    app.get('/', (req, res) => {
        res.send('Protected by helmet with ALLOW-FROM');
    });
    
    app.listen(4005);
}
// {/fact}

// Example 7: Using http module with correct header
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_7() {
    const server = http.createServer((req, res) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'DENY');
        res.end('Hello World!');
    });
    
    server.listen(4006);
}
// {/fact}

// Example 8: Using https module with correct header
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_8() {
    const options = {
        // Assume these are defined elsewhere
        key: 'privateKey',
        cert: 'certificate'
    };
    
    const server = https.createServer(options, (req, res) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.end('Secure Hello World!');
    });
    
    server.listen(4007);
}
// {/fact}

// Example 9: Setting header in route-specific middleware
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    const secureFrames = (req, res, next) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'DENY');
        next();
    };
    
    app.get('/secure', secureFrames, (req, res) => {
        res.send('Secure route');
    });
    
    app.listen(4008);
}
// {/fact}

// Example 10: Setting header conditionally based on route
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.use((req, res, next) => {
        if (req.path.startsWith('/admin')) {
            // ok: javascript-x-frame-options-misconfiguration
            res.setHeader('X-Frame-Options', 'DENY');
        } else {
            // ok: javascript-x-frame-options-misconfiguration
            res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        }
        next();
    });
    
    app.listen(4009);
}
// {/fact}

// Example 11: Using express.js response methods
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/api/data', (req, res) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.header('X-Frame-Options', 'DENY');
        res.json({ data: 'example' });
    });
    
    app.listen(4010);
}
// {/fact}

// Example 12: Setting header with append method
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/content', (req, res) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.append('X-Frame-Options', 'SAMEORIGIN');
        res.send('Content with appended header');
    });
    
    app.listen(4011);
}
// {/fact}

// Example 13: Using custom middleware function
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    function addSecurityHeaders(req, res, next) {
        // ok: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
        next();
    }
    
    app.use(addSecurityHeaders);
    
    app.get('/', (req, res) => {
        res.send('Secure page');
    });
    
    app.listen(4012);
}
// {/fact}

// Example 14: Setting header in error handler
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/error', (req, res) => {
        throw new Error('Test error');
    });
    
    app.use((err, req, res, next) => {
        // ok: javascript-x-frame-options-misconfiguration
        res.setHeader('X-Frame-Options', 'DENY');
        res.status(500).send('Something broke!');
    });
    
    app.listen(4013);
}
// {/fact}

// Example 15: Using helmet with custom configuration
// {fact rule=user-interface-misrepresentation-of-critical-information@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    // ok: javascript-x-frame-options-misconfiguration
    app.use(helmet({
        frameguard: {
            action: 'deny'
        }
    }));
    
    app.get('/', (req, res) => {
        res.send('Protected by custom helmet config');
    });
    
    app.listen(4014);
}
// {/fact}