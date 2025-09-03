// This file demonstrates proper and improper implementations of the HTTP Strict-Transport-Security header
// Rule ID: javascript-enforce-strict-transport-security
// CWE: 319 - Cleartext Transmission of Sensitive Information

const express = require('express');
const http = require('http');
const https = require('https');
const helmet = require('helmet');
const fs = require('fs');

// BAD CASES - Vulnerable implementations

// Missing HSTS header completely
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/', (req, res) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.send('Sensitive data without HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// HSTS with too short max-age
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.use((req, res, next) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=86400'); // Only 1 day
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with insufficient HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// HSTS without includeSubDomains
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.use((req, res, next) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000'); // 1 year but no includeSubDomains
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with incomplete HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using helmet but with insufficient max-age
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    // ruleid: javascript-enforce-strict-transport-security
    app.use(helmet.hsts({
        maxAge: 10000, // Too short
        includeSubDomains: true
    }));
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with insufficient HSTS protection via helmet');
    });
    
    app.listen(3000);
}
// {/fact}

// Using helmet but without includeSubDomains
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    // ruleid: javascript-enforce-strict-transport-security
    app.use(helmet.hsts({
        maxAge: 31536000, // 1 year
        includeSubDomains: false // Explicitly disabled
    }));
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with incomplete HSTS protection via helmet');
    });
    
    app.listen(3000);
}
// {/fact}

// Node.js http server with incorrect HSTS header
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
    const server = http.createServer((req, res) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=8000000');
        res.end('Sensitive data with insufficient HSTS protection');
    });
    
    server.listen(3000);
}
// {/fact}

// Express with dynamic but insufficient max-age
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    const maxAgeInDays = 30; // Only 30 days
    
    app.use((req, res, next) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', `max-age=${maxAgeInDays * 86400}; includeSubDomains`);
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with dynamically set but insufficient HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using a custom middleware with incorrect HSTS implementation
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    function securityHeaders(req, res, next) {
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15551999; includeSubDomains'); // Just under the recommended minimum
        next();
    }
    
    app.use(securityHeaders);
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with almost-but-not-quite sufficient HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using a configuration object with incorrect settings
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    const securityConfig = {
        hstsMaxAge: 15000000, // Less than recommended
        hstsIncludeSubdomains: true
    };
    
    app.use((req, res, next) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 
            `max-age=${securityConfig.hstsMaxAge}; includeSubDomains=${securityConfig.hstsIncludeSubdomains}`);
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with configurable but insufficient HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using Express response methods directly with incorrect HSTS
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/', (req, res) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.header('Strict-Transport-Security', 'max-age=31536000'); // Missing includeSubDomains
        res.send('Sensitive data with incomplete HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using conditional HSTS that sometimes fails to set proper headers
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.use((req, res, next) => {
        if (req.secure) {
            // ruleid: javascript-enforce-strict-transport-security
            res.setHeader('Strict-Transport-Security', 'max-age=10000000; includeSubDomains'); // Too short
        }
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with conditional but insufficient HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using a third-party middleware with incorrect configuration
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    function hstsMiddleware(options) {
        return (req, res, next) => {
            // ruleid: javascript-enforce-strict-transport-security
            res.setHeader('Strict-Transport-Security', 
                `max-age=${options.maxAge}; ${options.includeSubDomains ? 'includeSubDomains' : ''}`);
            next();
        };
    }
    
    app.use(hstsMiddleware({
        maxAge: 10000000, // Too short
        includeSubDomains: true
    }));
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with custom middleware but insufficient HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using multiple headers but with incorrect HSTS
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.use((req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15552000'); // Missing includeSubDomains
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with multiple security headers but incomplete HSTS');
    });
    
    app.listen(3000);
}
// {/fact}

// Using environment variables but with incorrect defaults
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    const hstsMaxAge = process.env.HSTS_MAX_AGE || 10000000; // Default is too short
    const hstsIncludeSubDomains = process.env.HSTS_INCLUDE_SUBDOMAINS === 'true' || false; // Default is false
    
    app.use((req, res, next) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 
            `max-age=${hstsMaxAge}${hstsIncludeSubDomains ? '; includeSubDomains' : ''}`);
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with environment-configurable but insufficient HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using a configuration file with incorrect settings
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    // Simulating loading from a config file
    const config = {
        security: {
            hsts: {
                maxAge: 15000000, // Too short
                includeSubDomains: true
            }
        }
    };
    
    app.use((req, res, next) => {
        // ruleid: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 
            `max-age=${config.security.hsts.maxAge}; ${config.security.hsts.includeSubDomains ? 'includeSubDomains' : ''}`);
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with config-file-based but insufficient HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// GOOD CASES - Secure implementations

// Proper HSTS with sufficient max-age and includeSubDomains
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.use((req, res, next) => {
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Proper HSTS with longer max-age and includeSubDomains
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.use((req, res, next) => {
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Proper HSTS with includeSubDomains and preload
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.use((req, res, next) => {
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with proper HSTS protection including preload');
    });
    
    app.listen(3000);
}
// {/fact}

// Using helmet with proper HSTS configuration
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    // ok: javascript-enforce-strict-transport-security
    app.use(helmet.hsts({
        maxAge: 15552000,
        includeSubDomains: true
    }));
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with proper HSTS protection via helmet');
    });
    
    app.listen(3000);
}
// {/fact}

// Using helmet with even stronger HSTS configuration
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    // ok: javascript-enforce-strict-transport-security
    app.use(helmet.hsts({
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    }));
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with strong HSTS protection via helmet');
    });
    
    app.listen(3000);
}
// {/fact}

// Node.js https server with proper HSTS header
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
    const options = {
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.cert')
    };
    
    const server = https.createServer(options, (req, res) => {
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
        res.end('Sensitive data with proper HSTS protection');
    });
    
    server.listen(3000);
}
// {/fact}

// Express with dynamic but sufficient max-age
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
    const app = express();
    const maxAgeInDays = 180; // 180 days (more than 15552000 seconds)
    
    app.use((req, res, next) => {
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', `max-age=${maxAgeInDays * 86400}; includeSubDomains`);
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with dynamically set proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using a custom middleware with correct HSTS implementation
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    function securityHeaders(req, res, next) {
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
        next();
    }
    
    app.use(securityHeaders);
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with proper HSTS protection via custom middleware');
    });
    
    app.listen(3000);
}
// {/fact}

// Using a configuration object with correct settings
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    const securityConfig = {
        hstsMaxAge: 15552000,
        hstsIncludeSubdomains: true
    };
    
    app.use((req, res, next) => {
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 
            `max-age=${securityConfig.hstsMaxAge}; includeSubDomains`);
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with configurable proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using Express response methods directly with correct HSTS
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/', (req, res) => {
        // ok: javascript-enforce-strict-transport-security
        res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        res.send('Sensitive data with proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using conditional HSTS that always sets proper headers when needed
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.use((req, res, next) => {
        if (req.secure) {
            // ok: javascript-enforce-strict-transport-security
            res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with conditional but proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using a third-party middleware with correct configuration
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    function hstsMiddleware(options) {
        return (req, res, next) => {
            // ok: javascript-enforce-strict-transport-security
            res.setHeader('Strict-Transport-Security', 
                `max-age=${options.maxAge}; ${options.includeSubDomains ? 'includeSubDomains' : ''}`);
            next();
        };
    }
    
    app.use(hstsMiddleware({
        maxAge: 15552000,
        includeSubDomains: true
    }));
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with custom middleware and proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using multiple headers with correct HSTS
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.use((req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with multiple security headers including proper HSTS');
    });
    
    app.listen(3000);
}
// {/fact}

// Using environment variables with correct defaults
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    const hstsMaxAge = process.env.HSTS_MAX_AGE || 15552000; // Default is sufficient
    const hstsIncludeSubDomains = process.env.HSTS_INCLUDE_SUBDOMAINS !== 'false'; // Default is true
    
    app.use((req, res, next) => {
        // ok: javascript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 
            `max-age=${hstsMaxAge}${hstsIncludeSubDomains ? '; includeSubDomains' : ''}`);
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with environment-configurable proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}

// Using a configuration file with correct settings
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    // Simulating loading from a config file
    const config = {
        security: {
            hsts: {
                maxAge: 31536000, // 1 year
                includeSubDomains: true,
                preload: true
            }
        }
    };
    
    app.use((req, res, next) => {
        // ok: javascript-enforce-strict-transport-security
        const hstsValue = `max-age=${config.security.hsts.maxAge}; ${config.security.hsts.includeSubDomains ? 'includeSubDomains' : ''}${config.security.hsts.preload ? '; preload' : ''}`;
        res.setHeader('Strict-Transport-Security', hstsValue);
        next();
    });
    
    app.get('/', (req, res) => {
        res.send('Sensitive data with config-file-based proper HSTS protection');
    });
    
    app.listen(3000);
}
// {/fact}