const express = require('express');
const app = express();
const http = require('http');
const https = require('https');
const axios = require('axios');
const url = require('url');
const validator = require('validator');
const sanitizeHtml = require('sanitize-html');
const { createServer } = require('http');

// True Positive Examples (Vulnerable Code)

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_1(req, res) {
    // Using user input directly in a response header
    const redirectUrl = req.query.url;
    
    // ruleid: javascript-header-injection
    res.setHeader('Location', redirectUrl);
    res.status(302).end();
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_2(req, res) {
    // Using user input from POST body in a response header
    const contentType = req.body.type;
    
    // ruleid: javascript-header-injection
    res.setHeader('Content-Type', contentType);
    res.send('Content type set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_3(req, res) {
    // Using user input from URL parameters in a custom header
    const userToken = req.params.token;
    
    // ruleid: javascript-header-injection
    res.setHeader('X-User-Token', userToken);
    res.send('User authenticated');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_4(req, res) {
    // Using user input from headers in another header
    const userAgent = req.headers['user-agent'];
    
    // ruleid: javascript-header-injection
    res.setHeader('X-Original-User-Agent', userAgent);
    res.send('Request processed');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_5(req, res) {
    // Using user input in multiple headers
    const lang = req.query.language;
    
    // ruleid: javascript-header-injection
    res.setHeader('Content-Language', lang);
    res.send('Language preference set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_6(req, res) {
    // Using user input in header with string concatenation
    const fileName = req.query.file;
    
    // ruleid: javascript-header-injection
    res.setHeader('Content-Disposition', 'attachment; filename=' + fileName);
    res.send('File download initiated');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_7(req, res) {
    // Using user input in header with template literals
    const origin = req.query.origin;
    
    // ruleid: javascript-header-injection
    res.setHeader('Access-Control-Allow-Origin', `${origin}`);
    res.send('CORS headers set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_8(req, res) {
    // Using user input from cookies in a header
    const theme = req.cookies.theme;
    
    // ruleid: javascript-header-injection
    res.setHeader('X-Theme', theme);
    res.send('Theme applied');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_9(req, res) {
    // Using user input in header after basic transformation
    const userId = req.query.id;
    const encodedId = Buffer.from(userId).toString('base64');
    
    // ruleid: javascript-header-injection
    res.setHeader('X-User-Id', encodedId);
    res.send('User ID encoded');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_10(req, res) {
    // Using user input in header with conditional logic
    let cacheControl = 'no-cache';
    if (req.query.cache === 'true') {
        cacheControl = req.query.cacheTime || '3600';
    }
    
    // ruleid: javascript-header-injection
    res.setHeader('Cache-Control', `max-age=${cacheControl}`);
    res.send('Cache settings applied');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_11(req, res) {
    // Using user input in header via object property
    const preferences = {
        format: req.query.format || 'json'
    };
    
    // ruleid: javascript-header-injection
    res.setHeader('X-Preferred-Format', preferences.format);
    res.json({ success: true });
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_12(req, res) {
    // Using user input in header after array operations
    const tags = req.query.tags ? req.query.tags.split(',') : [];
    const tagString = tags.join(';');
    
    // ruleid: javascript-header-injection
    res.setHeader('X-Content-Tags', tagString);
    res.send('Tags processed');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_13(req, res) {
    // Using user input in header with error handling
    let version;
    try {
        version = req.query.version || '1.0';
    } catch (e) {
        version = '1.0';
    }
    
    // ruleid: javascript-header-injection
    res.setHeader('X-API-Version', version);
    res.send('API version set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_14(req, res) {
    // Using user input in header with async operation
    const userRole = req.query.role;
    
    setTimeout(() => {
        // ruleid: javascript-header-injection
        res.setHeader('X-User-Role', userRole);
        res.send('Role processed');
    }, 100);
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_15(req, res) {
    // Using user input in header with object destructuring
    const { format, encoding } = req.query;
    
    // ruleid: javascript-header-injection
    res.setHeader('X-Content-Encoding', encoding);
    res.send(`Content will be encoded with ${encoding}`);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_1(req, res) {
    // Using hardcoded value in a response header
    // ok: javascript-header-injection
    res.setHeader('Location', '/dashboard');
    res.status(302).end();
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_2(req, res) {
    // Validating user input before using in a response header
    const redirectUrl = req.query.url;
    
    const allowedUrls = ['/home', '/dashboard', '/profile'];
    if (allowedUrls.includes(redirectUrl)) {
        // ok: javascript-header-injection
        res.setHeader('Location', redirectUrl);
        res.status(302).end();
    } else {
        res.status(400).send('Invalid redirect URL');
    }
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_3(req, res) {
    // Using a whitelist for content type
    const contentType = req.body.type;
    const allowedTypes = ['application/json', 'text/plain', 'text/html'];
    
    if (allowedTypes.includes(contentType)) {
        // ok: javascript-header-injection
        res.setHeader('Content-Type', contentType);
        res.send('Content type set');
    } else {
        res.setHeader('Content-Type', 'application/json');
        res.send('Default content type applied');
    }
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_4(req, res) {
    // Using regex validation for user input
    const lang = req.query.language;
    
    if (/^[a-z]{2}(-[A-Z]{2})?$/.test(lang)) {
        // ok: javascript-header-injection
        res.setHeader('Content-Language', lang);
        res.send('Language preference set');
    } else {
        res.setHeader('Content-Language', 'en-US');
        res.send('Default language set');
    }
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_5(req, res) {
    // Using a validator library
    const fileName = req.query.file;
    
    if (validator.isAlphanumeric(fileName)) {
        // ok: javascript-header-injection
        res.setHeader('Content-Disposition', `attachment; filename=${fileName}.pdf`);
        res.send('File download initiated');
    } else {
        res.status(400).send('Invalid filename');
    }
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_6(req, res) {
    // Sanitizing user input before using in a header
    const origin = req.query.origin;
    
    // Validate origin is a proper URL
    try {
        const parsedUrl = new URL(origin);
        // ok: javascript-header-injection
        res.setHeader('Access-Control-Allow-Origin', parsedUrl.origin);
        res.send('CORS headers set');
    } catch (e) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send('Default CORS headers set');
    }
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_7(req, res) {
    // Using environment variables instead of user input
    // ok: javascript-header-injection
    res.setHeader('X-Powered-By', process.env.APP_NAME || 'MyApp');
    res.send('Headers set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_8(req, res) {
    // Using a mapping to validate user input
    const theme = req.cookies.theme;
    const themeMap = {
        'dark': 'theme-dark',
        'light': 'theme-light',
        'blue': 'theme-blue'
    };
    
    // ok: javascript-header-injection
    res.setHeader('X-Theme', themeMap[theme] || 'theme-default');
    res.send('Theme applied');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_9(req, res) {
    // Using numeric validation for user input
    const userId = req.query.id;
    
    if (/^\d+$/.test(userId)) {
        // ok: javascript-header-injection
        res.setHeader('X-User-Id', userId);
        res.send('User ID validated');
    } else {
        res.status(400).send('Invalid user ID');
    }
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_10(req, res) {
    // Using a function to validate cache control values
    const cacheTime = req.query.cacheTime;
    
    function isValidCacheTime(time) {
        const num = parseInt(time, 10);
        return !isNaN(num) && num >= 0 && num <= 86400; // 0 to 24 hours
    }
    
    if (isValidCacheTime(cacheTime)) {
        // ok: javascript-header-injection
        res.setHeader('Cache-Control', `max-age=${cacheTime}`);
        res.send('Cache settings applied');
    } else {
        res.setHeader('Cache-Control', 'no-cache');
        res.send('Default cache settings applied');
    }
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_11(req, res) {
    // Using a switch statement to validate format
    const format = req.query.format;
    let validFormat;
    
    switch(format) {
        case 'json':
            validFormat = 'application/json';
            break;
        case 'xml':
            validFormat = 'application/xml';
            break;
        case 'text':
            validFormat = 'text/plain';
            break;
        default:
            validFormat = 'application/json';
    }
    
    // ok: javascript-header-injection
    res.setHeader('Content-Type', validFormat);
    res.send('Format validated');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_12(req, res) {
    // Using array filter to validate tags
    const tags = req.query.tags ? req.query.tags.split(',') : [];
    const validTags = tags.filter(tag => /^[a-z0-9-]+$/i.test(tag));
    const tagString = validTags.join(';');
    
    // ok: javascript-header-injection
    res.setHeader('X-Content-Tags', tagString);
    res.send('Tags validated and processed');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_13(req, res) {
    // Using semantic versioning validation
    const version = req.query.version;
    
    if (/^\d+\.\d+\.\d+$/.test(version)) {
        // ok: javascript-header-injection
        res.setHeader('X-API-Version', version);
        res.send('API version validated');
    } else {
        res.setHeader('X-API-Version', '1.0.0');
        res.send('Default API version set');
    }
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_14(req, res) {
    // Using a map of allowed roles
    const userRole = req.query.role;
    const allowedRoles = new Set(['admin', 'user', 'guest', 'moderator']);
    
    // ok: javascript-header-injection
    res.setHeader('X-User-Role', allowedRoles.has(userRole) ? userRole : 'guest');
    res.send('Role validated');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_15(req, res) {
    // Using object destructuring with default values
    const { encoding = 'utf-8' } = req.query;
    const validEncodings = ['utf-8', 'ascii', 'base64'];
    
    // ok: javascript-header-injection
    res.setHeader('X-Content-Encoding', validEncodings.includes(encoding) ? encoding : 'utf-8');
    res.send(`Content will be encoded with validated encoding`);
}
// {/fact}