// Test cases for javascript-check-data-from-client-request
// This rule detects when untrusted inputs are passed to Response objects or used to create Cookies

const express = require('express');
const app = express();
const sanitizeHtml = require('sanitize-html');
const { Cookie } = require('tough-cookie');
const cookieParser = require('cookie-parser');
const escapeHtml = require('escape-html');
const { Response } = require('node-fetch');

// True Positive Cases (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(req, res) {
    // Using user input directly in response header
    const userAgent = req.headers['user-agent'];
    // ruleid: javascript-check-data-from-client-request
    res.setHeader('X-User-Agent', userAgent);
    res.send('Response sent');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(req, res) {
    // Using query parameter directly in cookie
    const theme = req.query.theme;
    // ruleid: javascript-check-data-from-client-request
    res.cookie('theme', theme);
    res.send('Cookie set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(req, res) {
    // Using POST body data directly in response header
    const customHeader = req.body.header;
    // ruleid: javascript-check-data-from-client-request
    res.setHeader('X-Custom', customHeader);
    res.send('Custom header set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(req, res) {
    // Using URL parameter directly in cookie with options
    const userId = req.params.id;
    // ruleid: javascript-check-data-from-client-request
    res.cookie('userId', userId, { maxAge: 900000, httpOnly: true });
    res.send('User cookie set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(req, res) {
    // Using request header directly in response
    const referer = req.headers.referer;
    // ruleid: javascript-check-data-from-client-request
    res.set('X-Referer', referer);
    res.send('Referer header set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(req, res) {
    // Using multiple request inputs in cookie
    const name = req.query.name;
    const role = req.body.role;
    // ruleid: javascript-check-data-from-client-request
    res.cookie('userInfo', `${name}:${role}`);
    res.send('User info cookie set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(req, res) {
    // Using cookie input in response header
    const sessionId = req.cookies.sessionId;
    // ruleid: javascript-check-data-from-client-request
    res.setHeader('X-Session-Id', sessionId);
    res.send('Session header set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(req, res) {
    // Creating a cookie object with user input
    const userPreference = req.query.preference;
    // ruleid: javascript-check-data-from-client-request
    const cookie = new Cookie({
        key: 'preference',
        value: userPreference
    });
    res.setHeader('Set-Cookie', cookie.toString());
    res.send('Preference cookie set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(req, res) {
    // Using request input in response status message
    const statusMessage = req.query.message;
    // ruleid: javascript-check-data-from-client-request
    res.statusMessage = statusMessage;
    res.status(400).send('Custom status message set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(req, res) {
    // Using request input in redirect URL
    const redirectUrl = req.query.redirect;
    // ruleid: javascript-check-data-from-client-request
    res.redirect(redirectUrl);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(req, res) {
    // Using request input in response type
    const contentType = req.query.type;
    // ruleid: javascript-check-data-from-client-request
    res.type(contentType);
    res.send('Response with custom type');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(req, res) {
    // Using request input in response attachment
    const filename = req.query.filename;
    // ruleid: javascript-check-data-from-client-request
    res.attachment(filename);
    res.send('File attachment');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(req, res) {
    // Using request input in location header
    const location = req.body.location;
    // ruleid: javascript-check-data-from-client-request
    res.location(location);
    res.status(201).send('Resource created');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(req, res) {
    // Using request input in vary header
    const varyHeader = req.query.vary;
    // ruleid: javascript-check-data-from-client-request
    res.vary(varyHeader);
    res.send('Vary header set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(req, res) {
    // Creating a Response object with user input
    const userInput = req.query.input;
    // ruleid: javascript-check-data-from-client-request
    const response = new Response(userInput, {
        headers: { 'Content-Type': 'text/plain' }
    });
    // Using the response object
    return response;
}
// {/fact}

// True Negative Cases (Secure Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(req, res) {
    // Sanitizing user input before setting response header
    const userAgent = req.headers['user-agent'];
    const sanitizedUserAgent = userAgent.replace(/[^\w\s.-]/g, '');
    // ok: javascript-check-data-from-client-request
    res.setHeader('X-User-Agent', sanitizedUserAgent);
    res.send('Response sent safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(req, res) {
    // Validating query parameter before setting cookie
    const theme = req.query.theme;
    const allowedThemes = ['light', 'dark', 'blue'];
    const safeTheme = allowedThemes.includes(theme) ? theme : 'light';
    // ok: javascript-check-data-from-client-request
    res.cookie('theme', safeTheme);
    res.send('Cookie set safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(req, res) {
    // Using hardcoded value in response header
    // ok: javascript-check-data-from-client-request
    res.setHeader('X-Custom', 'static-safe-value');
    res.send('Custom header set safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(req, res) {
    // Sanitizing URL parameter before setting cookie
    const userId = req.params.id;
    const sanitizedUserId = userId.replace(/[^0-9]/g, '');
    // ok: javascript-check-data-from-client-request
    res.cookie('userId', sanitizedUserId, { maxAge: 900000, httpOnly: true });
    res.send('User cookie set safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(req, res) {
    // Using sanitizeHtml library to clean input
    const userContent = req.body.content;
    const cleanContent = sanitizeHtml(userContent);
    // ok: javascript-check-data-from-client-request
    res.set('X-User-Content', cleanContent);
    res.send('Content header set safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(req, res) {
    // Using escapeHtml for cookie value
    const name = req.query.name;
    const escapedName = escapeHtml(name);
    // ok: javascript-check-data-from-client-request
    res.cookie('userName', escapedName);
    res.send('User name cookie set safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(req, res) {
    // Using a whitelist for allowed values
    const action = req.query.action;
    const allowedActions = ['view', 'edit', 'delete'];
    const safeAction = allowedActions.includes(action) ? action : 'view';
    // ok: javascript-check-data-from-client-request
    res.cookie('lastAction', safeAction);
    res.send('Action cookie set safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(req, res) {
    // Using parseInt to ensure numeric value
    const itemId = req.params.id;
    const safeItemId = parseInt(itemId, 10) || 0;
    // ok: javascript-check-data-from-client-request
    res.cookie('lastItem', String(safeItemId));
    res.send('Item cookie set safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(req, res) {
    // Using a server-generated value instead of client input
    const sessionId = generateSecureSessionId(); // Assume this is a secure function
    // ok: javascript-check-data-from-client-request
    res.cookie('sessionId', sessionId, { httpOnly: true, secure: true });
    res.send('Session cookie set safely');
    
    function generateSecureSessionId() {
        return 'secure-' + Math.random().toString(36).substring(2, 15);
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(req, res) {
    // Using URL validation before redirect
    const redirectUrl = req.query.redirect;
    const isValidUrl = /^(https?:\/\/)?[\w-]+(\.[\w-]+)+\.?(:\d+)?(\/\S*)?$/.test(redirectUrl);
    const safeUrl = isValidUrl ? redirectUrl : '/default';
    // ok: javascript-check-data-from-client-request
    res.redirect(safeUrl);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(req, res) {
    // Using a whitelist for content types
    const contentType = req.query.type;
    const allowedTypes = ['text/plain', 'application/json', 'text/html'];
    const safeType = allowedTypes.includes(contentType) ? contentType : 'text/plain';
    // ok: javascript-check-data-from-client-request
    res.type(safeType);
    res.send('Response with safe type');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(req, res) {
    // Sanitizing filename for attachment
    const filename = req.query.filename;
    const safeFilename = filename.replace(/[^a-zA-Z0-9_.-]/g, '_');
    // ok: javascript-check-data-from-client-request
    res.attachment(safeFilename);
    res.send('File attachment with safe name');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(req, res) {
    // Using URL validation for location header
    const location = req.body.location;
    const safeLocation = validateAndSanitizeUrl(location);
    // ok: javascript-check-data-from-client-request
    res.location(safeLocation);
    res.status(201).send('Resource created with safe location');
    
    function validateAndSanitizeUrl(url) {
        if (/^https?:\/\/trusted-domain\.com\/\w+$/.test(url)) {
            return url;
        }
        return '/default-location';
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(req, res) {
    // Using a whitelist for vary header
    const varyHeader = req.query.vary;
    const allowedVaryValues = ['Accept', 'Accept-Encoding', 'Origin'];
    const safeVary = allowedVaryValues.includes(varyHeader) ? varyHeader : 'Accept';
    // ok: javascript-check-data-from-client-request
    res.vary(safeVary);
    res.send('Safe vary header set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(req, res) {
    // Creating a Response object with sanitized user input
    const userInput = req.query.input;
    const sanitizedInput = sanitizeHtml(userInput, {
        allowedTags: ['b', 'i', 'em', 'strong'],
        allowedAttributes: {}
    });
    // ok: javascript-check-data-from-client-request
    const response = new Response(sanitizedInput, {
        headers: { 'Content-Type': 'text/html' }
    });
    // Using the response object
    return response;
}
// {/fact}

// Start the server
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.listen(3000, () => {
    console.log('Server running on port 3000');
});