import express from 'express';
import { Request, Response, NextFunction } from 'express';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { sanitizeHeader } from 'header-sanitizer'; // Hypothetical sanitization library

// True Positive Examples (Vulnerable Code)

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    // ruleid: typescript-header-injection
    res.setHeader('Location', redirectUrl);
    res.status(302).end();
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userAgent = req.headers['user-agent'] as string;
    // ruleid: typescript-header-injection
    res.setHeader('X-User-Agent', userAgent);
    res.send('User agent logged');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const referer = req.query.referer as string;
    // ruleid: typescript-header-injection
    res.header('Referer', referer);
    res.send('Referer set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const customHeader = req.body.headerValue;
    // ruleid: typescript-header-injection
    res.set('X-Custom-Header', customHeader);
    res.json({ success: true });
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const contentType = req.query.type as string;
    // ruleid: typescript-header-injection
    res.setHeader('Content-Type', contentType);
    res.send('Content type set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const language = req.headers['accept-language'];
    // ruleid: typescript-header-injection
    res.header('Content-Language', language as string);
    res.send('Language preference set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const origin = req.query.origin as string;
    // ruleid: typescript-header-injection
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.send('CORS header set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const cacheControl = req.body.cache;
    // ruleid: typescript-header-injection
    res.set('Cache-Control', cacheControl);
    res.send('Cache control set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const authToken = req.headers.authorization;
    // ruleid: typescript-header-injection
    res.header('X-Auth-Token', authToken as string);
    res.json({ authenticated: true });
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const fileName = req.query.file as string;
    // ruleid: typescript-header-injection
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send('File download initiated');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const userInput = req.body.input;
    const headerName = 'X-' + req.query.headerName;
    // ruleid: typescript-header-injection
    res.setHeader(headerName as string, userInput);
    res.send('Dynamic header set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const redirectPath = req.query.path;
    // ruleid: typescript-header-injection
    res.setHeader('Location', `https://example.com${redirectPath}`);
    res.status(302).end();
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const userProvidedValue = req.query.value as string;
    const headers: Record<string, string> = {};
    headers['X-Custom-Value'] = userProvidedValue;
    
    for (const [name, value] of Object.entries(headers)) {
        // ruleid: typescript-header-injection
        res.setHeader(name, value);
    }
    res.send('Headers set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    let headerValue: string;
    
    if (req.query.type === 'admin') {
        headerValue = 'admin';
    } else {
        headerValue = req.query.value as string;
    }
    
    // ruleid: typescript-header-injection
    res.setHeader('X-Role', headerValue);
    res.send('Role header set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const cookieValue = req.cookies.sessionId;
    // ruleid: typescript-header-injection
    res.setHeader('Set-Cookie', `auth=${cookieValue}; Path=/; HttpOnly`);
    res.send('Cookie set');
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    const safeUrl = new URL(redirectUrl).toString();
    // ok: typescript-header-injection
    res.setHeader('Location', safeUrl);
    res.status(302).end();
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    // ok: typescript-header-injection
    res.setHeader('X-User-Agent', 'Custom User Agent');
    res.send('User agent set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const referer = req.query.referer as string;
    // Validate against allowed referers
    const allowedReferers = ['https://example.com', 'https://trusted-site.com'];
    
    if (allowedReferers.includes(referer)) {
        // ok: typescript-header-injection
        res.header('Referer', referer);
    } else {
        res.header('Referer', 'https://example.com');
    }
    res.send('Referer set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const customHeader = req.body.headerValue;
    // Sanitize header value to remove any CR/LF
    const sanitizedHeader = customHeader.toString().replace(/[\r\n]+/g, '');
    
    // ok: typescript-header-injection
    res.set('X-Custom-Header', sanitizedHeader);
    res.json({ success: true });
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const contentTypeMap: Record<string, string> = {
        'html': 'text/html',
        'json': 'application/json',
        'text': 'text/plain'
    };
    
    const requestedType = req.query.type as string;
    const contentType = contentTypeMap[requestedType] || 'text/plain';
    
    // ok: typescript-header-injection
    res.setHeader('Content-Type', contentType);
    res.send('Content type set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const supportedLanguages = ['en-US', 'es-ES', 'fr-FR'];
    const requestedLanguage = req.headers['accept-language'] as string;
    
    let language = 'en-US'; // Default
    if (requestedLanguage && supportedLanguages.includes(requestedLanguage)) {
        language = requestedLanguage;
    }
    
    // ok: typescript-header-injection
    res.header('Content-Language', language);
    res.send('Language preference set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const allowedOrigins = ['https://example.com', 'https://trusted-site.com'];
    const origin = req.query.origin as string;
    
    if (origin && allowedOrigins.includes(origin)) {
        // ok: typescript-header-injection
        res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
        res.setHeader('Access-Control-Allow-Origin', 'https://example.com');
    }
    res.send('CORS header set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const validCacheOptions = ['no-cache', 'private', 'public, max-age=3600'];
    const cacheIndex = parseInt(req.body.cacheOption) || 0;
    
    // ok: typescript-header-injection
    res.set('Cache-Control', validCacheOptions[cacheIndex] || 'no-cache');
    res.send('Cache control set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    // Generate a new token instead of using user input
    const generatedToken = 'server-generated-token-' + Date.now();
    
    // ok: typescript-header-injection
    res.header('X-Auth-Token', generatedToken);
    res.json({ authenticated: true });
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const fileName = req.query.file as string;
    // Sanitize filename to prevent header injection
    const sanitizedFileName = fileName.replace(/[^\w\s.-]/g, '');
    
    // ok: typescript-header-injection
    res.setHeader('Content-Disposition', `attachment; filename="${sanitizedFileName}"`);
    res.send('File download initiated');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    // Using a fixed header name instead of user input
    const headerName = 'X-Custom-Header';
    const userInput = req.body.input;
    
    // Sanitize the value
    const sanitizedValue = userInput.toString().replace(/[\r\n]+/g, '');
    
    // ok: typescript-header-injection
    res.setHeader(headerName, sanitizedValue);
    res.send('Header set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    // Using a hypothetical sanitization function
    const redirectPath = req.query.path as string;
    const sanitizedPath = sanitizeHeader(redirectPath);
    
    // ok: typescript-header-injection
    res.setHeader('Location', `https://example.com${sanitizedPath}`);
    res.status(302).end();
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    // Using a whitelist of allowed header values
    const allowedValues = ['value1', 'value2', 'value3'];
    const userProvidedValue = req.query.value as string;
    
    if (allowedValues.includes(userProvidedValue)) {
        // ok: typescript-header-injection
        res.setHeader('X-Custom-Value', userProvidedValue);
    } else {
        res.setHeader('X-Custom-Value', 'default');
    }
    res.send('Header set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    // Using a fixed set of header values based on conditions
    let headerValue: string;
    
    if (req.query.type === 'admin' && req.session?.isAdmin) {
        headerValue = 'admin';
    } else if (req.query.type === 'user' && req.session?.userId) {
        headerValue = 'user';
    } else {
        headerValue = 'guest';
    }
    
    // ok: typescript-header-injection
    res.setHeader('X-Role', headerValue);
    res.send('Role header set');
}
// {/fact}

// {fact rule=neutralization-of-http@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    // Generate a new session ID instead of using user input
    const newSessionId = 'sess_' + Math.random().toString(36).substring(2, 15);
    
    // ok: typescript-header-injection
    res.setHeader('Set-Cookie', `auth=${newSessionId}; Path=/; HttpOnly; Secure; SameSite=Strict`);
    res.send('Cookie set');
}
// {/fact}