import express from 'express';
import { Request, Response } from 'express';
import * as http from 'http';
import * as https from 'https';
import { sanitizeHtml } from 'sanitize-html';
import { escape } from 'html-escaper';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const window = new JSDOM('').window;
const purify = DOMPurify(window);

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userInput = req.query.name as string;
    // ruleid: typescript-check-data-from-client-request
    res.cookie('username', userInput);
    res.send('Cookie set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userMessage = req.body.message;
    // ruleid: typescript-check-data-from-client-request
    res.send(`<div>${userMessage}</div>`);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const userId = req.params.id;
    // ruleid: typescript-check-data-from-client-request
    res.setHeader('X-User-Id', userId);
    res.send('Header set');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const theme = req.cookies.theme;
    // ruleid: typescript-check-data-from-client-request
    res.cookie('userTheme', theme, { maxAge: 900000 });
    res.send('Theme preference saved');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const redirectUrl = req.query.redirect as string;
    // ruleid: typescript-check-data-from-client-request
    res.redirect(redirectUrl);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const userAgent = req.headers['user-agent'] as string;
    // ruleid: typescript-check-data-from-client-request
    res.setHeader('X-Original-User-Agent', userAgent);
    res.send('Request processed');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const searchTerm = req.query.q as string;
    // ruleid: typescript-check-data-from-client-request
    res.render('search', { term: searchTerm });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const userComment = req.body.comment;
    let responseHtml = '<h1>Comments</h1>';
    // ruleid: typescript-check-data-from-client-request
    responseHtml += `<div class="comment">${userComment}</div>`;
    res.send(responseHtml);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const language = req.query.lang as string;
    // ruleid: typescript-check-data-from-client-request
    res.cookie('language', language, { httpOnly: false });
    res.send('Language preference saved');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const referer = req.headers.referer as string;
    // ruleid: typescript-check-data-from-client-request
    res.setHeader('X-Referer', referer);
    res.send('Referer logged');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const username = req.body.username;
    const password = req.body.password;
    
    if (username === 'admin' && password === 'password') {
        // ruleid: typescript-check-data-from-client-request
        res.cookie('authToken', username + ':' + Math.random().toString());
        res.redirect('/dashboard');
    } else {
        res.send('Login failed');
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const customScript = req.query.script as string;
    // ruleid: typescript-check-data-from-client-request
    res.send(`<script>${customScript}</script>`);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const contentType = req.headers['content-type'] as string;
    // ruleid: typescript-check-data-from-client-request
    res.setHeader('X-Content-Type', contentType);
    res.json({ status: 'success' });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const sessionId = req.cookies.sessionId;
    // ruleid: typescript-check-data-from-client-request
    res.cookie('backupSessionId', sessionId);
    res.send('Session backed up');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const htmlContent = req.body.content;
    // ruleid: typescript-check-data-from-client-request
    res.send(`
        <html>
            <body>
                <div id="user-content">${htmlContent}</div>
            </body>
        </html>
    `);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const userInput = req.query.name as string;
    // ok: typescript-check-data-from-client-request
    res.cookie('username', escape(userInput));
    res.send('Cookie set safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const userMessage = req.body.message;
    // ok: typescript-check-data-from-client-request
    res.send(`<div>${purify.sanitize(userMessage)}</div>`);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const userId = req.params.id;
    // Validate that userId only contains alphanumeric characters
    if (/^[a-zA-Z0-9]+$/.test(userId)) {
        // ok: typescript-check-data-from-client-request
        res.setHeader('X-User-Id', userId);
        res.send('Header set safely');
    } else {
        res.status(400).send('Invalid user ID');
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const theme = req.cookies.theme;
    // Only allow specific theme values
    const allowedThemes = ['light', 'dark', 'blue', 'green'];
    const safeTheme = allowedThemes.includes(theme) ? theme : 'light';
    // ok: typescript-check-data-from-client-request
    res.cookie('userTheme', safeTheme, { maxAge: 900000 });
    res.send('Theme preference saved safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const redirectUrl = req.query.redirect as string;
    // Whitelist of allowed redirect URLs
    const allowedRedirects = ['/home', '/dashboard', '/profile', '/settings'];
    if (allowedRedirects.includes(redirectUrl)) {
        // ok: typescript-check-data-from-client-request
        res.redirect(redirectUrl);
    } else {
        res.redirect('/home'); // Default safe redirect
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const userAgent = req.headers['user-agent'] as string;
    // ok: typescript-check-data-from-client-request
    res.setHeader('X-Original-User-Agent', encodeURIComponent(userAgent));
    res.send('Request processed safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const searchTerm = req.query.q as string;
    // ok: typescript-check-data-from-client-request
    res.render('search', { term: escape(searchTerm) });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const userComment = req.body.comment;
    let responseHtml = '<h1>Comments</h1>';
    // ok: typescript-check-data-from-client-request
    responseHtml += `<div class="comment">${sanitizeHtml(userComment)}</div>`;
    res.send(responseHtml);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const language = req.query.lang as string;
    // Validate language code format (e.g., 'en-US', 'fr', 'de-DE')
    if (/^[a-z]{2}(-[A-Z]{2})?$/.test(language)) {
        // ok: typescript-check-data-from-client-request
        res.cookie('language', language, { httpOnly: true });
        res.send('Language preference saved safely');
    } else {
        res.cookie('language', 'en', { httpOnly: true });
        res.send('Default language set');
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const referer = req.headers.referer as string;
    // ok: typescript-check-data-from-client-request
    res.setHeader('X-Referer', encodeURIComponent(referer || ''));
    res.send('Referer logged safely');
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const username = req.body.username;
    const password = req.body.password;
    
    if (username === 'admin' && password === 'password') {
        // Generate a secure token instead of using user input
        const token = Buffer.from(Math.random().toString()).toString('base64');
        // ok: typescript-check-data-from-client-request
        res.cookie('authToken', token, { httpOnly: true, secure: true });
        res.redirect('/dashboard');
    } else {
        res.send('Login failed');
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    // Instead of using client-provided script, use a predefined one
    const scriptId = req.query.scriptId as string;
    const safeScripts: {[key: string]: string} = {
        'welcome': 'console.log("Welcome to our site!");',
        'analytics': 'trackPageView();'
    };
    
    const script = safeScripts[scriptId] || '';
    // ok: typescript-check-data-from-client-request
    res.send(`<script>${script}</script>`);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const contentType = req.headers['content-type'] as string;
    // Validate content type against allowed values
    const allowedTypes = ['application/json', 'text/plain', 'application/xml'];
    const safeContentType = allowedTypes.includes(contentType) ? contentType : 'unknown';
    // ok: typescript-check-data-from-client-request
    res.setHeader('X-Content-Type', safeContentType);
    res.json({ status: 'success' });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const sessionId = req.cookies.sessionId;
    // Validate session ID format (assuming it's a UUID)
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(sessionId)) {
        // ok: typescript-check-data-from-client-request
        res.cookie('backupSessionId', sessionId, { httpOnly: true, secure: true });
        res.send('Session backed up safely');
    } else {
        res.status(400).send('Invalid session');
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const htmlContent = req.body.content;
    // ok: typescript-check-data-from-client-request
    res.send(`
        <html>
            <body>
                <div id="user-content">${DOMPurify.sanitize(htmlContent)}</div>
            </body>
        </html>
    `);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});