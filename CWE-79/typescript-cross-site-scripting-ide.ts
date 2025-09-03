import express from 'express';
import { Request, Response } from 'express';
import * as DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { escape } from 'html-escaper';
import * as sanitizeHtml from 'sanitize-html';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const window = new JSDOM('').window;
const purify = DOMPurify(window);

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const username = req.query.username as string;
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<div>Welcome, ${username}!</div>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const searchTerm = req.params.term;
    const html = `<h1>Search Results for: ${searchTerm}</h1>`;
    // ruleid: typescript-cross-site-scripting-ide
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const comment = req.body.comment;
    let responseHtml = '<div class="comment-section">';
    responseHtml += '<h3>New Comment Added:</h3>';
    // ruleid: typescript-cross-site-scripting-ide
    responseHtml += `<p>${comment}</p>`;
    responseHtml += '</div>';
    res.send(responseHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userProfile = req.body;
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`
        <div class="profile">
            <h2>${userProfile.name}</h2>
            <p>${userProfile.bio}</p>
        </div>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const errorMsg = req.query.error as string;
    // ruleid: typescript-cross-site-scripting-ide
    document.getElementById('errorContainer')!.innerHTML = errorMsg;
    res.send('Error page loaded');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const userInput = req.query.input as string;
    const element = document.createElement('div');
    // ruleid: typescript-cross-site-scripting-ide
    element.innerHTML = `User input: ${userInput}`;
    document.body.appendChild(element);
    res.send('Content updated');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const redirectUrl = req.query.redirect as string;
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<a href="${redirectUrl}">Click here to continue</a>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const userScript = req.body.customScript;
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`
        <div>
            <script>${userScript}</script>
            <p>Custom script loaded!</p>
        </div>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const userId = req.params.id;
    const userContent = req.body.content;
    let html = `<div data-user-id="${userId}">`;
    // ruleid: typescript-cross-site-scripting-ide
    html += `<div class="content">${userContent}</div>`;
    html += '</div>';
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const styles = req.query.theme as string;
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`
        <style>
            .custom-theme {
                ${styles}
            }
        </style>
        <div class="custom-theme">Themed content</div>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const header = req.headers['x-custom-header'] as string;
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<div>Header value: ${header}</div>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const cookie = req.cookies.userPreference;
    // ruleid: typescript-cross-site-scripting-ide
    document.getElementById('preferences')!.innerHTML = `Your preference: ${cookie}`;
    res.send('Preferences loaded');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    let userHtml = req.body.customHtml;
    if (userHtml.length > 100) {
        userHtml = userHtml.substring(0, 100) + '...';
    }
    // Truncating doesn't make it safe
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<div class="user-content">${userHtml}</div>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const searchParams = new URLSearchParams(req.url.split('?')[1]);
    const query = searchParams.get('q');
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<h2>Results for: ${query}</h2>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const jsonData = JSON.parse(req.body.data);
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`
        <div>
            <h3>${jsonData.title}</h3>
            <p>${jsonData.description}</p>
        </div>
    `);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const username = req.query.username as string;
    // ok: typescript-cross-site-scripting-ide
    res.send(`<div>Welcome, ${escape(username)}!</div>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const searchTerm = req.params.term;
    // ok: typescript-cross-site-scripting-ide
    const html = `<h1>Search Results for: ${sanitizeHtml(searchTerm)}</h1>`;
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const comment = req.body.comment;
    let responseHtml = '<div class="comment-section">';
    responseHtml += '<h3>New Comment Added:</h3>';
    // ok: typescript-cross-site-scripting-ide
    responseHtml += `<p>${purify.sanitize(comment)}</p>`;
    responseHtml += '</div>';
    res.send(responseHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const userProfile = req.body;
    // ok: typescript-cross-site-scripting-ide
    res.send(`
        <div class="profile">
            <h2>${escape(userProfile.name)}</h2>
            <p>${escape(userProfile.bio)}</p>
        </div>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const errorMsg = req.query.error as string;
    // ok: typescript-cross-site-scripting-ide
    document.getElementById('errorContainer')!.textContent = errorMsg;
    res.send('Error page loaded');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const userInput = req.query.input as string;
    const element = document.createElement('div');
    // ok: typescript-cross-site-scripting-ide
    element.textContent = `User input: ${userInput}`;
    document.body.appendChild(element);
    res.send('Content updated');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const redirectUrl = req.query.redirect as string;
    // Validate URL before using it
    const validatedUrl = validateAndSanitizeUrl(redirectUrl);
    if (validatedUrl) {
        // ok: typescript-cross-site-scripting-ide
        res.send(`<a href="${escape(validatedUrl)}">Click here to continue</a>`);
    } else {
        res.send('Invalid URL');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    // Don't allow user-provided scripts at all
    // ok: typescript-cross-site-scripting-ide
    res.send(`
        <div>
            <script>console.log("Safe, hardcoded script");</script>
            <p>Script loaded!</p>
        </div>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const userId = req.params.id;
    const userContent = req.body.content;
    // ok: typescript-cross-site-scripting-ide
    let html = `<div data-user-id="${escape(userId)}">`;
    html += `<div class="content">${sanitizeHtml(userContent)}</div>`;
    html += '</div>';
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const theme = req.query.theme as string;
    // Only allow specific themes from a whitelist
    const allowedThemes: Record<string, string> = {
        'dark': 'background-color: #333; color: #fff;',
        'light': 'background-color: #fff; color: #333;'
    };
    
    // ok: typescript-cross-site-scripting-ide
    const safeStyles = allowedThemes[theme] || allowedThemes['light'];
    res.send(`
        <style>
            .custom-theme {
                ${safeStyles}
            }
        </style>
        <div class="custom-theme">Themed content</div>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const header = req.headers['x-custom-header'] as string;
    // ok: typescript-cross-site-scripting-ide
    res.send(`<div>Header value: ${purify.sanitize(header)}</div>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const cookie = req.cookies.userPreference;
    // ok: typescript-cross-site-scripting-ide
    document.getElementById('preferences')!.textContent = `Your preference: ${cookie}`;
    res.send('Preferences loaded');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const userHtml = req.body.customHtml;
    // ok: typescript-cross-site-scripting-ide
    const sanitizedHtml = sanitizeHtml(userHtml, {
        allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
        allowedAttributes: {}
    });
    res.send(`<div class="user-content">${sanitizedHtml}</div>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const searchParams = new URLSearchParams(req.url.split('?')[1]);
    const query = searchParams.get('q');
    // ok: typescript-cross-site-scripting-ide
    res.send(`<h2>Results for: ${escape(query || '')}</h2>`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const jsonData = JSON.parse(req.body.data);
    // ok: typescript-cross-site-scripting-ide
    res.send(`
        <div>
            <h3>${sanitizeHtml(jsonData.title)}</h3>
            <p>${sanitizeHtml(jsonData.description)}</p>
        </div>
    `);
}
// {/fact}

// Helper function for URL validation
function validateAndSanitizeUrl(url: string): string | null {
    try {
        const parsedUrl = new URL(url);
        // Only allow http and https protocols
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return null;
        }
        return parsedUrl.toString();
    } catch (e) {
        return null;
    }
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});