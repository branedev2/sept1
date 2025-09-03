// File: xss_examples.ts

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

// TRUE POSITIVES (Vulnerable Code Examples)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const username = req.query.username as string;
    // Directly inserting user input into HTML
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<div>Welcome, ${username}!</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const comment = req.body.comment as string;
    let html = '<div class="comment-section">';
    // ruleid: typescript-cross-site-scripting-ide
    html += `<p>${comment}</p>`;
    html += '</div>';
    res.send(html);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const searchTerm = req.query.q as string;
    // Using innerHTML with user input
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            // ruleid: typescript-cross-site-scripting-ide
            document.getElementById('search-results').innerHTML = '<h2>Results for: ${searchTerm}</h2>';
        });
    `;
    res.send(`<html><head><script>${script}</script></head><body><div id="search-results"></div></body></html>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userId = req.params.id;
    // Using dangerouslySetInnerHTML in React-like code
    const reactComponent = `
        function UserProfile() {
            // ruleid: typescript-cross-site-scripting-ide
            return <div dangerouslySetInnerHTML={{ __html: 'User ID: ${userId}' }} />;
        }
    `;
    res.send(reactComponent);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const userInput = req.query.input as string;
    // Using eval with user input
    // ruleid: typescript-cross-site-scripting-ide
    eval(`const userMessage = "${userInput}"`);
    res.send(`<div>Processed</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const userStyle = req.query.style as string;
    // Injecting user input into style attribute
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<div style="${userStyle}">Styled content</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const userUrl = req.query.url as string;
    // Injecting user input into href attribute
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<a href="${userUrl}">Click here</a>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const userScript = req.body.script as string;
    // Directly inserting user input into script tag
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<script>${userScript}</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const header = req.headers['x-custom-header'] as string;
    let content = '<div class="header-content">';
    // ruleid: typescript-cross-site-scripting-ide
    content += header;
    content += '</div>';
    res.send(content);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const userEvent = req.query.event as string;
    // Injecting user input into event handler
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<button onclick="${userEvent}">Click me</button>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const userCookie = req.cookies.userData;
    // Using document.write with user input
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            // ruleid: typescript-cross-site-scripting-ide
            document.write('<p>Welcome back, ${userCookie}</p>');
        });
    `;
    res.send(`<html><head><script>${script}</script></head><body></body></html>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const userInput = req.query.input as string;
    let sanitized = userInput.replace(/<script>/g, '');
    // Incomplete sanitization (only removes <script> tags)
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const userId = req.params.id;
    const userRole = req.query.role as string;
    // Multiple user inputs in template literal
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<div>User ID: ${userId}, Role: ${userRole}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const userTheme = req.query.theme as string;
    // Using user input in a data attribute
    // ruleid: typescript-cross-site-scripting-ide
    res.send(`<div data-theme="${userTheme}">Themed content</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const userInput = req.body.content as string;
    if (userInput.indexOf('<script>') === -1) {
        // Insufficient validation
        // ruleid: typescript-cross-site-scripting-ide
        res.send(`<div>${userInput}</div>`);
    } else {
        res.send('Invalid input');
    }
}
// {/fact}

// TRUE NEGATIVES (Safe Code Examples)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const username = req.query.username as string;
    // Using HTML escaping
    // ok: typescript-cross-site-scripting-ide
    res.send(`<div>Welcome, ${escape(username)}!</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const comment = req.body.comment as string;
    let html = '<div class="comment-section">';
    // Using DOMPurify for sanitization
    // ok: typescript-cross-site-scripting-ide
    html += `<p>${purify.sanitize(comment)}</p>`;
    html += '</div>';
    res.send(html);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const searchTerm = req.query.q as string;
    // Using textContent instead of innerHTML
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const element = document.getElementById('search-results');
            // ok: typescript-cross-site-scripting-ide
            element.textContent = 'Results for: ' + ${JSON.stringify(searchTerm)};
        });
    `;
    res.send(`<html><head><script>${script}</script></head><body><div id="search-results"></div></body></html>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const userId = req.params.id;
    // Using safe React pattern
    const reactComponent = `
        function UserProfile() {
            // ok: typescript-cross-site-scripting-ide
            return <div>User ID: {${JSON.stringify(userId)}}</div>;
        }
    `;
    res.send(reactComponent);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const userInput = req.query.input as string;
    // Avoiding eval, using safe alternatives
    // ok: typescript-cross-site-scripting-ide
    const userMessage = JSON.parse(JSON.stringify(userInput));
    res.send(`<div>Processed</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const userStyle = req.query.style as string;
    // Validating style against whitelist
    const allowedStyles = ['color:red', 'color:blue', 'font-weight:bold'];
    // ok: typescript-cross-site-scripting-ide
    const safeStyle = allowedStyles.includes(userStyle) ? userStyle : 'color:black';
    res.send(`<div style="${safeStyle}">Styled content</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const userUrl = req.query.url as string;
    // Validating URL protocol
    let safeUrl = '';
    if (userUrl && (userUrl.startsWith('http://') || userUrl.startsWith('https://'))) {
        // ok: typescript-cross-site-scripting-ide
        safeUrl = encodeURI(userUrl);
    } else {
        safeUrl = '#';
    }
    res.send(`<a href="${safeUrl}">Click here</a>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const userScript = req.body.script as string;
    // Using JSON for data transfer instead of injecting scripts
    // ok: typescript-cross-site-scripting-ide
    res.send(`<div id="data" data-content='${JSON.stringify({ script: userScript })}'></div>
              <script>
                const data = JSON.parse(document.getElementById('data').dataset.content);
                console.log(data.script);
              </script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const header = req.headers['x-custom-header'] as string;
    let content = '<div class="header-content">';
    // Using sanitizeHtml library
    // ok: typescript-cross-site-scripting-ide
    content += sanitizeHtml(header);
    content += '</div>';
    res.send(content);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const userEvent = req.query.event as string;
    // Using a predefined event handler instead of injecting code
    // ok: typescript-cross-site-scripting-ide
    res.send(`<button data-event="${escape(userEvent)}" onclick="handleEvent(this.dataset.event)">Click me</button>
              <script>
                function handleEvent(eventName) {
                  console.log('Event triggered:', eventName);
                }
              </script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const userCookie = req.cookies.userData;
    // Using safe DOM manipulation
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const welcomeElement = document.createElement('p');
            // ok: typescript-cross-site-scripting-ide
            welcomeElement.textContent = 'Welcome back, ' + ${JSON.stringify(userCookie)};
            document.body.appendChild(welcomeElement);
        });
    `;
    res.send(`<html><head><script>${script}</script></head><body></body></html>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const userInput = req.query.input as string;
    // Using proper HTML sanitization
    // ok: typescript-cross-site-scripting-ide
    const sanitized = sanitizeHtml(userInput, {
        allowedTags: ['b', 'i', 'em', 'strong'],
        allowedAttributes: {}
    });
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const userId = req.params.id;
    const userRole = req.query.role as string;
    // Escaping multiple inputs
    // ok: typescript-cross-site-scripting-ide
    res.send(`<div>User ID: ${escape(userId)}, Role: ${escape(userRole)}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const userTheme = req.query.theme as string;
    // Validating against a whitelist for data attributes
    const allowedThemes = ['light', 'dark', 'blue', 'green'];
    // ok: typescript-cross-site-scripting-ide
    const safeTheme = allowedThemes.includes(userTheme) ? userTheme : 'light';
    res.send(`<div data-theme="${safeTheme}">Themed content</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const userInput = req.body.content as string;
    // Using React's JSX syntax which automatically escapes content
    const reactComponent = `
        function UserContent() {
            // ok: typescript-cross-site-scripting-ide
            return <div>{${JSON.stringify(userInput)}}</div>;
        }
    `;
    res.send(reactComponent);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});