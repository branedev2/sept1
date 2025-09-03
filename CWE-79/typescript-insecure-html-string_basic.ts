import express from 'express';
import { Request, Response } from 'express';
import * as DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { sanitizeHtml } from 'sanitize-html';
import { escape } from 'html-escaper';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True positives (vulnerable code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const username = req.query.username as string;
    // ruleid: typescript-insecure-html-string
    const html = `<div>Welcome, ${username}!</div>`;
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const comment = req.body.comment as string;
    // ruleid: typescript-insecure-html-string
    const commentHtml = `
        <div class="comment">
            <p>${comment}</p>
            <span>Posted just now</span>
        </div>
    `;
    res.send(commentHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const searchTerm = req.query.q as string;
    // ruleid: typescript-insecure-html-string
    const resultsHtml = `<h2>Search results for: ${searchTerm}</h2>
                        <div class="results">No results found</div>`;
    res.send(resultsHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userProfile = {
        name: req.query.name as string,
        bio: req.query.bio as string
    };
    
    // ruleid: typescript-insecure-html-string
    const profileHtml = `
        <div class="profile">
            <h1>${userProfile.name}</h1>
            <p>${userProfile.bio}</p>
        </div>
    `;
    res.send(profileHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const errorMsg = req.query.error as string;
    // ruleid: typescript-insecure-html-string
    const errorHtml = `<div class="alert alert-danger">${errorMsg}</div>`;
    res.send(errorHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const header = req.headers['user-agent'] as string;
    // ruleid: typescript-insecure-html-string
    const html = `<div>You are using: ${header}</div>`;
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const links = req.body.links as string[];
    let linksHtml = '<ul>';
    
    for (const link of links) {
        // ruleid: typescript-insecure-html-string
        linksHtml += `<li><a href="${link}">${link}</a></li>`;
    }
    
    linksHtml += '</ul>';
    res.send(linksHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const title = req.query.title as string;
    const content = req.body.content as string;
    
    // ruleid: typescript-insecure-html-string
    const articleHtml = `
        <article>
            <h1>${title}</h1>
            <div class="content">${content}</div>
        </article>
    `;
    res.send(articleHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const cookie = req.cookies.preference as string;
    // ruleid: typescript-insecure-html-string
    const preferencesHtml = `<div>Your saved preference: ${cookie}</div>`;
    res.send(preferencesHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const username = req.query.username as string;
    let greeting = '';
    
    if (username) {
        // ruleid: typescript-insecure-html-string
        greeting = `<h1>Hello, ${username}!</h1>`;
    } else {
        greeting = '<h1>Hello, Guest!</h1>';
    }
    
    res.send(greeting);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const data = JSON.parse(req.body.data as string);
    // ruleid: typescript-insecure-html-string
    const html = `<div data-info="${data.info}">${data.content}</div>`;
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const referer = req.headers.referer as string;
    // ruleid: typescript-insecure-html-string
    const backLink = `<a href="${referer}">Go Back</a>`;
    res.send(backLink);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const items = req.body.items as string[];
    let tableHtml = '<table><tr><th>Item</th></tr>';
    
    for (let i = 0; i < items.length; i++) {
        // ruleid: typescript-insecure-html-string
        tableHtml += `<tr><td>${items[i]}</td></tr>`;
    }
    
    tableHtml += '</table>';
    res.send(tableHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const customStyles = req.query.style as string;
    // ruleid: typescript-insecure-html-string
    const styledDiv = `<div style="${customStyles}">Custom styled content</div>`;
    res.send(styledDiv);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const scriptSrc = req.query.script as string;
    // ruleid: typescript-insecure-html-string
    const scriptTag = `<script src="${scriptSrc}"></script>`;
    res.send(`<html><head>${scriptTag}</head><body>Content</body></html>`);
}
// {/fact}

// True negatives (safe code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const username = req.query.username as string;
    // ok: typescript-insecure-html-string
    const safeUsername = escape(username);
    const html = `<div>Welcome, ${safeUsername}!</div>`;
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const comment = req.body.comment as string;
    // ok: typescript-insecure-html-string
    const safeComment = DOMPurify.sanitize(comment);
    const commentHtml = `
        <div class="comment">
            <p>${safeComment}</p>
            <span>Posted just now</span>
        </div>
    `;
    res.send(commentHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const searchTerm = req.query.q as string;
    // ok: typescript-insecure-html-string
    res.render('search-results', { searchTerm: searchTerm });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const window = new JSDOM('').window;
    const purify = DOMPurify(window);
    
    const userProfile = {
        name: purify.sanitize(req.query.name as string),
        bio: purify.sanitize(req.query.bio as string)
    };
    
    // ok: typescript-insecure-html-string
    const profileHtml = `
        <div class="profile">
            <h1>${userProfile.name}</h1>
            <p>${userProfile.bio}</p>
        </div>
    `;
    res.send(profileHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const errorMsg = req.query.error as string;
    // ok: typescript-insecure-html-string
    res.render('error', { errorMessage: errorMsg });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    // ok: typescript-insecure-html-string
    res.send('<div>Static HTML content</div>');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const links = req.body.links as string[];
    let linksHtml = '<ul>';
    
    for (const link of links) {
        // ok: typescript-insecure-html-string
        const safeLink = escape(link);
        linksHtml += `<li><a href="${safeLink}">${safeLink}</a></li>`;
    }
    
    linksHtml += '</ul>';
    res.send(linksHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const title = req.query.title as string;
    const content = req.body.content as string;
    
    // ok: typescript-insecure-html-string
    res.render('article', { 
        title: title,
        content: content
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    // ok: typescript-insecure-html-string
    const staticHtml = `
        <div class="container">
            <h1>Welcome to our site</h1>
            <p>This is a static HTML content</p>
        </div>
    `;
    res.send(staticHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const username = req.query.username as string;
    
    // ok: typescript-insecure-html-string
    const sanitizedUsername = sanitizeHtml(username);
    const greeting = `<h1>Hello, ${sanitizedUsername}!</h1>`;
    
    res.send(greeting);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const data = JSON.parse(req.body.data as string);
    
    // Create DOM element safely
    // ok: typescript-insecure-html-string
    const div = document.createElement('div');
    div.textContent = data.content;
    div.setAttribute('data-info', data.info);
    
    res.send(div.outerHTML);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    // ok: typescript-insecure-html-string
    const safeHtml = sanitizeHtml('<p>User content</p>', {
        allowedTags: ['p', 'b', 'i', 'em', 'strong', 'a'],
        allowedAttributes: {
            'a': ['href']
        }
    });
    
    res.send(safeHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const items = req.body.items as string[];
    
    // ok: typescript-insecure-html-string
    const safeItems = items.map(item => escape(item));
    
    let tableHtml = '<table><tr><th>Item</th></tr>';
    for (let i = 0; i < safeItems.length; i++) {
        tableHtml += `<tr><td>${safeItems[i]}</td></tr>`;
    }
    tableHtml += '</table>';
    
    res.send(tableHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    // ok: typescript-insecure-html-string
    const htmlTemplate = `
        <div class="user-profile">
            <h1>{{username}}</h1>
            <p>{{bio}}</p>
        </div>
    `;
    
    // Using a template engine that automatically escapes values
    const renderedHtml = renderTemplate(htmlTemplate, {
        username: req.query.username,
        bio: req.query.bio
    });
    
    res.send(renderedHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const userInput = req.query.input as string;
    
    // Using React's JSX which automatically escapes values
    // ok: typescript-insecure-html-string
    const element = React.createElement('div', null, userInput);
    const html = ReactDOMServer.renderToString(element);
    
    res.send(html);
}
// {/fact}

// Helper function for good_case_14
function renderTemplate(template: string, data: Record<string, any>): string {
    let result = template;
    for (const key in data) {
        const value = escape(String(data[key] || ''));
        result = result.replace(new RegExp(`{{${key}}}`, 'g'), value);
    }
    return result;
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});