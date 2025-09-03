// File: insecure-createnodesfrommarkup-test-cases.ts

import * as express from 'express';
import * as http from 'http';
import * as url from 'url';
import * as DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

// Initialize Express app and DOM environment for examples
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Setup JSDOM for DOM manipulation examples
const { window } = new JSDOM('<!DOCTYPE html><html><body></body></html>');
const document = window.document;

// Vulnerable examples (True Positives)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    app.get('/profile', (req, res) => {
        const username = req.query.username as string;
        
        // Using untrusted input directly in createNodesFromMarkup
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const nodes = document.createNodesFromMarkup(username, true);
        
        document.body.appendChild(nodes);
        res.send('Profile updated');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    app.post('/comment', (req, res) => {
        const comment = req.body.comment;
        
        // Using untrusted POST data in createNodes
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const commentNodes = document.createNodes(comment);
        
        document.getElementById('comments').appendChild(commentNodes);
        res.send('Comment added');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    app.get('/search', (req, res) => {
        const searchTerm = req.query.q as string;
        
        // Using query parameter in generateNodes
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const resultNodes = document.generateNodes(`<div>${searchTerm}</div>`);
        
        document.getElementById('results').appendChild(resultNodes);
        res.send('Search completed');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const userInput = parsedUrl.query.content as string;
        
        // Using URL parameter in createNodesFromMarkup
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const nodes = document.createNodesFromMarkup(`<p>${userInput}</p>`, false);
        
        // Use nodes in the response
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end('Content added');
    }).listen(8080);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    app.get('/template', (req, res) => {
        const template = req.query.template as string;
        let processedTemplate = '';
        
        if (template.length > 10) {
            processedTemplate = template.substring(0, 10);
        } else {
            processedTemplate = template;
        }
        
        // Still vulnerable despite some processing
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const nodes = document.createNodes(processedTemplate);
        
        document.body.appendChild(nodes);
        res.send('Template applied');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    app.get('/header', (req, res) => {
        const customHeader = req.headers['x-custom-header'] as string;
        
        // Using header value in generateNodes
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const headerNodes = document.generateNodes(customHeader);
        
        document.getElementById('header').appendChild(headerNodes);
        res.send('Header applied');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    app.post('/article', (req, res) => {
        const articleContent = req.body.content;
        const articleTitle = req.body.title;
        
        // Concatenating multiple user inputs
        const articleMarkup = `<h1>${articleTitle}</h1><div>${articleContent}</div>`;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const articleNodes = document.createNodesFromMarkup(articleMarkup, true);
        
        document.getElementById('articles').appendChild(articleNodes);
        res.send('Article published');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    app.get('/widget', (req, res) => {
        const widgetId = req.query.id as string;
        const widgetTitle = req.query.title as string;
        
        // Using multiple query parameters
        let widgetContent = '';
        switch(widgetId) {
            case '1':
                widgetContent = `<div class="widget">${widgetTitle}</div>`;
                break;
            default:
                widgetContent = `<div class="default-widget">${widgetTitle}</div>`;
        }
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const widgetNodes = document.createNodes(widgetContent);
        
        document.body.appendChild(widgetNodes);
        res.send('Widget added');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    app.get('/cookie-display', (req, res) => {
        const cookieValue = req.cookies.userPreference;
        
        // Using cookie value in generateNodes
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const prefNodes = document.generateNodes(`<div>${cookieValue}</div>`);
        
        document.getElementById('preferences').appendChild(prefNodes);
        res.send('Preferences loaded');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    app.post('/format-text', (req, res) => {
        const text = req.body.text;
        const format = req.body.format;
        
        let formattedText = '';
        if (format === 'bold') {
            formattedText = `<strong>${text}</strong>`;
        } else if (format === 'italic') {
            formattedText = `<em>${text}</em>`;
        } else {
            formattedText = `<span>${text}</span>`;
        }
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const textNodes = document.createNodesFromMarkup(formattedText, false);
        
        document.getElementById('formatted-text').appendChild(textNodes);
        res.send('Text formatted');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    app.get('/user-card', (req, res) => {
        const userId = req.query.id as string;
        
        // Fetch user data from database (simulated)
        const userData = { name: "User " + userId };
        
        // Using user-influenced data
        const cardHTML = `<div class="card">User: ${userData.name}</div>`;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const cardNodes = document.createNodes(cardHTML);
        
        document.getElementById('user-cards').appendChild(cardNodes);
        res.send('Card created');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    app.get('/embed', (req, res) => {
        const embedCode = req.query.code as string;
        
        try {
            // Attempting to decode but still vulnerable
            const decodedEmbed = decodeURIComponent(embedCode);
            
            // ruleid: insecure-createnodesfrommarkup-ts-rule
            const embedNodes = document.generateNodes(decodedEmbed);
            
            document.getElementById('embeds').appendChild(embedNodes);
            res.send('Content embedded');
        } catch (e) {
            res.status(400).send('Invalid embed code');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    app.get('/notification', (req, res) => {
        const message = req.query.message as string;
        const type = req.query.type as string;
        
        // Creating HTML with user input
        let notificationHTML = '';
        if (type === 'success') {
            notificationHTML = `<div class="success">${message}</div>`;
        } else if (type === 'error') {
            notificationHTML = `<div class="error">${message}</div>`;
        } else {
            notificationHTML = `<div class="info">${message}</div>`;
        }
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const notificationNodes = document.createNodesFromMarkup(notificationHTML, true);
        
        document.getElementById('notifications').appendChild(notificationNodes);
        res.send('Notification shown');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    app.post('/preview', (req, res) => {
        const htmlContent = req.body.html;
        
        // Directly using user-provided HTML
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const previewNodes = document.createNodes(htmlContent);
        
        document.getElementById('preview').appendChild(previewNodes);
        res.send('Preview generated');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    app.get('/dynamic-content', (req, res) => {
        const contentId = req.query.id as string;
        const contentTitle = req.query.title as string;
        const contentBody = req.query.body as string;
        
        // Complex HTML construction with multiple user inputs
        const contentHTML = `
            <article id="content-${contentId}">
                <h2>${contentTitle}</h2>
                <div class="content-body">${contentBody}</div>
                <footer>Content ID: ${contentId}</footer>
            </article>
        `;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const contentNodes = document.generateNodes(contentHTML);
        
        document.getElementById('dynamic-content').appendChild(contentNodes);
        res.send('Dynamic content loaded');
    });
}
// {/fact}

// Safe examples (True Negatives)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    app.get('/profile', (req, res) => {
        const username = req.query.username as string;
        
        // Sanitizing input before using createNodesFromMarkup
        const sanitizedUsername = DOMPurify.sanitize(username);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const nodes = document.createNodesFromMarkup(sanitizedUsername, true);
        
        document.body.appendChild(nodes);
        res.send('Profile updated safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    app.post('/comment', (req, res) => {
        const comment = req.body.comment;
        
        // Using text content instead of HTML
        const commentElement = document.createElement('div');
        commentElement.textContent = comment; // Safe: assigns as text, not HTML
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        document.getElementById('comments').appendChild(commentElement);
        
        res.send('Comment added safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    app.get('/search', (req, res) => {
        const searchTerm = req.query.q as string;
        
        // Escaping HTML special characters
        const escapedTerm = searchTerm
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const resultNodes = document.generateNodes(`<div>${escapedTerm}</div>`);
        
        document.getElementById('results').appendChild(resultNodes);
        res.send('Search completed safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const userInput = parsedUrl.query.content as string;
        
        // Using createElement and textContent instead
        const paragraph = document.createElement('p');
        paragraph.textContent = userInput; // Safe: assigns as text, not HTML
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        document.body.appendChild(paragraph);
        
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end('Content added safely');
    }).listen(8080);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    app.get('/template', (req, res) => {
        const template = req.query.template as string;
        
        // Using a whitelist of allowed templates
        const allowedTemplates = {
            'info': '<div class="info-box"></div>',
            'warning': '<div class="warning-box"></div>',
            'error': '<div class="error-box"></div>'
        };
        
        // Only use predefined templates, not user input directly
        const safeTemplate = allowedTemplates[template] || allowedTemplates['info'];
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const nodes = document.createNodes(safeTemplate);
        
        document.body.appendChild(nodes);
        res.send('Template applied safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    app.get('/header', (req, res) => {
        const customHeader = req.headers['x-custom-header'] as string;
        
        // Sanitize header value
        const sanitizedHeader = DOMPurify.sanitize(customHeader);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const headerNodes = document.generateNodes(sanitizedHeader);
        
        document.getElementById('header').appendChild(headerNodes);
        res.send('Header applied safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    app.post('/article', (req, res) => {
        const articleContent = req.body.content;
        const articleTitle = req.body.title;
        
        // Create elements safely
        const articleContainer = document.createElement('div');
        
        const titleElement = document.createElement('h1');
        titleElement.textContent = articleTitle;
        
        const contentElement = document.createElement('div');
        contentElement.textContent = articleContent;
        
        articleContainer.appendChild(titleElement);
        articleContainer.appendChild(contentElement);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        document.getElementById('articles').appendChild(articleContainer);
        
        res.send('Article published safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    app.get('/widget', (req, res) => {
        const widgetId = req.query.id as string;
        const widgetTitle = req.query.title as string;
        
        // Create widget safely
        const widgetElement = document.createElement('div');
        widgetElement.className = widgetId === '1' ? 'widget' : 'default-widget';
        
        const titleElement = document.createElement('h2');
        titleElement.textContent = widgetTitle;
        
        widgetElement.appendChild(titleElement);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        document.body.appendChild(widgetElement);
        
        res.send('Widget added safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    app.get('/cookie-display', (req, res) => {
        const cookieValue = req.cookies.userPreference;
        
        // Sanitize cookie value
        const sanitizedValue = DOMPurify.sanitize(cookieValue);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const prefNodes = document.generateNodes(`<div>${sanitizedValue}</div>`);
        
        document.getElementById('preferences').appendChild(prefNodes);
        res.send('Preferences loaded safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    app.post('/format-text', (req, res) => {
        const text = req.body.text;
        const format = req.body.format;
        
        // Create elements safely
        const container = document.createElement('div');
        
        const textElement = document.createElement(
            format === 'bold' ? 'strong' : 
            format === 'italic' ? 'em' : 'span'
        );
        
        textElement.textContent = text;
        container.appendChild(textElement);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        document.getElementById('formatted-text').appendChild(container);
        
        res.send('Text formatted safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    app.get('/user-card', (req, res) => {
        const userId = req.query.id as string;
        
        // Fetch user data from database (simulated)
        const userData = { name: "User " + userId };
        
        // Create card element safely
        const cardElement = document.createElement('div');
        cardElement.className = 'card';
        
        const nameElement = document.createElement('span');
        nameElement.textContent = `User: ${userData.name}`;
        
        cardElement.appendChild(nameElement);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        document.getElementById('user-cards').appendChild(cardElement);
        
        res.send('Card created safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    app.get('/embed', (req, res) => {
        const embedCode = req.query.code as string;
        
        try {
            // Decode and sanitize
            const decodedEmbed = decodeURIComponent(embedCode);
            const sanitizedEmbed = DOMPurify.sanitize(decodedEmbed, {
                ALLOWED_TAGS: ['iframe'],
                ALLOWED_ATTR: ['src', 'width', 'height']
            });
            
            // ok: insecure-createnodesfrommarkup-ts-rule
            const embedNodes = document.generateNodes(sanitizedEmbed);
            
            document.getElementById('embeds').appendChild(embedNodes);
            res.send('Content embedded safely');
        } catch (e) {
            res.status(400).send('Invalid embed code');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    app.get('/notification', (req, res) => {
        const message = req.query.message as string;
        const type = req.query.type as string;
        
        // Create notification safely
        const notificationElement = document.createElement('div');
        
        // Set class based on type
        if (type === 'success') {
            notificationElement.className = 'success';
        } else if (type === 'error') {
            notificationElement.className = 'error';
        } else {
            notificationElement.className = 'info';
        }
        
        notificationElement.textContent = message;
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        document.getElementById('notifications').appendChild(notificationElement);
        
        res.send('Notification shown safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    app.post('/preview', (req, res) => {
        const htmlContent = req.body.html;
        
        // Sanitize HTML content
        const sanitizedHTML = DOMPurify.sanitize(htmlContent, {
            ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li'],
            ALLOWED_ATTR: []
        });
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const previewNodes = document.createNodes(sanitizedHTML);
        
        document.getElementById('preview').appendChild(previewNodes);
        res.send('Preview generated safely');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    app.get('/dynamic-content', (req, res) => {
        const contentId = req.query.id as string;
        const contentTitle = req.query.title as string;
        const contentBody = req.query.body as string;
        
        // Create content safely
        const article = document.createElement('article');
        article.id = `content-${contentId}`;
        
        const title = document.createElement('h2');
        title.textContent = contentTitle;
        
        const body = document.createElement('div');
        body.className = 'content-body';
        body.textContent = contentBody;
        
        const footer = document.createElement('footer');
        footer.textContent = `Content ID: ${contentId}`;
        
        article.appendChild(title);
        article.appendChild(body);
        article.appendChild(footer);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        document.getElementById('dynamic-content').appendChild(article);
        
        res.send('Dynamic content loaded safely');
    });
}
// {/fact}

// Start the server
const server = app.listen(3000, () => {
    console.log('Server is running on port 3000');
});

export { server };