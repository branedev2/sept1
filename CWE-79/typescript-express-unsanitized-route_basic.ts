import express, { Request, Response } from 'express';
import { sanitizeHtml } from 'sanitize-html';
import { escape } from 'html-escaper';
import * as DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize DOMPurify
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// TRUE POSITIVES (Vulnerable Code)

// Case 1: Direct use of query parameter in res.send()
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userInput = req.query.userInput as string;
    // ruleid: typescript-express-unsanitized-route
    res.send(`<div>${userInput}</div>`);
}
// {/fact}

// Case 2: Direct use of body parameter in res.send()
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userMessage = req.body.message;
    // ruleid: typescript-express-unsanitized-route
    res.send(`<p>You said: ${userMessage}</p>`);
}
// {/fact}

// Case 3: Direct use of URL parameter in res.send()
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const username = req.params.username;
    // ruleid: typescript-express-unsanitized-route
    res.send(`<h1>Profile for ${username}</h1>`);
}
// {/fact}

// Case 4: Direct use of header in res.send()
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userAgent = req.headers['user-agent'];
    // ruleid: typescript-express-unsanitized-route
    res.send(`<div>Your browser: ${userAgent}</div>`);
}
// {/fact}

// Case 5: Using multiple user inputs in res.send()
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const name = req.query.name as string;
    const comment = req.body.comment;
    // ruleid: typescript-express-unsanitized-route
    res.send(`<div>Name: ${name}, Comment: ${comment}</div>`);
}
// {/fact}

// Case 6: Using user input in res.render() template data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const userInput = req.query.input as string;
    // ruleid: typescript-express-unsanitized-route
    res.render('template', { message: userInput });
}
// {/fact}

// Case 7: Using user input after string manipulation
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    let userInput = req.query.input as string;
    userInput = userInput.toUpperCase();
    // ruleid: typescript-express-unsanitized-route
    res.send(`<div>${userInput}</div>`);
}
// {/fact}

// Case 8: Using user input in HTML attributes
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const color = req.query.color as string;
    // ruleid: typescript-express-unsanitized-route
    res.send(`<div style="color:${color}">Colored text</div>`);
}
// {/fact}

// Case 9: Using user input in JavaScript code
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const userId = req.query.id as string;
    // ruleid: typescript-express-unsanitized-route
    res.send(`<script>const userId = "${userId}";</script>`);
}
// {/fact}

// Case 10: Using user input with conditional logic
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const userInput = req.query.input as string;
    let output = '';
    
    if (userInput && userInput.length > 0) {
        output = `<div>${userInput}</div>`;
    } else {
        output = '<div>No input provided</div>';
    }
    
    // ruleid: typescript-express-unsanitized-route
    res.send(output);
}
// {/fact}

// Case 11: Using user input in JSON response that might be rendered as HTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const userInput = req.query.input as string;
    const data = {
        content: userInput
    };
    
    // ruleid: typescript-express-unsanitized-route
    res.send(data);
}
// {/fact}

// Case 12: Using user input after array operations
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const tags = req.query.tags as string[];
    const tagList = tags.join(', ');
    
    // ruleid: typescript-express-unsanitized-route
    res.send(`<div>Tags: ${tagList}</div>`);
}
// {/fact}

// Case 13: Using user input in template literals with expressions
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const name = req.query.name as string;
    const age = req.query.age as string;
    
    // ruleid: typescript-express-unsanitized-route
    res.send(`<div>Name: ${name}, Age: ${parseInt(age) > 18 ? 'Adult' : 'Minor'}</div>`);
}
// {/fact}

// Case 14: Using user input in HTML with event handlers
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const callback = req.query.callback as string;
    
    // ruleid: typescript-express-unsanitized-route
    res.send(`<button onclick="${callback}()">Click me</button>`);
}
// {/fact}

// Case 15: Using user input in a complex HTML structure
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const title = req.query.title as string;
    const content = req.body.content;
    const author = req.params.author;
    
    // ruleid: typescript-express-unsanitized-route
    res.send(`
        <article>
            <h1>${title}</h1>
            <div class="content">${content}</div>
            <footer>By ${author}</footer>
        </article>
    `);
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Case 1: Sanitizing query parameter before using in res.send()
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const userInput = req.query.userInput as string;
    // ok: typescript-express-unsanitized-route
    res.send(`<div>${sanitizeHtml(userInput)}</div>`);
}
// {/fact}

// Case 2: Escaping body parameter before using in res.send()
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const userMessage = req.body.message;
    // ok: typescript-express-unsanitized-route
    res.send(`<p>You said: ${escape(userMessage)}</p>`);
}
// {/fact}

// Case 3: Using DOMPurify to sanitize URL parameter
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const username = req.params.username;
    // ok: typescript-express-unsanitized-route
    res.send(`<h1>Profile for ${purify.sanitize(username)}</h1>`);
}
// {/fact}

// Case 4: Sending user input as plain text, not HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const userInput = req.query.input as string;
    // ok: typescript-express-unsanitized-route
    res.type('text/plain').send(userInput);
}
// {/fact}

// Case 5: Using JSON.stringify for user input in JavaScript context
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const userData = req.body.data;
    // ok: typescript-express-unsanitized-route
    res.send(`<script>const userData = ${JSON.stringify(userData)};</script>`);
}
// {/fact}

// Case 6: Using encodeURIComponent for user input in URL context
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    // ok: typescript-express-unsanitized-route
    res.send(`<a href="/redirect?to=${encodeURIComponent(redirectUrl)}">Click here</a>`);
}
// {/fact}

// Case 7: Sanitizing multiple inputs
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const name = req.query.name as string;
    const comment = req.body.comment;
    // ok: typescript-express-unsanitized-route
    res.send(`<div>Name: ${sanitizeHtml(name)}, Comment: ${sanitizeHtml(comment)}</div>`);
}
// {/fact}

// Case 8: Using a template engine with auto-escaping
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const userInput = req.query.input as string;
    // ok: typescript-express-unsanitized-route
    res.render('template-with-auto-escaping', { message: userInput });
}
// {/fact}

// Case 9: Using non-user input in res.send()
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const staticHtml = '<div>Static content</div>';
    // ok: typescript-express-unsanitized-route
    res.send(staticHtml);
}
// {/fact}

// Case 10: Validating and sanitizing user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    let color = req.query.color as string;
    
    // Validate that color is a valid CSS color
    const validColors = ['red', 'blue', 'green', 'yellow', 'black', 'white'];
    if (!validColors.includes(color.toLowerCase())) {
        color = 'black'; // Default safe value
    }
    
    // ok: typescript-express-unsanitized-route
    res.send(`<div style="color:${color}">Colored text</div>`);
}
// {/fact}

// Case 11: Using numeric user input safely
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const id = req.query.id as string;
    const numericId = parseInt(id, 10);
    
    // ok: typescript-express-unsanitized-route
    res.send(`<div>ID: ${numericId}</div>`);
}
// {/fact}

// Case 12: Using JSON response with Content-Type
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const userInput = req.query.input as string;
    const data = {
        content: userInput
    };
    
    // ok: typescript-express-unsanitized-route
    res.json(data);
}
// {/fact}

// Case 13: Custom sanitization function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const userInput = req.query.input as string;
    
    function customSanitize(input: string): string {
        return input.replace(/[<>]/g, '');
    }
    
    // ok: typescript-express-unsanitized-route
    res.send(`<div>${customSanitize(userInput)}</div>`);
}
// {/fact}

// Case 14: Using a whitelist approach for HTML tags
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const userContent = req.body.content;
    
    const options = {
        allowedTags: ['b', 'i', 'em', 'strong', 'a'],
        allowedAttributes: {
            'a': ['href']
        }
    };
    
    // ok: typescript-express-unsanitized-route
    res.send(`<div>${sanitizeHtml(userContent, options)}</div>`);
}
// {/fact}

// Case 15: Handling user input in different contexts appropriately
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const title = req.query.title as string;
    const content = req.body.content;
    const author = req.params.author;
    
    // ok: typescript-express-unsanitized-route
    res.send(`
        <article>
            <h1>${sanitizeHtml(title)}</h1>
            <div class="content">${sanitizeHtml(content)}</div>
            <footer>By ${sanitizeHtml(author)}</footer>
        </article>
    `);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});