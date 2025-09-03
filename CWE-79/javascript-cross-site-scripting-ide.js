// JavaScript Cross-Site Scripting (XSS) Test Cases
// Rule ID: javascript-cross-site-scripting-ide
// CWE-79: Improper Neutralization of Input During Web Page Generation

// Required imports for examples
const express = require('express');
const app = express();
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);
const sanitizeHtml = require('sanitize-html');
const escapeHtml = require('escape-html');

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Direct reflection of query parameter in HTML response
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.name;
    // ruleid: javascript-cross-site-scripting-ide
    res.send(`<div>Hello, ${userInput}!</div>`);
}
// {/fact}

// Example 2: Reflecting URL parameter in innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req, res) {
    const app = document.getElementById('app');
    const userInput = new URLSearchParams(window.location.search).get('message');
    // ruleid: javascript-cross-site-scripting-ide
    app.innerHTML = `<p>${userInput}</p>`;
}
// {/fact}

// Example 3: Using document.write with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req, res) {
    const userInput = new URLSearchParams(window.location.search).get('content');
    // ruleid: javascript-cross-site-scripting-ide
    document.write(`<div class="user-content">${userInput}</div>`);
}
// {/fact}

// Example 4: Setting element's outerHTML with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    const element = document.getElementById('profile');
    const username = new URLSearchParams(window.location.search).get('username');
    // ruleid: javascript-cross-site-scripting-ide
    element.outerHTML = `<div id="profile">Welcome back, ${username}</div>`;
}
// {/fact}

// Example 5: Using eval with user input (another XSS vector)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    const code = new URLSearchParams(window.location.search).get('code');
    // ruleid: javascript-cross-site-scripting-ide
    eval(code);
}
// {/fact}

// Example 6: Using jQuery's html() method with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    const message = new URLSearchParams(window.location.search).get('message');
    // ruleid: javascript-cross-site-scripting-ide
    $('#message-container').html(message);
}
// {/fact}

// Example 7: Setting iframe srcdoc with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    const content = new URLSearchParams(window.location.search).get('content');
    const iframe = document.getElementById('preview-frame');
    // ruleid: javascript-cross-site-scripting-ide
    iframe.srcdoc = `<html><body>${content}</body></html>`;
}
// {/fact}

// Example 8: Using insertAdjacentHTML with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    const comment = new URLSearchParams(window.location.search).get('comment');
    const commentsSection = document.getElementById('comments');
    // ruleid: javascript-cross-site-scripting-ide
    commentsSection.insertAdjacentHTML('beforeend', `<div class="comment">${comment}</div>`);
}
// {/fact}

// Example 9: Setting location.href with user input without validation
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    const redirectUrl = new URLSearchParams(window.location.search).get('redirect');
    // ruleid: javascript-cross-site-scripting-ide
    window.location.href = redirectUrl; // Can lead to javascript:alert(1) style attacks
}
// {/fact}

// Example 10: Express response with user input in a script tag
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req, res) {
    const username = req.query.username;
    // ruleid: javascript-cross-site-scripting-ide
    res.send(`
        <script>
            const currentUser = "${username}";
            displayWelcomeMessage(currentUser);
        </script>
    `);
}
// {/fact}

// Example 11: Setting a custom data attribute with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    const userData = new URLSearchParams(window.location.search).get('user');
    const userElement = document.getElementById('user-info');
    // ruleid: javascript-cross-site-scripting-ide
    userElement.setAttribute('data-user', userData);
    // This can be exploited if the attribute is later used in unsafe ways
}
// {/fact}

// Example 12: Creating a new element with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    const title = new URLSearchParams(window.location.search).get('title');
    const div = document.createElement('div');
    // ruleid: javascript-cross-site-scripting-ide
    div.innerHTML = `<h1>${title}</h1>`;
    document.body.appendChild(div);
}
// {/fact}

// Example 13: Using template literals with user input in React's dangerouslySetInnerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    const content = new URLSearchParams(window.location.search).get('content');
    // ruleid: javascript-cross-site-scripting-ide
    return React.createElement('div', {
        dangerouslySetInnerHTML: {
            __html: `<p>${content}</p>`
        }
    });
}
// {/fact}

// Example 14: Setting a style attribute with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    const color = new URLSearchParams(window.location.search).get('color');
    const element = document.getElementById('themed-element');
    // ruleid: javascript-cross-site-scripting-ide
    element.style = `color: ${color}`; // Can be exploited with "color: x; behavior: url(javascript:alert(1))"
}
// {/fact}

// Example 15: Using Function constructor with user input (similar to eval)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    const userCode = new URLSearchParams(window.location.search).get('code');
    // ruleid: javascript-cross-site-scripting-ide
    const dynamicFunction = new Function(userCode);
    dynamicFunction();
}
// {/fact}

// TRUE NEGATIVES (Safe Code Examples)

// Example 1: Properly sanitizing input with DOMPurify
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req, res) {
    const userInput = req.query.name;
    // ok: javascript-cross-site-scripting-ide
    const sanitizedInput = DOMPurify.sanitize(userInput);
    res.send(`<div>Hello, ${sanitizedInput}!</div>`);
}
// {/fact}

// Example 2: Using textContent instead of innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    const app = document.getElementById('app');
    const userInput = new URLSearchParams(window.location.search).get('message');
    // ok: javascript-cross-site-scripting-ide
    app.textContent = userInput; // textContent doesn't parse HTML, so it's safe
}
// {/fact}

// Example 3: Using encodeURIComponent for URL parameters
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    const userInput = new URLSearchParams(window.location.search).get('redirect');
    // ok: javascript-cross-site-scripting-ide
    const safeUrl = encodeURIComponent(userInput);
    window.location.href = `/redirect?url=${safeUrl}`;
}
// {/fact}

// Example 4: Using sanitize-html library
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req, res) {
    const userComment = req.body.comment;
    // ok: javascript-cross-site-scripting-ide
    const sanitizedComment = sanitizeHtml(userComment, {
        allowedTags: ['b', 'i', 'em', 'strong', 'a'],
        allowedAttributes: {
            'a': ['href']
        }
    });
    res.send(`<div class="comment">${sanitizedComment}</div>`);
}
// {/fact}

// Example 5: Using escape-html library
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req, res) {
    const username = req.query.username;
    // ok: javascript-cross-site-scripting-ide
    const escapedUsername = escapeHtml(username);
    res.send(`<div>Welcome, ${escapedUsername}!</div>`);
}
// {/fact}

// Example 6: Creating text nodes instead of setting innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    const message = new URLSearchParams(window.location.search).get('message');
    const container = document.getElementById('message-container');
    // ok: javascript-cross-site-scripting-ide
    const textNode = document.createTextNode(message);
    container.appendChild(textNode);
}
// {/fact}

// Example 7: Using jQuery's text() method instead of html()
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    const message = new URLSearchParams(window.location.search).get('message');
    // ok: javascript-cross-site-scripting-ide
    $('#message-container').text(message);
}
// {/fact}

// Example 8: Validating URLs before using them
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    const redirectUrl = new URLSearchParams(window.location.search).get('redirect');
    
    // ok: javascript-cross-site-scripting-ide
    const isValidUrl = /^https?:\/\/trusted-domain\.com\/.*$/.test(redirectUrl);
    if (isValidUrl) {
        window.location.href = redirectUrl;
    } else {
        console.error('Invalid redirect URL');
    }
}
// {/fact}

// Example 9: Using React's JSX which automatically escapes values
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    const userInput = new URLSearchParams(window.location.search).get('name');
    // ok: javascript-cross-site-scripting-ide
    return React.createElement('div', null, `Hello, ${userInput}`);
    // Or in JSX: <div>Hello, {userInput}</div>
}
// {/fact}

// Example 10: Using a whitelist for allowed values
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    const requestedTheme = new URLSearchParams(window.location.search).get('theme');
    const allowedThemes = ['light', 'dark', 'blue', 'green'];
    
    // ok: javascript-cross-site-scripting-ide
    const theme = allowedThemes.includes(requestedTheme) ? requestedTheme : 'light';
    document.body.className = `theme-${theme}`;
}
// {/fact}

// Example 11: Using setAttribute with sanitized input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    const userData = new URLSearchParams(window.location.search).get('user');
    const userElement = document.getElementById('user-info');
    
    // ok: javascript-cross-site-scripting-ide
    const sanitizedData = DOMPurify.sanitize(userData);
    userElement.setAttribute('data-user', sanitizedData);
}
// {/fact}

// Example 12: Proper handling of JSON data
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    const userDataJson = new URLSearchParams(window.location.search).get('userData');
    try {
        // ok: javascript-cross-site-scripting-ide
        const userData = JSON.parse(userDataJson);
        document.getElementById('username').textContent = userData.name;
    } catch (e) {
        console.error('Invalid JSON');
    }
}
// {/fact}

// Example 13: Using template literals with proper sanitization
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req, res) {
    const title = req.query.title;
    // ok: javascript-cross-site-scripting-ide
    const sanitizedTitle = DOMPurify.sanitize(title);
    res.send(`
        <html>
            <head><title>${sanitizedTitle}</title></head>
            <body><h1>${sanitizedTitle}</h1></body>
        </html>
    `);
}
// {/fact}

// Example 14: Using a Content Security Policy header
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req, res) {
    const userContent = req.query.content;
    
    // ok: javascript-cross-site-scripting-ide
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; object-src 'none'"
    );
    res.send(`<div>${userContent}</div>`);
    // Even though content is unsanitized, CSP provides a defense layer
}
// {/fact}

// Example 15: Using a custom sanitization function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    const userInput = new URLSearchParams(window.location.search).get('input');
    
    function customSanitize(input) {
        // Simple example - in practice, use a proper library
        return input.replace(/[<>]/g, '');
    }
    
    // ok: javascript-cross-site-scripting-ide
    const sanitizedInput = customSanitize(userInput);
    document.getElementById('output').innerHTML = sanitizedInput;
}
// {/fact}

// Start the Express server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});