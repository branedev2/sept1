// Import necessary libraries
const express = require('express');
const app = express();
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// True Positive Examples (Vulnerable Code)

// Example 1: Direct reflection of query parameter in innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    app.get('/search', (req, res) => {
        const query = req.query.q;
        const html = `
            <div>
                <h2>Search Results for: ${query}</h2>
                <div id="results">
                    // ruleid: javascript-cross-site-scripting-ide
                    document.getElementById('results').innerHTML = query;
                </div>
            </div>
        `;
        res.send(html);
    });
}
// {/fact}

// Example 2: Reflecting user input in document.write
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    app.get('/welcome', (req, res) => {
        const username = req.query.username;
        res.send(`
            <script>
                // ruleid: javascript-cross-site-scripting-ide
                document.write("<h1>Welcome, " + username + "!</h1>");
            </script>
        `);
    });
}
// {/fact}

// Example 3: Using eval with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    app.get('/calculate', (req, res) => {
        const expression = req.query.expr;
        res.send(`
            <script>
                try {
                    // ruleid: javascript-cross-site-scripting-ide
                    const result = eval(expression);
                    document.write("Result: " + result);
                } catch (e) {
                    document.write("Invalid expression");
                }
            </script>
        `);
    });
}
// {/fact}

// Example 4: Setting location.href with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    app.get('/redirect', (req, res) => {
        const destination = req.query.url;
        res.send(`
            <script>
                // ruleid: javascript-cross-site-scripting-ide
                window.location.href = destination;
            </script>
        `);
    });
}
// {/fact}

// Example 5: Using innerHTML with template literals
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    app.get('/profile', (req, res) => {
        const userProfile = req.query.profile;
        res.send(`
            <script>
                // ruleid: javascript-cross-site-scripting-ide
                document.getElementById('profile').innerHTML = `<div class="profile">${userProfile}</div>`;
            </script>
        `);
    });
}
// {/fact}

// Example 6: Using dangerouslySetInnerHTML in React
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    app.get('/react-component', (req, res) => {
        const userContent = req.query.content;
        res.send(`
            <script>
                function UserContent() {
                    // ruleid: javascript-cross-site-scripting-ide
                    return React.createElement('div', { 
                        dangerouslySetInnerHTML: { __html: userContent } 
                    });
                }
                ReactDOM.render(UserContent(), document.getElementById('root'));
            </script>
        `);
    });
}
// {/fact}

// Example 7: Setting iframe srcdoc with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    app.get('/iframe-content', (req, res) => {
        const frameContent = req.query.content;
        res.send(`
            <script>
                // ruleid: javascript-cross-site-scripting-ide
                document.getElementById('myFrame').srcdoc = frameContent;
            </script>
        `);
    });
}
// {/fact}

// Example 8: Using jQuery's html() method with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    app.get('/jquery-content', (req, res) => {
        const content = req.query.content;
        res.send(`
            <script>
                $(document).ready(function() {
                    // ruleid: javascript-cross-site-scripting-ide
                    $('#content').html(content);
                });
            </script>
        `);
    });
}
// {/fact}

// Example 9: Setting element's outerHTML with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    app.get('/update-element', (req, res) => {
        const newHtml = req.query.html;
        res.send(`
            <script>
                // ruleid: javascript-cross-site-scripting-ide
                document.getElementById('container').outerHTML = newHtml;
            </script>
        `);
    });
}
// {/fact}

// Example 10: Using setTimeout with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    app.get('/execute-later', (req, res) => {
        const userCode = req.query.code;
        res.send(`
            <script>
                // ruleid: javascript-cross-site-scripting-ide
                setTimeout(userCode, 1000);
            </script>
        `);
    });
}
// {/fact}

// Example 11: Using Function constructor with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    app.get('/dynamic-function', (req, res) => {
        const userFunction = req.query.func;
        res.send(`
            <script>
                try {
                    // ruleid: javascript-cross-site-scripting-ide
                    const dynamicFunc = new Function(userFunction);
                    dynamicFunc();
                } catch (e) {
                    console.error("Error executing function");
                }
            </script>
        `);
    });
}
// {/fact}

// Example 12: Setting a script's text content with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    app.get('/dynamic-script', (req, res) => {
        const scriptContent = req.query.script;
        res.send(`
            <script>
                const scriptElement = document.createElement('script');
                // ruleid: javascript-cross-site-scripting-ide
                scriptElement.textContent = scriptContent;
                document.head.appendChild(scriptElement);
            </script>
        `);
    });
}
// {/fact}

// Example 13: Using insertAdjacentHTML with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    app.get('/insert-html', (req, res) => {
        const htmlContent = req.query.html;
        res.send(`
            <script>
                // ruleid: javascript-cross-site-scripting-ide
                document.getElementById('container').insertAdjacentHTML('beforeend', htmlContent);
            </script>
        `);
    });
}
// {/fact}

// Example 14: Setting a base href with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    app.get('/set-base', (req, res) => {
        const baseUrl = req.query.base;
        res.send(`
            <script>
                const baseElement = document.createElement('base');
                // ruleid: javascript-cross-site-scripting-ide
                baseElement.href = baseUrl;
                document.head.appendChild(baseElement);
            </script>
        `);
    });
}
// {/fact}

// Example 15: Using jQuery's append with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    app.get('/append-content', (req, res) => {
        const appendContent = req.query.content;
        res.send(`
            <script>
                $(document).ready(function() {
                    // ruleid: javascript-cross-site-scripting-ide
                    $('#container').append(appendContent);
                });
            </script>
        `);
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using textContent instead of innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    app.get('/search', (req, res) => {
        const query = req.query.q;
        const html = `
            <div>
                <h2>Search Results for:</h2>
                <div id="results"></div>
            </div>
            <script>
                // ok: javascript-cross-site-scripting-ide
                document.getElementById('results').textContent = query;
            </script>
        `;
        res.send(html);
    });
}
// {/fact}

// Example 2: Using DOMPurify to sanitize HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    app.get('/welcome', (req, res) => {
        const username = req.query.username;
        res.send(`
            <div id="welcome"></div>
            <script>
                // ok: javascript-cross-site-scripting-ide
                document.getElementById('welcome').innerHTML = DOMPurify.sanitize("<h1>Welcome, " + username + "!</h1>");
            </script>
        `);
    });
}
// {/fact}

// Example 3: Using encodeURIComponent for URL parameters
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    app.get('/redirect', (req, res) => {
        const destination = req.query.url;
        res.send(`
            <script>
                // ok: javascript-cross-site-scripting-ide
                window.location.href = "/redirect?url=" + encodeURIComponent(destination);
            </script>
        `);
    });
}
// {/fact}

// Example 4: Using a whitelist for allowed values
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    app.get('/set-theme', (req, res) => {
        const theme = req.query.theme;
        res.send(`
            <script>
                const allowedThemes = ['light', 'dark', 'blue', 'green'];
                // ok: javascript-cross-site-scripting-ide
                if (allowedThemes.includes(theme)) {
                    document.body.className = theme;
                } else {
                    document.body.className = 'default';
                }
            </script>
        `);
    });
}
// {/fact}

// Example 5: Using React's safe text rendering
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    app.get('/react-component', (req, res) => {
        const userContent = req.query.content;
        res.send(`
            <script>
                function UserContent() {
                    // ok: javascript-cross-site-scripting-ide
                    return React.createElement('div', {}, userContent);
                }
                ReactDOM.render(UserContent(), document.getElementById('root'));
            </script>
        `);
    });
}
// {/fact}

// Example 6: Using a custom sanitization function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    app.get('/profile', (req, res) => {
        const userProfile = req.query.profile;
        res.send(`
            <script>
                function sanitizeHTML(text) {
                    const element = document.createElement('div');
                    element.textContent = text;
                    return element.innerHTML;
                }
                
                // ok: javascript-cross-site-scripting-ide
                document.getElementById('profile').innerHTML = sanitizeHTML(userProfile);
            </script>
        `);
    });
}
// {/fact}

// Example 7: Using jQuery's text() method instead of html()
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    app.get('/jquery-content', (req, res) => {
        const content = req.query.content;
        res.send(`
            <script>
                $(document).ready(function() {
                    // ok: javascript-cross-site-scripting-ide
                    $('#content').text(content);
                });
            </script>
        `);
    });
}
// {/fact}

// Example 8: Creating a text node instead of using innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    app.get('/add-content', (req, res) => {
        const userContent = req.query.content;
        res.send(`
            <script>
                // ok: javascript-cross-site-scripting-ide
                const textNode = document.createTextNode(userContent);
                document.getElementById('container').appendChild(textNode);
            </script>
        `);
    });
}
// {/fact}

// Example 9: Using a template system with auto-escaping
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    app.get('/template', (req, res) => {
        const userData = req.query.data;
        res.send(`
            <script>
                const template = Handlebars.compile("<div>{{data}}</div>");
                // ok: javascript-cross-site-scripting-ide
                document.getElementById('output').innerHTML = template({ data: userData });
            </script>
        `);
    });
}
// {/fact}

// Example 10: Using setAttribute with non-script attributes
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    app.get('/set-attribute', (req, res) => {
        const title = req.query.title;
        res.send(`
            <script>
                // ok: javascript-cross-site-scripting-ide
                document.getElementById('header').setAttribute('title', title);
            </script>
        `);
    });
}
// {/fact}

// Example 11: Using a Content Security Policy
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    app.get('/csp-protected', (req, res) => {
        const userInput = req.query.input;
        // ok: javascript-cross-site-scripting-ide
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
        res.send(`
            <div id="content">${userInput}</div>
        `);
    });
}
// {/fact}

// Example 12: Using DOMPurify with allowed tags
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    app.get('/sanitized-html', (req, res) => {
        const htmlContent = req.query.html;
        res.send(`
            <script>
                // ok: javascript-cross-site-scripting-ide
                document.getElementById('content').innerHTML = DOMPurify.sanitize(htmlContent, {
                    ALLOWED_TAGS: ['b', 'i', 'p', 'br']
                });
            </script>
        `);
    });
}
// {/fact}

// Example 13: Using a numeric conversion for user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    app.get('/calculate', (req, res) => {
        const userValue = req.query.value;
        res.send(`
            <script>
                // ok: javascript-cross-site-scripting-ide
                const numericValue = Number(userValue);
                document.getElementById('result').textContent = "Result: " + (numericValue * 2);
            </script>
        `);
    });
}
// {/fact}

// Example 14: Using JSON.stringify for data display
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    app.get('/display-data', (req, res) => {
        const userData = req.query.data;
        res.send(`
            <script>
                // ok: javascript-cross-site-scripting-ide
                document.getElementById('data-display').textContent = JSON.stringify(userData);
            </script>
        `);
    });
}
// {/fact}

// Example 15: Using HTML entities encoding
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    app.get('/html-entities', (req, res) => {
        const userInput = req.query.input;
        res.send(`
            <script>
                function escapeHTML(str) {
                    return str.replace(/[&<>"']/g, function(match) {
                        return {
                            '&': '&amp;',
                            '<': '&lt;',
                            '>': '&gt;',
                            '"': '&quot;',
                            "'": '&#39;'
                        }[match];
                    });
                }
                
                // ok: javascript-cross-site-scripting-ide
                document.getElementById('content').innerHTML = escapeHTML(userInput);
            </script>
        `);
    });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});