const express = require('express');
const app = express();
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);
const sanitizeHtml = require('sanitize-html');
const he = require('he');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.name;
    // Using dangerouslySetInnerHTML with user input
    const html = `
        <div id="content">
            ${React.createElement('div', {
                // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
                dangerouslySetInnerHTML: { __html: userInput }
            })}
        </div>
    `;
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req, res) {
    const userComment = req.body.comment;
    // Using innerHTML with user input directly
    res.send(`
        <script>
            document.getElementById('comments').innerHTML = "${userComment}";
            // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req, res) {
    const userName = req.query.user;
    // Using jQuery's html() method with user input
    res.send(`
        <script>
            $(document).ready(function() {
                // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
                $("#username").html('${userName}');
            });
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req, res) {
    const searchTerm = req.query.q;
    // Using document.write with user input
    res.send(`
        <script>
            // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
            document.write("<p>You searched for: " + "${searchTerm}" + "</p>");
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req, res) {
    const userProfile = req.params.profile;
    // Using insertAdjacentHTML with user input
    res.send(`
        <script>
            // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
            document.getElementById('profile').insertAdjacentHTML('beforeend', '${userProfile}');
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req, res) {
    const userHtml = req.body.content;
    // Using React's dangerouslySetInnerHTML in a component
    const component = {
        render: function() {
            return React.createElement('div', {
                // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
                dangerouslySetInnerHTML: { __html: userHtml }
            });
        }
    };
    res.json(component);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req, res) {
    const userScript = req.query.script;
    // Using eval with user input
    res.send(`
        <script>
            // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
            eval('const userValue = "' + ${userScript} + '";');
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req, res) {
    const userId = req.params.id;
    // Using outerHTML with user input
    res.send(`
        <script>
            // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
            document.getElementById('user').outerHTML = '<div id="user">' + "${userId}" + '</div>';
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req, res) {
    const headerText = req.query.header;
    // Using jQuery's append with user input
    res.send(`
        <script>
            $(function() {
                // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
                $("header").append('${headerText}');
            });
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req, res) {
    const template = req.body.template;
    // Using Function constructor with user input
    res.send(`
        <script>
            // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
            const templateFunc = new Function('data', 'return `' + ${template} + '`;');
            document.body.innerHTML = templateFunc({});
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req, res) {
    const userStyle = req.query.style;
    // Using jQuery's html() with user input in a different context
    res.send(`
        <script>
            $(document).ready(function() {
                // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
                $("#customStyles").html('<style>' + '${userStyle}' + '</style>');
            });
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req, res) {
    const userContent = req.body.content;
    // Using Element.innerHTML with user input
    res.send(`
        <script>
            window.onload = function() {
                const element = document.createElement('div');
                // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
                element.innerHTML = '${userContent}';
                document.body.appendChild(element);
            };
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req, res) {
    const userMessage = req.headers['x-custom-message'];
    // Using createContextualFragment with user input
    res.send(`
        <script>
            const range = document.createRange();
            // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
            const fragment = range.createContextualFragment('${userMessage}');
            document.body.appendChild(fragment);
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req, res) {
    const userWidget = req.cookies.widgetContent;
    // Using Handlebars with triple braces (unescaped)
    const template = Handlebars.compile(`
        <div class="widget">
            {{{widget}}}
        </div>
    `);
    // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const html = template({ widget: userWidget });
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req, res) {
    const userCode = req.query.code;
    // Using document.body.innerHTML with user input
    res.send(`
        <script>
            // ruleid: javascript-do-not-avoid-escaping-for-untrusted-user-input
            document.body.innerHTML += '<pre>' + ${userCode} + '</pre>';
        </script>
    `);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req, res) {
    const userInput = req.query.name;
    // Using text content instead of innerHTML
    // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const html = `
        <div id="content">
            <div id="user-name"></div>
        </div>
        <script>
            document.getElementById('user-name').textContent = "${userInput}";
        </script>
    `;
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req, res) {
    const userComment = req.body.comment;
    // Sanitizing user input before using innerHTML
    // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const sanitizedComment = sanitizeHtml(userComment);
    res.send(`
        <script>
            document.getElementById('comments').innerHTML = "${sanitizedComment}";
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req, res) {
    const userName = req.query.user;
    // Using jQuery's text() method instead of html()
    res.send(`
        <script>
            $(document).ready(function() {
                // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
                $("#username").text('${userName}');
            });
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req, res) {
    const searchTerm = req.query.q;
    // Using textContent instead of document.write
    res.send(`
        <script>
            window.onload = function() {
                // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
                document.getElementById('search-results').textContent = "You searched for: " + "${searchTerm}";
            };
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req, res) {
    const userProfile = req.params.profile;
    // Using DOMPurify to sanitize HTML
    // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const cleanProfile = DOMPurify.sanitize(userProfile);
    res.send(`
        <script>
            document.getElementById('profile').innerHTML = '${cleanProfile}';
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req, res) {
    const userHtml = req.body.content;
    // Using React's children prop instead of dangerouslySetInnerHTML
    const component = {
        render: function() {
            // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
            return React.createElement('div', {}, userHtml);
        }
    };
    res.json(component);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req, res) {
    const userScript = req.query.script;
    // Avoiding eval by using a safer alternative
    res.send(`
        <script>
            // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
            const userValue = "${userScript}";
            console.log(userValue);
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req, res) {
    const userId = req.params.id;
    // Using createElement and textContent instead of outerHTML
    res.send(`
        <script>
            window.onload = function() {
                const userDiv = document.createElement('div');
                userDiv.id = 'user';
                // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
                userDiv.textContent = "${userId}";
                document.body.appendChild(userDiv);
            };
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req, res) {
    const headerText = req.query.header;
    // Using jQuery's text() with user input
    res.send(`
        <script>
            $(function() {
                // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
                $("header").text('${headerText}');
            });
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req, res) {
    const template = req.body.template;
    // Using a template library with auto-escaping
    // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const safeTemplate = he.encode(template);
    res.send(`
        <script>
            const templateFunc = (data) => \`${safeTemplate}\`;
            document.getElementById('output').textContent = templateFunc({});
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req, res) {
    const userStyle = req.query.style;
    // Using CSS sanitization before applying styles
    // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const sanitizedStyle = userStyle.replace(/[<>]/g, '');
    res.send(`
        <style>
            .user-style {
                ${sanitizedStyle}
            }
        </style>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req, res) {
    const userContent = req.body.content;
    // Using createElement and appendChild instead of innerHTML
    res.send(`
        <script>
            window.onload = function() {
                const element = document.createElement('div');
                const textNode = document.createTextNode('${userContent}');
                // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
                element.appendChild(textNode);
                document.body.appendChild(element);
            };
        </script>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req, res) {
    const userMessage = req.headers['x-custom-message'];
    // Using sanitize-html library
    // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const cleanMessage = sanitizeHtml(userMessage, {
        allowedTags: ['b', 'i', 'em', 'strong'],
        allowedAttributes: {}
    });
    res.send(`
        <div id="message">${cleanMessage}</div>
    `);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req, res) {
    const userWidget = req.cookies.widgetContent;
    // Using Handlebars with double braces (escaped)
    const template = Handlebars.compile(`
        <div class="widget">
            {{widget}}
        </div>
    `);
    // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const html = template({ widget: userWidget });
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req, res) {
    const userCode = req.query.code;
    // Using a code highlighting library that handles escaping
    // ok: javascript-do-not-avoid-escaping-for-untrusted-user-input
    const highlightedCode = hljs.highlight('javascript', userCode).value;
    res.send(`
        <pre><code class="hljs">${highlightedCode}</code></pre>
    `);
}
// {/fact}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});