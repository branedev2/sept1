// This file contains test cases for the javascript-do-not-use-raw-html-in-join rule
// which detects potential XSS vulnerabilities when using array.join() to create HTML

// Required imports for HTTP handling
const express = require('express');
const app = express();
const http = require('http');
const https = require('https');
const axios = require('axios');

// TRUE POSITIVES - Vulnerable code that should be detected

// Case 1: Basic HTML construction with join using user input from query parameter
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
    const userName = req.query.name;
    const htmlParts = ['<div>', userName, '</div>'];
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = htmlParts.join('');
    res.send(html);
}
// {/fact}

// Case 2: HTML construction with join using user input from request body
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
    const userComment = req.body.comment;
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = ['<p class="comment">', userComment, '</p>'].join('');
    res.send(html);
}
// {/fact}

// Case 3: HTML construction with join using user input from URL parameter with template literals
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
    const productId = req.params.id;
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        `<div class="product">`,
        `<h2>Product ID: ${productId}</h2>`,
        `<button onclick="buyProduct('${productId}')">Buy Now</button>`,
        `</div>`
    ].join('');
    res.send(html);
}
// {/fact}

// Case 4: HTML construction with join using user input from headers
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
    const userAgent = req.headers['user-agent'];
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<div class="debug-info">',
        '<h3>Debug Information</h3>',
        '<p>User Agent: ' + userAgent + '</p>',
        '</div>'
    ].join('\n');
    res.send(html);
}
// {/fact}

// Case 5: HTML construction with join using user input from cookies
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
    const theme = req.cookies.theme;
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<div>',
        '<p>Your current theme is: ' + theme + '</p>',
        '<button onclick="changeTheme()">Change Theme</button>',
        '</div>'
    ].join('');
    res.send(html);
}
// {/fact}

// Case 6: HTML construction with join using user input in a table
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
    const users = JSON.parse(req.body.users);
    let rows = [];
    
    for (const user of users) {
        // ruleid: javascript-do-not-use-raw-html-in-join
        const row = [
            '<tr>',
            '<td>' + user.name + '</td>',
            '<td>' + user.email + '</td>',
            '</tr>'
        ].join('');
        rows.push(row);
    }
    
    const table = '<table>' + rows.join('') + '</table>';
    res.send(table);
}
// {/fact}

// Case 7: HTML construction with join using user input in attributes
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
    const imageUrl = req.query.img;
    const altText = req.query.alt;
    
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<figure>',
        `<img src="${imageUrl}" alt="${altText}">`,
        '<figcaption>User provided image</figcaption>',
        '</figure>'
    ].join('');
    
    res.send(html);
}
// {/fact}

// Case 8: HTML construction with join using user input in event handlers
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
    const clickHandler = req.query.handler;
    
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<div>',
        `<button onclick="${clickHandler}">Click me</button>`,
        '</div>'
    ].join('');
    
    res.send(html);
}
// {/fact}

// Case 9: HTML construction with join using user input in a complex structure
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
    const searchTerm = req.query.q;
    const category = req.query.category;
    
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<div class="search-results">',
        `<h2>Results for: ${searchTerm}</h2>`,
        `<p>Category: ${category}</p>`,
        '<ul>',
        '<li>Result 1</li>',
        '<li>Result 2</li>',
        '</ul>',
        '</div>'
    ].join('\n');
    
    res.send(html);
}
// {/fact}

// Case 10: HTML construction with join using user input in a form
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
    const defaultValue = req.query.default;
    const formAction = req.query.action || '/submit';
    
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<form action="' + formAction + '" method="post">',
        '<label for="input">Enter value:</label>',
        '<input type="text" id="input" name="input" value="' + defaultValue + '">',
        '<button type="submit">Submit</button>',
        '</form>'
    ].join('');
    
    res.send(html);
}
// {/fact}

// Case 11: HTML construction with join using user input in a script tag
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
    const userId = req.query.id;
    
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<div id="user-profile">',
        '<h2>User Profile</h2>',
        '<script>',
        'const userId = "' + userId + '";',
        'loadUserData(userId);',
        '</script>',
        '</div>'
    ].join('\n');
    
    res.send(html);
}
// {/fact}

// Case 12: HTML construction with join using user input in a style attribute
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
    const color = req.query.color || 'blue';
    const fontSize = req.query.size || '16px';
    
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<div>',
        '<p style="color: ' + color + '; font-size: ' + fontSize + '">',
        'Styled text',
        '</p>',
        '</div>'
    ].join('');
    
    res.send(html);
}
// {/fact}

// Case 13: HTML construction with join using user input from API response
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
    const apiUrl = req.query.api;
    
    axios.get(apiUrl)
        .then(response => {
            const data = response.data;
            
            // ruleid: javascript-do-not-use-raw-html-in-join
            const html = [
                '<div class="api-data">',
                '<h2>' + data.title + '</h2>',
                '<p>' + data.description + '</p>',
                '</div>'
            ].join('');
            
            res.send(html);
        })
        .catch(error => {
            res.status(500).send('Error fetching data');
        });
}
// {/fact}

// Case 14: HTML construction with join using user input in a meta tag
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
    const metaDescription = req.query.description;
    const pageTitle = req.query.title;
    
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<!DOCTYPE html>',
        '<html>',
        '<head>',
        '<title>' + pageTitle + '</title>',
        '<meta name="description" content="' + metaDescription + '">',
        '</head>',
        '<body>',
        '<h1>Page Content</h1>',
        '</body>',
        '</html>'
    ].join('\n');
    
    res.send(html);
}
// {/fact}

// Case 15: HTML construction with join using user input in a data attribute
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
    const userData = req.query.data;
    
    // ruleid: javascript-do-not-use-raw-html-in-join
    const html = [
        '<div>',
        '<button data-user-info="' + userData + '" onclick="processUser()">',
        'Process User Data',
        '</button>',
        '</div>'
    ].join('');
    
    res.send(html);
}
// {/fact}

// TRUE NEGATIVES - Safe code that should not be detected

// Case 1: Using createElement and appendChild instead of join for HTML manipulation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
    const userName = req.query.name;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const div = document.createElement('div');
            const textNode = document.createTextNode('${userName}');
            div.appendChild(textNode);
            document.body.appendChild(div);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 2: Using DOM methods to create elements from user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
    const userComment = req.body.comment;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const p = document.createElement('p');
            p.className = 'comment';
            p.textContent = ${JSON.stringify(userComment)};
            document.getElementById('comments').appendChild(p);
        });
    `;
    
    res.send(`<div id="comments"></div><script>${script}</script>`);
}
// {/fact}

// Case 3: Using a template engine (like EJS) instead of manual HTML construction
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
    const productId = req.params.id;
    
    // ok: javascript-do-not-use-raw-html-in-join
    res.render('product', { 
        productId: productId,
        title: 'Product Details'
    });
}
// {/fact}

// Case 4: Using a sanitization library before rendering user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
    const userAgent = req.headers['user-agent'];
    const DOMPurify = require('dompurify');
    
    // ok: javascript-do-not-use-raw-html-in-join
    const sanitizedUserAgent = DOMPurify.sanitize(userAgent);
    
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const div = document.createElement('div');
            div.className = 'debug-info';
            
            const h3 = document.createElement('h3');
            h3.textContent = 'Debug Information';
            div.appendChild(h3);
            
            const p = document.createElement('p');
            p.textContent = 'User Agent: ${sanitizedUserAgent}';
            div.appendChild(p);
            
            document.body.appendChild(div);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 5: Using React's JSX (which handles escaping automatically)
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
    const theme = req.cookies.theme;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const reactComponent = `
        function ThemeDisplay() {
            return (
                <div>
                    <p>Your current theme is: {${JSON.stringify(theme)}}</p>
                    <button onClick={changeTheme}>Change Theme</button>
                </div>
            );
        }
        
        ReactDOM.render(<ThemeDisplay />, document.getElementById('root'));
    `;
    
    res.send(`<div id="root"></div><script type="text/babel">${reactComponent}</script>`);
}
// {/fact}

// Case 6: Using map and DOM methods to create table rows
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
    const users = JSON.parse(req.body.users);
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const table = document.createElement('table');
            const users = ${JSON.stringify(users)};
            
            users.forEach(user => {
                const row = document.createElement('tr');
                
                const nameCell = document.createElement('td');
                nameCell.textContent = user.name;
                row.appendChild(nameCell);
                
                const emailCell = document.createElement('td');
                emailCell.textContent = user.email;
                row.appendChild(emailCell);
                
                table.appendChild(row);
            });
            
            document.body.appendChild(table);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 7: Using DOM methods to create an image with user-provided attributes
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
    const imageUrl = req.query.img;
    const altText = req.query.alt;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const figure = document.createElement('figure');
            
            const img = document.createElement('img');
            img.src = ${JSON.stringify(imageUrl)};
            img.alt = ${JSON.stringify(altText)};
            figure.appendChild(img);
            
            const figcaption = document.createElement('figcaption');
            figcaption.textContent = 'User provided image';
            figure.appendChild(figcaption);
            
            document.body.appendChild(figure);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 8: Using addEventListener instead of inline event handlers
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
    const clickHandler = req.query.handler;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const div = document.createElement('div');
            
            const button = document.createElement('button');
            button.textContent = 'Click me';
            button.addEventListener('click', function() {
                // Safely use the handler name as a variable reference, not as raw code
                if (typeof window[${JSON.stringify(clickHandler)}] === 'function') {
                    window[${JSON.stringify(clickHandler)}]();
                }
            });
            
            div.appendChild(button);
            document.body.appendChild(div);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 9: Using DOM methods for a complex structure
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
    const searchTerm = req.query.q;
    const category = req.query.category;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const container = document.createElement('div');
            container.className = 'search-results';
            
            const heading = document.createElement('h2');
            heading.textContent = 'Results for: ' + ${JSON.stringify(searchTerm)};
            container.appendChild(heading);
            
            const categoryPara = document.createElement('p');
            categoryPara.textContent = 'Category: ' + ${JSON.stringify(category)};
            container.appendChild(categoryPara);
            
            const ul = document.createElement('ul');
            
            const li1 = document.createElement('li');
            li1.textContent = 'Result 1';
            ul.appendChild(li1);
            
            const li2 = document.createElement('li');
            li2.textContent = 'Result 2';
            ul.appendChild(li2);
            
            container.appendChild(ul);
            document.body.appendChild(container);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 10: Using DOM methods to create a form
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
    const defaultValue = req.query.default;
    const formAction = req.query.action || '/submit';
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.createElement('form');
            form.action = ${JSON.stringify(formAction)};
            form.method = 'post';
            
            const label = document.createElement('label');
            label.htmlFor = 'input';
            label.textContent = 'Enter value:';
            form.appendChild(label);
            
            const input = document.createElement('input');
            input.type = 'text';
            input.id = 'input';
            input.name = 'input';
            input.value = ${JSON.stringify(defaultValue)};
            form.appendChild(input);
            
            const button = document.createElement('button');
            button.type = 'submit';
            button.textContent = 'Submit';
            form.appendChild(button);
            
            document.body.appendChild(form);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 11: Using a data attribute and accessing it safely
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
    const userId = req.query.id;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const container = document.createElement('div');
            container.id = 'user-profile';
            
            const heading = document.createElement('h2');
            heading.textContent = 'User Profile';
            container.appendChild(heading);
            
            // Store user ID safely as a data attribute
            container.dataset.userId = ${JSON.stringify(userId)};
            
            // Access the data attribute safely
            const storedUserId = container.dataset.userId;
            loadUserData(storedUserId);
            
            document.body.appendChild(container);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 12: Using style properties instead of string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
    const color = req.query.color || 'blue';
    const fontSize = req.query.size || '16px';
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const div = document.createElement('div');
            
            const p = document.createElement('p');
            p.textContent = 'Styled text';
            
            // Set styles using properties, not string concatenation
            p.style.color = ${JSON.stringify(color)};
            p.style.fontSize = ${JSON.stringify(fontSize)};
            
            div.appendChild(p);
            document.body.appendChild(div);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 13: Using DOM methods to display API data
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
    const apiUrl = req.query.api;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            fetch(${JSON.stringify(apiUrl)})
                .then(response => response.json())
                .then(data => {
                    const container = document.createElement('div');
                    container.className = 'api-data';
                    
                    const heading = document.createElement('h2');
                    heading.textContent = data.title;
                    container.appendChild(heading);
                    
                    const paragraph = document.createElement('p');
                    paragraph.textContent = data.description;
                    container.appendChild(paragraph);
                    
                    document.body.appendChild(container);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Case 14: Using document.head.appendChild for meta tags
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
    const metaDescription = req.query.description;
    const pageTitle = req.query.title;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            // Set page title
            document.title = ${JSON.stringify(pageTitle)};
            
            // Create meta description
            const metaDesc = document.createElement('meta');
            metaDesc.name = 'description';
            metaDesc.content = ${JSON.stringify(metaDescription)};
            document.head.appendChild(metaDesc);
            
            // Create page content
            const heading = document.createElement('h1');
            heading.textContent = 'Page Content';
            document.body.appendChild(heading);
        });
    `;
    
    res.send(`<!DOCTYPE html><html><head><script>${script}</script></head><body></body></html>`);
}
// {/fact}

// Case 15: Using dataset for data attributes
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
    const userData = req.query.data;
    
    // ok: javascript-do-not-use-raw-html-in-join
    const script = `
        document.addEventListener('DOMContentLoaded', function() {
            const div = document.createElement('div');
            
            const button = document.createElement('button');
            button.textContent = 'Process User Data';
            
            // Use dataset instead of attribute string
            button.dataset.userInfo = ${JSON.stringify(userData)};
            
            button.addEventListener('click', function() {
                processUser(this.dataset.userInfo);
            });
            
            div.appendChild(button);
            document.body.appendChild(div);
        });
    `;
    
    res.send(`<script>${script}</script>`);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});