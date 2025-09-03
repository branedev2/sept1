// File: template-injection-examples.js

const express = require('express');
const app = express();
const handlebars = require('handlebars');
const pug = require('pug');
const ejs = require('ejs');
const lodash = require('lodash');
const vm = require('vm');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    app.get('/vulnerable-handlebars', (req, res) => {
        const userTemplate = req.query.template;
        const template = handlebars.compile(userTemplate);
        // ruleid: javascript-dangerous-locals-as-template-context
        const result = template({ name: 'John' });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    app.post('/vulnerable-pug', (req, res) => {
        const userTemplate = req.body.template;
        // ruleid: javascript-dangerous-locals-as-template-context
        const compiledFunction = pug.compile(userTemplate);
        const html = compiledFunction({ user: 'Admin' });
        res.send(html);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    app.get('/vulnerable-ejs', (req, res) => {
        const userTemplate = req.query.template;
        // ruleid: javascript-dangerous-locals-as-template-context
        const html = ejs.render(userTemplate, { user: req.session.user });
        res.send(html);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    app.get('/vulnerable-lodash-template', (req, res) => {
        const userTemplate = req.query.template;
        // ruleid: javascript-dangerous-locals-as-template-context
        const compiled = lodash.template(userTemplate);
        const result = compiled({ 'user': 'fred' });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    app.post('/vulnerable-eval', (req, res) => {
        const userInput = req.body.code;
        // ruleid: javascript-dangerous-locals-as-template-context
        const result = eval('`' + userInput + '`');
        res.send({ result });
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    app.get('/vulnerable-vm', (req, res) => {
        const userScript = req.query.script;
        const context = { data: { sensitive: 'secret' } };
        // ruleid: javascript-dangerous-locals-as-template-context
        vm.runInNewContext(userScript, context);
        res.json(context);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    app.get('/vulnerable-function', (req, res) => {
        const userCode = req.query.code;
        // ruleid: javascript-dangerous-locals-as-template-context
        const dynamicFunction = new Function('data', userCode);
        const result = dynamicFunction({ user: 'admin' });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    app.post('/vulnerable-indirect-template', (req, res) => {
        const userTemplate = req.body.template;
        const templateEngine = req.body.engine || 'handlebars';
        let result;
        
        if (templateEngine === 'handlebars') {
            const template = handlebars.compile(userTemplate);
            // ruleid: javascript-dangerous-locals-as-template-context
            result = template({ data: req.body.data });
        } else if (templateEngine === 'ejs') {
            // ruleid: javascript-dangerous-locals-as-template-context
            result = ejs.render(userTemplate, { data: req.body.data });
        }
        
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    app.get('/vulnerable-template-from-header', (req, res) => {
        const userTemplate = req.headers['x-template'];
        // ruleid: javascript-dangerous-locals-as-template-context
        const result = handlebars.compile(userTemplate)({ user: req.session.user });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    app.get('/vulnerable-template-with-processing', (req, res) => {
        let userTemplate = req.query.template;
        // Some processing that doesn't sanitize
        userTemplate = userTemplate.replace(/{{2,}/, '{{');
        userTemplate = userTemplate.replace(/}{2,}/, '}}');
        
        // ruleid: javascript-dangerous-locals-as-template-context
        const result = handlebars.compile(userTemplate)({ data: 'sensitive' });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    app.post('/vulnerable-template-storage', (req, res) => {
        // Store template from user input
        const storedTemplates = {};
        storedTemplates[req.body.templateName] = req.body.templateContent;
        
        // Later use the stored template
        const templateToUse = storedTemplates[req.query.template];
        // ruleid: javascript-dangerous-locals-as-template-context
        const result = handlebars.compile(templateToUse)({ user: 'admin' });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    app.get('/vulnerable-template-concatenation', (req, res) => {
        const headerTemplate = '<h1>Welcome</h1>';
        const userTemplate = req.query.template;
        const footerTemplate = '<footer>Copyright 2023</footer>';
        
        const fullTemplate = headerTemplate + userTemplate + footerTemplate;
        // ruleid: javascript-dangerous-locals-as-template-context
        const result = handlebars.compile(fullTemplate)({ user: 'admin' });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    app.get('/vulnerable-template-json', (req, res) => {
        const templateData = JSON.parse(req.query.data);
        // ruleid: javascript-dangerous-locals-as-template-context
        const result = handlebars.compile(templateData.template)({ user: templateData.user });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    app.post('/vulnerable-template-callback', (req, res) => {
        const userTemplate = req.body.template;
        
        processTemplate(userTemplate, (template) => {
            // ruleid: javascript-dangerous-locals-as-template-context
            const result = handlebars.compile(template)({ data: req.body.data });
            res.send(result);
        });
        
        function processTemplate(template, callback) {
            // Some processing
            callback(template);
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    app.get('/vulnerable-template-promise', async (req, res) => {
        try {
            const userTemplate = req.query.template;
            
            const processedTemplate = await new Promise((resolve) => {
                setTimeout(() => {
                    resolve(userTemplate);
                }, 100);
            });
            
            // ruleid: javascript-dangerous-locals-as-template-context
            const result = handlebars.compile(processedTemplate)({ user: 'admin' });
            res.send(result);
        } catch (error) {
            res.status(500).send('Error');
        }
    });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    app.get('/safe-handlebars', (req, res) => {
        // Using a predefined template, not user input
        const template = handlebars.compile('Hello {{name}}!');
        // ok: javascript-dangerous-locals-as-template-context
        const result = template({ name: req.query.name });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    app.post('/safe-pug', (req, res) => {
        // Using a predefined template, not user input
        // ok: javascript-dangerous-locals-as-template-context
        const compiledFunction = pug.compile('p Hello #{user}');
        const html = compiledFunction({ user: req.body.username });
        res.send(html);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    app.get('/safe-ejs', (req, res) => {
        // Using a predefined template, not user input
        // ok: javascript-dangerous-locals-as-template-context
        const html = ejs.render('<p><%= user %></p>', { user: req.query.username });
        res.send(html);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    app.get('/safe-lodash-template', (req, res) => {
        // Using a predefined template, not user input
        // ok: javascript-dangerous-locals-as-template-context
        const compiled = lodash.template('hello <%= user %>!');
        const result = compiled({ 'user': req.query.name });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    app.post('/safe-template-selection', (req, res) => {
        // Select from predefined templates based on user input
        const templates = {
            'welcome': 'Welcome {{name}}!',
            'goodbye': 'Goodbye {{name}}!',
            'error': 'Error: {{message}}'
        };
        
        const templateKey = req.body.template;
        const selectedTemplate = templates[templateKey] || templates['error'];
        
        // ok: javascript-dangerous-locals-as-template-context
        const template = handlebars.compile(selectedTemplate);
        const result = template({ name: req.body.name, message: 'Invalid template' });
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    app.get('/safe-sanitized-vm', (req, res) => {
        // Whitelist approach for VM execution
        const allowedScripts = {
            'getData': 'this.result = this.data.value * 2;',
            'formatData': 'this.result = "Value: " + this.data.value;'
        };
        
        const scriptKey = req.query.script;
        const script = allowedScripts[scriptKey];
        
        if (script) {
            const context = { data: { value: parseInt(req.query.value) || 0 }, result: null };
            // ok: javascript-dangerous-locals-as-template-context
            vm.runInNewContext(script, context);
            res.json({ result: context.result });
        } else {
            res.status(400).send('Invalid script key');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    app.get('/safe-function-whitelist', (req, res) => {
        // Whitelist approach for dynamic functions
        const allowedFunctions = {
            'calculate': 'return data.x * data.y;',
            'concatenate': 'return data.first + " " + data.last;'
        };
        
        const functionKey = req.query.function;
        const functionBody = allowedFunctions[functionKey];
        
        if (functionBody) {
            // ok: javascript-dangerous-locals-as-template-context
            const dynamicFunction = new Function('data', functionBody);
            const result = dynamicFunction({ 
                x: parseInt(req.query.x) || 0, 
                y: parseInt(req.query.y) || 0,
                first: req.query.first || '',
                last: req.query.last || ''
            });
            res.send({ result });
        } else {
            res.status(400).send('Invalid function key');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    app.post('/safe-template-validation', (req, res) => {
        const userTemplate = req.body.template;
        
        // Validate template against allowed patterns
        const allowedPatternRegex = /^[A-Za-z0-9\s<>{}%=:;,.\-_'"!?()[\]]*$/;
        const forbiddenPatterns = ['eval', 'Function', 'setTimeout', 'setInterval', 'execScript'];
        
        if (!allowedPatternRegex.test(userTemplate) || 
            forbiddenPatterns.some(pattern => userTemplate.includes(pattern))) {
            return res.status(400).send('Invalid template');
        }
        
        try {
            // ok: javascript-dangerous-locals-as-template-context
            const result = ejs.render(userTemplate, { 
                user: { name: req.body.name, role: 'user' },
                // Provide limited context
                helpers: {
                    formatDate: (date) => new Date(date).toLocaleDateString()
                }
            }, { escape: true });
            res.send(result);
        } catch (error) {
            res.status(500).send('Error processing template');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    app.get('/safe-template-library', (req, res) => {
        // Using a template library with predefined templates
        const templateLibrary = {
            'userProfile': '<div>Name: {{user.name}}, Email: {{user.email}}</div>',
            'productInfo': '<div>Product: {{product.name}}, Price: {{product.price}}</div>'
        };
        
        const templateName = req.query.template;
        const templateContent = templateLibrary[templateName];
        
        if (!templateContent) {
            return res.status(400).send('Template not found');
        }
        
        // ok: javascript-dangerous-locals-as-template-context
        const template = handlebars.compile(templateContent);
        const result = template({
            user: {
                name: req.query.name,
                email: req.query.email
            },
            product: {
                name: req.query.product,
                price: req.query.price
            }
        });
        
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    app.post('/safe-handlebars-helpers', (req, res) => {
        // Register safe helpers
        handlebars.registerHelper('safeFormat', function(text) {
            return new handlebars.SafeString(purify.sanitize(text));
        });
        
        // Using a predefined template with helpers
        const templateContent = '<div>{{safeFormat message}}</div>';
        
        // ok: javascript-dangerous-locals-as-template-context
        const template = handlebars.compile(templateContent);
        const result = template({ message: req.body.message });
        
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    app.get('/safe-template-with-sanitization', (req, res) => {
        // Using a predefined template with sanitized user input
        const templateContent = '<p>{{message}}</p>';
        
        // Sanitize user input before using it in the template context
        const sanitizedMessage = purify.sanitize(req.query.message || '');
        
        // ok: javascript-dangerous-locals-as-template-context
        const template = handlebars.compile(templateContent);
        const result = template({ message: sanitizedMessage });
        
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    app.post('/safe-template-with-escaping', (req, res) => {
        // Using lodash template with proper escaping
        const templateContent = '<p><%= _.escape(message) %></p>';
        
        // ok: javascript-dangerous-locals-as-template-context
        const compiled = lodash.template(templateContent);
        const result = compiled({ 
            message: req.body.message,
            _: lodash // Pass lodash for escaping
        });
        
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    app.get('/safe-template-strict-context', (req, res) => {
        // Using a predefined template with strict type checking
        const templateContent = '<p>{{#if isString name}}{{name}}{{else}}Invalid name{{/if}}</p>';
        
        // Register helper for type checking
        handlebars.registerHelper('isString', function(value, options) {
            if (typeof value === 'string') {
                return options.fn(this);
            }
            return options.inverse(this);
        });
        
        // ok: javascript-dangerous-locals-as-template-context
        const template = handlebars.compile(templateContent);
        const result = template({ name: req.query.name });
        
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    app.post('/safe-template-with-validation', (req, res) => {
        // Using a predefined template with input validation
        const templateContent = '<p>Hello, {{name}}!</p>';
        
        // Validate user input
        const name = req.body.name;
        if (typeof name !== 'string' || name.length > 50 || /[<>'"&]/.test(name)) {
            return res.status(400).send('Invalid name');
        }
        
        // ok: javascript-dangerous-locals-as-template-context
        const template = handlebars.compile(templateContent);
        const result = template({ name });
        
        res.send(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    app.get('/safe-template-with-encoding', (req, res) => {
        // Using a predefined template with HTML encoding
        const templateContent = '<p>{{encodedMessage}}</p>';
        
        // HTML encode user input
        const encodeHTML = (str) => {
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        };
        
        // ok: javascript-dangerous-locals-as-template-context
        const template = handlebars.compile(templateContent);
        const result = template({ 
            encodedMessage: encodeHTML(req.query.message || '')
        });
        
        res.send(result);
    });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});