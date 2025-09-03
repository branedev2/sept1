// Common imports for template engines
const express = require('express');
const app = express();
const pug = require('pug');
const ejs = require('ejs');
const handlebars = require('handlebars');
const nunjucks = require('nunjucks');
const doT = require('dot');
const mustache = require('mustache');
const lodash = require('lodash');

// Set up middleware for parsing request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TRUE POSITIVES - Vulnerable code examples

// Example 1: Pug template engine with unvalidated user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req, res) {
    const userTemplate = req.query.template;
    // ruleid: javascript-server-side-template-injection
    const compiledFunction = pug.compile(userTemplate);
    const html = compiledFunction({
        user: { name: 'John' }
    });
    res.send(html);
}
// {/fact}

// Example 2: EJS with user-controlled template
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req, res) {
    const userTemplate = req.body.template;
    // ruleid: javascript-server-side-template-injection
    const html = ejs.render(userTemplate, {
        user: { name: 'Alice' }
    });
    res.send(html);
}
// {/fact}

// Example 3: Handlebars with user input as template
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req, res) {
    const userTemplate = req.params.template;
    // ruleid: javascript-server-side-template-injection
    const compiledTemplate = handlebars.compile(userTemplate);
    const html = compiledTemplate({ username: 'Bob' });
    res.send(html);
}
// {/fact}

// Example 4: Nunjucks with user-controlled template string
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req, res) {
    const userTemplate = req.query.template || 'Default template';
    // ruleid: javascript-server-side-template-injection
    const html = nunjucks.renderString(userTemplate, { 
        user: req.session.user 
    });
    res.send(html);
}
// {/fact}

// Example 5: DoT template with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req, res) {
    const userTemplate = req.headers['x-template'];
    // ruleid: javascript-server-side-template-injection
    const tempFn = doT.template(userTemplate);
    const html = tempFn({ name: 'Charlie' });
    res.send(html);
}
// {/fact}

// Example 6: Mustache with user-provided template
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req, res) {
    const userTemplate = req.body.customTemplate;
    // ruleid: javascript-server-side-template-injection
    const html = mustache.render(userTemplate, { 
        username: req.session.username 
    });
    res.send(html);
}
// {/fact}

// Example 7: Lodash template with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req, res) {
    const userTemplate = req.query.tpl;
    // ruleid: javascript-server-side-template-injection
    const compiled = lodash.template(userTemplate);
    const html = compiled({ 'user': 'Dave' });
    res.send(html);
}
// {/fact}

// Example 8: EJS renderFile with user-controlled filename
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req, res) {
    const templateFile = req.query.template;
    // ruleid: javascript-server-side-template-injection
    ejs.renderFile(templateFile, { user: 'Eve' }, (err, html) => {
        if (err) {
            return res.status(500).send('Error rendering template');
        }
        res.send(html);
    });
}
// {/fact}

// Example 9: Handlebars with template from cookie
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req, res) {
    const userTemplate = req.cookies.template;
    // ruleid: javascript-server-side-template-injection
    const template = handlebars.compile(userTemplate);
    const html = template({ data: req.session.data });
    res.send(html);
}
// {/fact}

// Example 10: Custom template engine with eval
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req, res) {
    const userTemplate = req.query.template;
    const data = { user: 'Frank', items: ['item1', 'item2'] };
    
    function renderTemplate(template, data) {
        // ruleid: javascript-server-side-template-injection
        return eval('`' + template + '`');
    }
    
    const html = renderTemplate(userTemplate, data);
    res.send(html);
}
// {/fact}

// Example 11: Template string with Function constructor
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req, res) {
    const userTemplate = req.body.template;
    const data = { username: 'Grace', role: 'admin' };
    
    // ruleid: javascript-server-side-template-injection
    const templateFunction = new Function('data', 'return `' + userTemplate + '`');
    const html = templateFunction(data);
    res.send(html);
}
// {/fact}

// Example 12: Nunjucks with user input in a more complex scenario
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req, res) {
    let baseTemplate = '{% extends "layout.html" %}\n{% block content %}';
    baseTemplate += req.query.content;
    baseTemplate += '{% endblock %}';
    
    // ruleid: javascript-server-side-template-injection
    const html = nunjucks.renderString(baseTemplate, {
        user: req.session.user,
        items: req.session.cart
    });
    res.send(html);
}
// {/fact}

// Example 13: EJS with template from request body in JSON
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req, res) {
    const requestData = req.body;
    if (requestData && requestData.templateData) {
        // ruleid: javascript-server-side-template-injection
        const html = ejs.render(requestData.templateData, {
            user: req.session.user,
            permissions: ['read', 'write']
        });
        res.send(html);
    }
}
// {/fact}

// Example 14: Pug with template from URL parameter with processing
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req, res) {
    let userTemplate = req.params.template;
    // Some processing that doesn't sanitize
    userTemplate = userTemplate.replace(/\s+/g, ' ').trim();
    
    // ruleid: javascript-server-side-template-injection
    const compiledFunction = pug.compile(userTemplate);
    const html = compiledFunction({
        user: { name: 'Helen', role: 'user' }
    });
    res.send(html);
}
// {/fact}

// Example 15: Template injection via API endpoint
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req, res) {
    const apiData = req.body;
    if (apiData.action === 'render_template') {
        // ruleid: javascript-server-side-template-injection
        const html = handlebars.compile(apiData.template)({
            data: apiData.data,
            user: req.user
        });
        res.json({ rendered: html });
    }
}
// {/fact}

// TRUE NEGATIVES - Safe code examples

// Example 1: Pug with predefined template
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req, res) {
    const username = req.query.username;
    // ok: javascript-server-side-template-injection
    const compiledFunction = pug.compile('p Hello, #{username}!');
    const html = compiledFunction({ username });
    res.send(html);
}
// {/fact}

// Example 2: EJS with safe template and user data
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req, res) {
    const userData = req.body.userData;
    // ok: javascript-server-side-template-injection
    const html = ejs.render('<p>Hello, <%= user.name %>!</p>', {
        user: { name: userData }
    });
    res.send(html);
}
// {/fact}

// Example 3: Handlebars with predefined template file
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req, res) {
    const username = req.params.username;
    const templateSource = '<div>Welcome, {{username}}!</div>';
    // ok: javascript-server-side-template-injection
    const template = handlebars.compile(templateSource);
    const html = template({ username });
    res.send(html);
}
// {/fact}

// Example 4: Nunjucks rendering a template file
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req, res) {
    const userId = req.query.id;
    // ok: javascript-server-side-template-injection
    nunjucks.render('user-profile.html', { 
        userId: userId,
        timestamp: new Date()
    }, (err, html) => {
        if (err) return res.status(500).send('Error');
        res.send(html);
    });
}
// {/fact}

// Example 5: DoT with predefined template
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req, res) {
    const userName = req.headers['x-user-name'];
    const templateStr = '<div>Hello, {{=it.name}}!</div>';
    // ok: javascript-server-side-template-injection
    const tempFn = doT.template(templateStr);
    const html = tempFn({ name: userName });
    res.send(html);
}
// {/fact}

// Example 6: Mustache with safe template
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req, res) {
    const userData = req.body.user;
    const template = '<h1>Welcome, {{username}}!</h1>';
    // ok: javascript-server-side-template-injection
    const html = mustache.render(template, { 
        username: userData.name 
    });
    res.send(html);
}
// {/fact}

// Example 7: Lodash template defined in code
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req, res) {
    const userInput = req.query.name;
    const templateStr = '<div>Hello, <%= user %>!</div>';
    // ok: javascript-server-side-template-injection
    const compiled = lodash.template(templateStr);
    const html = compiled({ 'user': userInput });
    res.send(html);
}
// {/fact}

// Example 8: EJS renderFile with fixed template path
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req, res) {
    const userId = req.query.id;
    // ok: javascript-server-side-template-injection
    ejs.renderFile('./templates/user-profile.ejs', { userId }, (err, html) => {
        if (err) {
            return res.status(500).send('Error rendering template');
        }
        res.send(html);
    });
}
// {/fact}

// Example 9: Handlebars with template from a safe source
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req, res) {
    const userRole = req.cookies.role;
    const fs = require('fs');
    const templateSource = fs.readFileSync('./templates/role-template.hbs', 'utf8');
    // ok: javascript-server-side-template-injection
    const template = handlebars.compile(templateSource);
    const html = template({ role: userRole });
    res.send(html);
}
// {/fact}

// Example 10: Template selection from predefined list
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req, res) {
    const templateName = req.query.template;
    const templates = {
        'welcome': '<h1>Welcome!</h1>',
        'goodbye': '<h1>Goodbye!</h1>',
        'error': '<h1>Error!</h1>'
    };
    
    // Validate template name
    if (!templates[templateName]) {
        return res.status(400).send('Invalid template');
    }
    
    // ok: javascript-server-side-template-injection
    const html = ejs.render(templates[templateName], {
        user: req.session.user
    });
    res.send(html);
}
// {/fact}

// Example 11: Using template literals safely
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req, res) {
    const username = req.body.username;
    // ok: javascript-server-side-template-injection
    const html = `<div>Hello, ${username}!</div>`;
    res.send(html);
}
// {/fact}

// Example 12: Nunjucks with template from filesystem
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req, res) {
    const productId = req.query.id;
    // ok: javascript-server-side-template-injection
    const html = nunjucks.render('products/detail.html', {
        productId: productId,
        categories: ['electronics', 'computers', 'accessories']
    });
    res.send(html);
}
// {/fact}

// Example 13: EJS with template from a safe source
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req, res) {
    const fs = require('fs');
    const templatePath = './templates/dashboard.ejs';
    const templateContent = fs.readFileSync(templatePath, 'utf8');
    
    // ok: javascript-server-side-template-injection
    const html = ejs.render(templateContent, {
        user: req.session.user,
        data: req.body.dashboardData
    });
    res.send(html);
}
// {/fact}

// Example 14: Pug with template selection from whitelist
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req, res) {
    const templateName = req.params.template;
    const allowedTemplates = {
        'profile': 'p Hello #{user.name}, your profile is ready.',
        'dashboard': 'div.dashboard\n  h1 Welcome back, #{user.name}',
        'settings': 'form.settings\n  label(for="email") Email\n  input(type="email", value=user.email)'
    };
    
    if (!allowedTemplates[templateName]) {
        return res.status(400).send('Invalid template');
    }
    
    // ok: javascript-server-side-template-injection
    const compiledFunction = pug.compile(allowedTemplates[templateName]);
    const html = compiledFunction({
        user: { name: req.session.username, email: req.session.email }
    });
    res.send(html);
}
// {/fact}

// Example 15: Handlebars with precompiled templates
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req, res) {
    const viewName = req.query.view;
    const precompiledTemplates = {
        'home': handlebars.compile('<div>Welcome to our site, {{username}}!</div>'),
        'about': handlebars.compile('<div>About us page for {{username}}</div>'),
        'contact': handlebars.compile('<div>Contact us, {{username}}</div>')
    };
    
    if (!precompiledTemplates[viewName]) {
        return res.status(400).send('Invalid view');
    }
    
    // ok: javascript-server-side-template-injection
    const html = precompiledTemplates[viewName]({
        username: req.session.username
    });
    res.send(html);
}
// {/fact}

// Export the app for testing
module.exports = app;