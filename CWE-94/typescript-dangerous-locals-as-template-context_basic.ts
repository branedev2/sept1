import express from 'express';
import { Request, Response } from 'express';
import * as handlebars from 'handlebars';
import * as pug from 'pug';
import * as ejs from 'ejs';
import * as mustache from 'mustache';
import * as nunjucks from 'nunjucks';
import * as lodash from 'lodash';
import * as vm from 'vm';
import * as DOMPurify from 'dompurify';
import { escape } from 'html-escaper';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userTemplate = req.query.template as string;
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const compiledTemplate = handlebars.compile(userTemplate);
    const result = compiledTemplate({ name: 'John' });
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userInput = req.body.content;
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const template = pug.compile(userInput);
    const html = template({ user: 'Admin' });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const templateData = req.query.template as string;
    
    try {
        // ruleid: typescript-dangerous-locals-as-template-context
        const html = ejs.render(templateData, { user: 'Admin' });
        res.send(html);
    } catch (error) {
        res.status(500).send('Error rendering template');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userTemplate = req.headers['x-template'] as string;
    const data = { username: 'admin', role: 'superuser' };
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const rendered = mustache.render(userTemplate, data);
    res.send(rendered);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const template = req.body.template;
    
    // ruleid: typescript-dangerous-locals-as-template-context
    nunjucks.renderString(template, { username: 'admin' }, (err, result) => {
        if (err) {
            res.status(500).send('Error rendering template');
        } else {
            res.send(result);
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const userTemplate = req.query.template as string;
    const data = { user: req.session?.username || 'guest' };
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const compiled = lodash.template(userTemplate);
    const result = compiled(data);
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const templateString = req.body.template;
    const context = { name: 'John', role: 'admin' };
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const script = new vm.Script(`
        const result = \`${templateString}\`;
        result;
    `);
    
    const vmContext = vm.createContext(context);
    const result = script.runInContext(vmContext);
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const userTemplate = req.cookies.template;
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const template = handlebars.compile(userTemplate);
    const html = template({ 
        user: { name: 'Admin', permissions: ['read', 'write'] } 
    });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const templateData = req.query.template as string;
    const userData = {
        username: req.session?.username,
        isAdmin: req.session?.isAdmin
    };
    
    try {
        // ruleid: typescript-dangerous-locals-as-template-context
        const result = eval('`' + templateData + '`');
        res.send(result);
    } catch (error) {
        res.status(500).send('Error processing template');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const userInput = req.body.template;
    const data = { company: 'Acme Corp', year: new Date().getFullYear() };
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const fn = new Function('data', 'return `' + userInput + '`');
    const result = fn(data);
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const templateEngine = req.query.engine as string;
    const templateContent = req.body.template;
    
    let result;
    if (templateEngine === 'handlebars') {
        // ruleid: typescript-dangerous-locals-as-template-context
        const template = handlebars.compile(templateContent);
        result = template({ data: 'sensitive data' });
    } else if (templateEngine === 'pug') {
        // ruleid: typescript-dangerous-locals-as-template-context
        result = pug.render(templateContent, { data: 'sensitive data' });
    } else {
        // ruleid: typescript-dangerous-locals-as-template-context
        result = ejs.render(templateContent, { data: 'sensitive data' });
    }
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const userTemplate = req.headers['x-custom-template'] as string;
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const templateFunction = (context: any) => {
        return eval('`' + userTemplate + '`');
    };
    
    const result = templateFunction({ username: 'admin' });
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const templateParts = {
        header: req.query.header as string,
        body: req.query.body as string,
        footer: req.query.footer as string
    };
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const compiledTemplate = handlebars.compile(
        templateParts.header + templateParts.body + templateParts.footer
    );
    
    const result = compiledTemplate({ user: 'John' });
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const userInput = req.body.template;
    const context = { data: req.body.data || {} };
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const render = (template: string, ctx: any) => {
        return new Function('ctx', 'with(ctx) { return `' + template + '`; }')(ctx);
    };
    
    const result = render(userInput, context);
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const templateId = req.query.id as string;
    // Simulating fetching a template from a database based on user input
    const fetchedTemplate = `Template with ID ${templateId}: <%= data %>`;
    
    // ruleid: typescript-dangerous-locals-as-template-context
    const html = ejs.render(fetchedTemplate, { data: 'Company Data' });
    res.send(html);
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    // Using a predefined template, not user input
    const template = '<h1>Hello, {{name}}!</h1>';
    
    // ok: typescript-dangerous-locals-as-template-context
    const compiledTemplate = handlebars.compile(template);
    const result = compiledTemplate({ name: req.query.name });
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    // Using a fixed template, only the data is from user input
    const template = 'h1 Welcome #{user}';
    
    // ok: typescript-dangerous-locals-as-template-context
    const html = pug.render(template, { user: req.body.username });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    // Using a predefined template
    const template = '<p>Welcome, <%= user %>!</p>';
    
    // ok: typescript-dangerous-locals-as-template-context
    const html = ejs.render(template, { user: req.query.username });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    // Using a fixed template
    const template = 'Hello, {{username}}!';
    
    // ok: typescript-dangerous-locals-as-template-context
    const rendered = mustache.render(template, { username: req.headers['x-username'] });
    
    res.send(rendered);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    // Using a predefined template
    const template = '<div>Welcome, {{ username }}</div>';
    
    // ok: typescript-dangerous-locals-as-template-context
    nunjucks.renderString(template, { username: req.body.username }, (err, result) => {
        if (err) {
            res.status(500).send('Error rendering template');
        } else {
            res.send(result);
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    // Using a fixed template
    const template = '<p>Hello, <%= user %>!</p>';
    
    // ok: typescript-dangerous-locals-as-template-context
    const compiled = lodash.template(template);
    const result = compiled({ user: req.query.name });
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    // Using sanitized user input in the context, not in the template
    const template = '<p>Hello, <%= user %>!</p>';
    
    // ok: typescript-dangerous-locals-as-template-context
    const html = ejs.render(template, { user: DOMPurify.sanitize(req.body.username) });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    // Using a predefined template with sanitized input in the context
    const template = '<div>{{name}}</div>';
    
    // ok: typescript-dangerous-locals-as-template-context
    const compiledTemplate = handlebars.compile(template);
    const result = compiledTemplate({ name: escape(req.cookies.username) });
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    // Using a template from a trusted source (not user input)
    const templates = {
        welcome: '<p>Welcome, <%= user %>!</p>',
        goodbye: '<p>Goodbye, <%= user %>!</p>'
    };
    
    const templateName = req.query.template as string;
    const selectedTemplate = templates[templateName as keyof typeof templates] || templates.welcome;
    
    // ok: typescript-dangerous-locals-as-template-context
    const html = ejs.render(selectedTemplate, { user: req.query.name });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    // Using a fixed template with user data
    const template = `
        <div>
            <h1>Welcome, {{user.name}}</h1>
            <p>Your role: {{user.role}}</p>
        </div>
    `;
    
    // ok: typescript-dangerous-locals-as-template-context
    const compiledTemplate = handlebars.compile(template);
    const result = compiledTemplate({ 
        user: {
            name: DOMPurify.sanitize(req.body.username),
            role: DOMPurify.sanitize(req.body.role)
        }
    });
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    // Using a template from a trusted source
    const getTemplate = (id: string): string => {
        const templates: Record<string, string> = {
            'user': '<p>User: <%= username %></p>',
            'admin': '<p>Admin: <%= username %></p>'
        };
        return templates[id] || templates['user'];
    };
    
    const templateId = req.query.template as string;
    const template = getTemplate(templateId);
    
    // ok: typescript-dangerous-locals-as-template-context
    const html = ejs.render(template, { username: req.query.name });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    // Using a fixed template with sanitized user input
    const template = 'p= message';
    
    const userMessage = req.body.message as string;
    const sanitizedMessage = DOMPurify.sanitize(userMessage);
    
    // ok: typescript-dangerous-locals-as-template-context
    const html = pug.render(template, { message: sanitizedMessage });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    // Using a fixed template with user data in a safe context
    const template = `
        <ul>
            {{#each items}}
                <li>{{this}}</li>
            {{/each}}
        </ul>
    `;
    
    const userItems = req.body.items as string[];
    const sanitizedItems = userItems.map(item => DOMPurify.sanitize(item));
    
    // ok: typescript-dangerous-locals-as-template-context
    const compiledTemplate = handlebars.compile(template);
    const result = compiledTemplate({ items: sanitizedItems });
    
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    // Using a whitelist to select a template
    const allowedTemplates = {
        'welcome': '<h1>Welcome, <%= user %>!</h1>',
        'profile': '<div>Profile for <%= user %></div>',
        'dashboard': '<div>Dashboard for <%= user %></div>'
    };
    
    const templateName = req.query.template as string;
    const template = allowedTemplates[templateName as keyof typeof allowedTemplates] || allowedTemplates.welcome;
    
    // ok: typescript-dangerous-locals-as-template-context
    const html = ejs.render(template, { user: req.session?.username || 'Guest' });
    
    res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    // Using a fixed template with user data in context
    const template = `
        <div class="user-card">
            <h2>{{ user.name }}</h2>
            <p>{{ user.email }}</p>
            <p>{{ user.bio }}</p>
        </div>
    `;
    
    const userData = {
        name: DOMPurify.sanitize(req.body.name || ''),
        email: DOMPurify.sanitize(req.body.email || ''),
        bio: DOMPurify.sanitize(req.body.bio || '')
    };
    
    // ok: typescript-dangerous-locals-as-template-context
    const result = nunjucks.renderString(template, { user: userData });
    
    res.send(result);
}
// {/fact}

export {
    bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
    bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
    bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
    good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
    good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
    good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};