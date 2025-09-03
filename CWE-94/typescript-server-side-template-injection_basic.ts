import express from 'express';
import Handlebars from 'handlebars';
import { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { sanitizeTemplate } from './security-utils'; // Hypothetical sanitization library

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.get('/render-template', (req: Request, res: Response) => {
    const userTemplate = req.query.template as string;
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(userTemplate);
    
    const result = template({ name: 'User' });
    res.send(result);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.post('/create-email', (req: Request, res: Response) => {
    const emailTemplate = req.body.template;
    const userData = { 
      firstName: req.body.firstName,
      lastName: req.body.lastName
    };
    
    try {
      // ruleid: typescript-server-side-template-injection
      const compiledTemplate = Handlebars.compile(emailTemplate);
      const emailContent = compiledTemplate(userData);
      
      res.json({ success: true, email: emailContent });
    } catch (error) {
      res.status(500).json({ error: 'Failed to compile template' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/preview', (req: Request, res: Response) => {
    const templateHeader = '<h1>Welcome {{name}}!</h1>';
    const templateFooter = '<p>Copyright 2023</p>';
    const userContent = req.query.content as string;
    
    // Concatenating user input with template parts
    const fullTemplate = templateHeader + userContent + templateFooter;
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(fullTemplate);
    
    res.send(template({ name: 'Guest' }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.get('/dynamic-page/:id', (req: Request, res: Response) => {
    const pageId = req.params.id;
    const customization = req.headers['x-template-customization'] as string;
    
    // Using header input in template
    // ruleid: typescript-server-side-template-injection
    const headerTemplate = Handlebars.compile(customization);
    
    const content = headerTemplate({ pageId });
    res.send(content);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/save-template', (req: Request, res: Response) => {
    const templateName = req.body.name;
    const templateContent = req.body.content;
    
    try {
      // Testing template by compiling it
      // ruleid: typescript-server-side-template-injection
      const test = Handlebars.compile(templateContent);
      
      // Save template to database if compilation succeeds
      res.json({ success: true, message: 'Template saved' });
    } catch (error) {
      res.status(400).json({ error: 'Invalid template' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.get('/render-with-cookie', (req: Request, res: Response) => {
    const userPreferences = req.cookies.preferences;
    let templateString = '';
    
    try {
      // Parse JSON from cookie
      const preferences = JSON.parse(userPreferences);
      templateString = preferences.template || '';
      
      // ruleid: typescript-server-side-template-injection
      const template = Handlebars.compile(templateString);
      
      res.send(template({ user: 'Guest' }));
    } catch (error) {
      res.status(400).send('Invalid preferences');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.post('/process-form', (req: Request, res: Response) => {
    const formData = req.body;
    let output = '';
    
    if (formData.useTemplate === 'true') {
      // ruleid: typescript-server-side-template-injection
      const template = Handlebars.compile(formData.templateData);
      output = template(formData);
    } else {
      output = 'No template processing requested';
    }
    
    res.send(output);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/multi-step-template', (req: Request, res: Response) => {
    const step1 = req.query.header as string;
    const step2 = req.query.body as string;
    const step3 = req.query.footer as string;
    
    const combinedTemplate = `${step1}\n${step2}\n${step3}`;
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(combinedTemplate);
    
    res.send(template({ title: 'Dynamic Page' }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/template-from-url', async (req: Request, res: Response) => {
    const templateUrl = req.query.url as string;
    
    try {
      const response = await fetch(templateUrl);
      const templateText = await response.text();
      
      // ruleid: typescript-server-side-template-injection
      const template = Handlebars.compile(templateText);
      
      res.send(template({ data: 'External template loaded' }));
    } catch (error) {
      res.status(500).send('Failed to load template');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/conditional-template', (req: Request, res: Response) => {
    let templateToUse;
    
    if (req.body.advanced === 'true') {
      templateToUse = req.body.advancedTemplate;
    } else {
      templateToUse = '<p>Basic template with {{content}}</p>';
    }
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(templateToUse);
    
    res.send(template({ content: req.body.content }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/template-with-partials', (req: Request, res: Response) => {
    const mainTemplate = req.query.template as string;
    const partialContent = req.query.partial as string;
    
    // Register partial from user input
    Handlebars.registerPartial('userPartial', partialContent);
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(mainTemplate);
    
    res.send(template({ message: 'Template with partials' }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.post('/template-options', (req: Request, res: Response) => {
    const userTemplate = req.body.template;
    const compileOptions = {
      noEscape: req.body.noEscape === 'true',
      strict: req.body.strict === 'true'
    };
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(userTemplate, compileOptions);
    
    res.send(template({ data: req.body.data }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/language-template', (req: Request, res: Response) => {
    const language = req.query.lang as string || 'en';
    const userCustomization = req.query.custom as string || '';
    
    let baseTemplate = '';
    switch (language) {
      case 'fr':
        baseTemplate = '<h1>Bonjour {{name}}!</h1>';
        break;
      case 'es':
        baseTemplate = '<h1>Hola {{name}}!</h1>';
        break;
      default:
        baseTemplate = '<h1>Hello {{name}}!</h1>';
    }
    
    const fullTemplate = baseTemplate + userCustomization;
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(fullTemplate);
    
    res.send(template({ name: 'User' }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.post('/dynamic-email', (req: Request, res: Response) => {
    const recipientName = req.body.name;
    const emailType = req.body.type;
    const customContent = req.body.content;
    
    let emailTemplate = '';
    if (emailType === 'welcome') {
      emailTemplate = `<h1>Welcome ${recipientName}!</h1>{{customContent}}`;
    } else if (emailType === 'farewell') {
      emailTemplate = `<h1>Goodbye ${recipientName}!</h1>{{customContent}}`;
    } else {
      emailTemplate = customContent; // Fully user-controlled if type is unknown
    }
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(emailTemplate);
    
    res.json({ 
      email: template({ customContent, recipientName }) 
    });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/admin/preview-template', (req: Request, res: Response) => {
    // Even in admin routes, user input should be treated as untrusted
    const templateId = req.query.id as string;
    const previewData = req.query.data as string;
    
    // This simulates retrieving a template from a database
    // but the template itself is still from user input
    const mockDbLookup = () => {
      return req.query.template as string;
    };
    
    const templateContent = mockDbLookup();
    
    // ruleid: typescript-server-side-template-injection
    const template = Handlebars.compile(templateContent);
    
    let contextData = {};
    try {
      contextData = JSON.parse(previewData);
    } catch (e) {
      contextData = { error: 'Invalid JSON data' };
    }
    
    res.send(template(contextData));
  });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/render-template', (req: Request, res: Response) => {
    // Using predefined templates instead of user input
    const templateName = req.query.template as string;
    let templateContent = '';
    
    // Only allow selection from predefined templates
    switch (templateName) {
      case 'welcome':
        templateContent = '<h1>Welcome {{name}}!</h1>';
        break;
      case 'goodbye':
        templateContent = '<h1>Goodbye {{name}}!</h1>';
        break;
      default:
        templateContent = '<h1>Hello {{name}}!</h1>';
    }
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(templateContent);
    
    const result = template({ name: req.query.name || 'User' });
    res.send(result);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/create-email', (req: Request, res: Response) => {
    // Load template from a trusted file instead of user input
    const templateType = req.body.type;
    let templatePath = '';
    
    // Validate and whitelist template types
    if (['welcome', 'reset', 'newsletter'].includes(templateType)) {
      templatePath = path.join(__dirname, 'templates', `${templateType}.hbs`);
    } else {
      templatePath = path.join(__dirname, 'templates', 'default.hbs');
    }
    
    try {
      const templateContent = fs.readFileSync(templatePath, 'utf8');
      
      // ok: typescript-server-side-template-injection
      const template = Handlebars.compile(templateContent);
      
      const emailContent = template({
        firstName: req.body.firstName,
        lastName: req.body.lastName
      });
      
      res.json({ success: true, email: emailContent });
    } catch (error) {
      res.status(500).json({ error: 'Failed to compile template' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/preview', (req: Request, res: Response) => {
    const templateHeader = '<h1>Welcome {{name}}!</h1>';
    const templateFooter = '<p>Copyright 2023</p>';
    
    // Instead of injecting user content into the template,
    // pass it as a context variable
    const userContent = req.query.content as string;
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(templateHeader + '<div>{{userContent}}</div>' + templateFooter);
    
    res.send(template({ 
      name: 'Guest',
      userContent: userContent // User content passed as data, not as template code
    }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.get('/dynamic-page/:id', (req: Request, res: Response) => {
    const pageId = req.params.id;
    
    // Use a predefined template
    const templateContent = '<header>{{customHeader}}</header><main>{{content}}</main>';
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(templateContent);
    
    // User input is passed as data to the template, not as template code
    const content = template({ 
      customHeader: req.headers['x-template-customization'] || 'Default Header',
      content: `Content for page ${pageId}`
    });
    
    res.send(content);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/save-template', (req: Request, res: Response) => {
    const templateName = req.body.name;
    const templateContent = req.body.content;
    
    try {
      // Sanitize the template before compiling
      const sanitizedTemplate = sanitizeTemplate(templateContent);
      
      // ok: typescript-server-side-template-injection
      const test = Handlebars.compile(sanitizedTemplate);
      
      // Save sanitized template to database if compilation succeeds
      res.json({ success: true, message: 'Template saved' });
    } catch (error) {
      res.status(400).json({ error: 'Invalid template' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.get('/render-with-cookie', (req: Request, res: Response) => {
    // Instead of using a template from cookies, use a predefined template
    const templateString = '<div>Hello {{user}}, your preferences are: {{preferences}}</div>';
    
    try {
      // Parse JSON from cookie
      const userPreferences = req.cookies.preferences ? JSON.parse(req.cookies.preferences) : {};
      
      // ok: typescript-server-side-template-injection
      const template = Handlebars.compile(templateString);
      
      res.send(template({ 
        user: 'Guest', 
        preferences: JSON.stringify(userPreferences)
      }));
    } catch (error) {
      res.status(400).send('Invalid preferences');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.post('/process-form', (req: Request, res: Response) => {
    const formData = req.body;
    let output = '';
    
    // Use a whitelist of allowed templates
    const allowedTemplates = {
      'contact': '<h1>Contact Form</h1><p>Name: {{name}}</p><p>Email: {{email}}</p>',
      'feedback': '<h1>Feedback</h1><p>Rating: {{rating}}/5</p><p>Comment: {{comment}}</p>'
    };
    
    const templateKey = formData.templateType;
    
    if (templateKey && allowedTemplates[templateKey]) {
      // ok: typescript-server-side-template-injection
      const template = Handlebars.compile(allowedTemplates[templateKey]);
      output = template(formData);
    } else {
      output = 'Invalid template type';
    }
    
    res.send(output);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/multi-step-template', (req: Request, res: Response) => {
    // Pre-defined template parts
    const headerTemplates = {
      'simple': '<header>{{title}}</header>',
      'fancy': '<header class="fancy">{{title}}</header>'
    };
    
    const bodyTemplates = {
      'one-col': '<div class="one-col">{{content}}</div>',
      'two-col': '<div class="two-col"><div>{{content}}</div><div>{{sidebar}}</div></div>'
    };
    
    const footerTemplates = {
      'minimal': '<footer>&copy; 2023</footer>',
      'full': '<footer>&copy; 2023 - <a href="{{contactLink}}">Contact</a></footer>'
    };
    
    // Get user selections from query params with defaults
    const headerType = (req.query.header as string) in headerTemplates ? 
      (req.query.header as string) : 'simple';
    
    const bodyType = (req.query.body as string) in bodyTemplates ? 
      (req.query.body as string) : 'one-col';
    
    const footerType = (req.query.footer as string) in footerTemplates ? 
      (req.query.footer as string) : 'minimal';
    
    // Combine selected templates
    const combinedTemplate = `
      ${headerTemplates[headerType]}
      ${bodyTemplates[bodyType]}
      ${footerTemplates[footerType]}
    `;
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(combinedTemplate);
    
    res.send(template({ 
      title: 'Dynamic Page',
      content: req.query.content || 'Default content',
      sidebar: req.query.sidebar || 'Sidebar content',
      contactLink: '/contact'
    }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/template-from-url', async (req: Request, res: Response) => {
    // Instead of loading templates from arbitrary URLs, use a whitelist
    const allowedTemplateUrls = {
      'product': 'https://trusted-domain.com/templates/product.hbs',
      'profile': 'https://trusted-domain.com/templates/profile.hbs'
    };
    
    const templateKey = req.query.template as string;
    
    if (!templateKey || !allowedTemplateUrls[templateKey]) {
      return res.status(400).send('Invalid template key');
    }
    
    try {
      const response = await fetch(allowedTemplateUrls[templateKey]);
      const templateText = await response.text();
      
      // ok: typescript-server-side-template-injection
      const template = Handlebars.compile(templateText);
      
      res.send(template({ data: req.query.data || 'Default data' }));
    } catch (error) {
      res.status(500).send('Failed to load template');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/conditional-template', (req: Request, res: Response) => {
    // Predefined templates for different use cases
    const templates = {
      basic: '<p>Basic template with {{content}}</p>',
      advanced: '<div class="advanced"><h2>{{title}}</h2><p>{{content}}</p></div>'
    };
    
    const templateType = req.body.type === 'advanced' ? 'advanced' : 'basic';
    const templateToUse = templates[templateType];
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(templateToUse);
    
    res.send(template({ 
      content: req.body.content || '',
      title: req.body.title || 'Default Title'
    }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/template-with-partials', (req: Request, res: Response) => {
    // Predefined partials
    const partials = {
      header: '<header>{{headerText}}</header>',
      footer: '<footer>{{footerText}}</footer>'
    };
    
    // Register safe partials
    Object.entries(partials).forEach(([name, content]) => {
      Handlebars.registerPartial(name, content);
    });
    
    // Predefined main template that uses partials
    const mainTemplate = `
      {{> header}}
      <main>{{mainContent}}</main>
      {{> footer}}
    `;
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(mainTemplate);
    
    res.send(template({ 
      headerText: req.query.header || 'Default Header',
      mainContent: req.query.content || 'Default Content',
      footerText: req.query.footer || '© 2023'
    }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.post('/template-options', (req: Request, res: Response) => {
    // Predefined template
    const templateContent = '<div class="{{className}}">{{content}}</div>';
    
    // Safe compile options
    const compileOptions = {
      noEscape: false, // Always escape output
      strict: true     // Use strict mode
    };
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(templateContent, compileOptions);
    
    res.send(template({ 
      className: req.body.className || 'default',
      content: req.body.content || 'Default content'
    }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/language-template', (req: Request, res: Response) => {
    const language = req.query.lang as string || 'en';
    
    // Predefined templates for different languages
    const templates = {
      en: '<h1>Hello {{name}}!</h1><p>{{message}}</p>',
      fr: '<h1>Bonjour {{name}}!</h1><p>{{message}}</p>',
      es: '<h1>Hola {{name}}!</h1><p>{{message}}</p>',
      de: '<h1>Hallo {{name}}!</h1><p>{{message}}</p>'
    };
    
    // Default to English if language not supported
    const templateContent = templates[language] || templates.en;
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(templateContent);
    
    res.send(template({ 
      name: req.query.name || 'User',
      message: req.query.message || 'Welcome to our site!'
    }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.post('/dynamic-email', (req: Request, res: Response) => {
    const recipientName = req.body.name;
    const emailType = req.body.type;
    
    // Predefined email templates
    const emailTemplates = {
      welcome: '<h1>Welcome {{recipientName}}!</h1><p>{{customContent}}</p>',
      farewell: '<h1>Goodbye {{recipientName}}!</h1><p>{{customContent}}</p>',
      notification: '<h1>Notification for {{recipientName}}</h1><p>{{customContent}}</p>'
    };
    
    // Default to notification if type not recognized
    const templateContent = emailTemplates[emailType] || emailTemplates.notification;
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(templateContent);
    
    res.json({ 
      email: template({ 
        recipientName: recipientName || 'User',
        customContent: req.body.content || 'No additional content provided.'
      }) 
    });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/admin/preview-template', (req: Request, res: Response) => {
    const templateId = req.query.id as string;
    
    // Simulate retrieving a template from a secure source
    const getTemplateById = (id: string): string => {
      const templates = {
        '1': '<h1>{{title}}</h1><p>{{content}}</p>',
        '2': '<div class="card"><h2>{{title}}</h2><div>{{content}}</div></div>',
        '3': '<section><h1>{{title}}</h1><article>{{content}}</article></section>'
      };
      
      return templates[id] || templates['1'];
    };
    
    const templateContent = getTemplateById(templateId);
    
    // ok: typescript-server-side-template-injection
    const template = Handlebars.compile(templateContent);
    
    // Parse preview data if provided, or use defaults
    let contextData = { title: 'Default Title', content: 'Default content' };
    
    if (req.query.data) {
      try {
        const parsedData = JSON.parse(req.query.data as string);
        contextData = {
          title: parsedData.title || contextData.title,
          content: parsedData.content || contextData.content
        };
      } catch (e) {
        // If JSON parsing fails, use defaults
      }
    }
    
    res.send(template(contextData));
  });
}
// {/fact}