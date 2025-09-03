// File: html_auto_escape_examples.ts
import * as express from 'express';
import * as nunjucks from 'nunjucks';
import * as pug from 'pug';
import * as ejs from 'ejs';
import * as handlebars from 'handlebars';
import * as mustache from 'mustache';
import * as React from 'react';
import * as ReactDOMServer from 'react-dom/server';
import { Liquid } from 'liquidjs';
import * as Eta from 'eta';
import * as Hogan from 'hogan.js';
import * as Marko from 'marko';
import * as Dust from 'dustjs-linkedin';
import * as Twig from 'twig';
import * as Swig from 'swig-templates';

// TRUE POSITIVES - Vulnerable code examples

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  const env = nunjucks.configure('views', {
    autoescape: false, // ruleid: typescript-do-not-disable-html-auto-escape
    express: app
  });
  
  app.get('/profile', (req, res) => {
    const username = req.query.username as string;
    res.render('profile.html', { username });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.set('view engine', 'pug');
  
  app.get('/article', (req, res) => {
    const content = req.query.content as string;
    // ruleid: typescript-do-not-disable-html-auto-escape
    const html = pug.render(`div !{content}`, { content });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/comment', (req, res) => {
    const comment = req.body.comment as string;
    // ruleid: typescript-do-not-disable-html-auto-escape
    const html = ejs.render('<div><%- comment %></div>', { comment });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  // ruleid: typescript-do-not-disable-html-auto-escape
  handlebars.compile('{{username}}', { noEscape: true });
  
  app.get('/user', (req, res) => {
    const username = req.query.username as string;
    const template = handlebars.compile('<div>{{username}}</div>', { noEscape: true });
    res.send(template({ username }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/message', (req, res) => {
    const message = req.query.message as string;
    // ruleid: typescript-do-not-disable-html-auto-escape
    mustache.parse('<div>{{{message}}}</div>');
    const rendered = mustache.render('<div>{{{message}}}</div>', { message });
    res.send(rendered);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const engine = new Liquid({
    // ruleid: typescript-do-not-disable-html-auto-escape
    autoEscape: false
  });
  
  app.get('/post', (req, res) => {
    const content = req.query.content as string;
    const template = engine.parseAndRenderSync('<div>{{ content }}</div>', { content });
    res.send(template);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: typescript-do-not-disable-html-auto-escape
  Eta.configure({
    autoEscape: false
  });
  
  app.get('/review', (req, res) => {
    const review = req.query.review as string;
    const html = Eta.render('<div><%= it.review %></div>', { review });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/notification', (req, res) => {
    const notification = req.query.notification as string;
    // ruleid: typescript-do-not-disable-html-auto-escape
    const template = Hogan.compile('<div>{{{notification}}}</div>');
    res.send(template.render({ notification }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // ruleid: typescript-do-not-disable-html-auto-escape
  const twigEnv = Twig.twig({
    autoescape: false
  });
  
  app.get('/bio', (req, res) => {
    const bio = req.query.bio as string;
    const template = Twig.twig({
      data: '<div>{{ bio }}</div>',
      autoescape: false
    });
    res.send(template.render({ bio }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  // ruleid: typescript-do-not-disable-html-auto-escape
  const swigEngine = new Swig({
    autoescape: false
  });
  
  app.get('/description', (req, res) => {
    const description = req.query.description as string;
    const template = swigEngine.compile('<div>{{ description }}</div>');
    res.send(template({ description }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/title', (req, res) => {
    const title = req.query.title as string;
    // ruleid: typescript-do-not-disable-html-auto-escape
    Dust.compile('<div>{title|s}</div>', 'title-template');
    Dust.loadSource(Dust.compile('<div>{title|s}</div>', 'title-template'));
    Dust.render('title-template', { title }, (err, out) => {
      res.send(out);
    });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  class DangerousComponent extends React.Component<{ html: string }> {
    render() {
      // ruleid: typescript-do-not-disable-html-auto-escape
      return React.createElement('div', { dangerouslySetInnerHTML: { __html: this.props.html } });
    }
  }
  
  const app = express();
  app.get('/react', (req, res) => {
    const userInput = req.query.content as string;
    const html = ReactDOMServer.renderToString(
      React.createElement(DangerousComponent, { html: userInput })
    );
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/template', (req, res) => {
    const content = req.query.content as string;
    // ruleid: typescript-do-not-disable-html-auto-escape
    const template = `
      <script>
        const rawHtml = String.raw\`${content}\`;
        document.getElementById('content').innerHTML = rawHtml;
      </script>
    `;
    res.send(template);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/custom-template', (req, res) => {
    const userContent = req.query.content as string;
    
    class CustomTemplateEngine {
      // ruleid: typescript-do-not-disable-html-auto-escape
      constructor(options: { escapeHtml: boolean } = { escapeHtml: true }) {
        this.options = options;
      }
      
      options: { escapeHtml: boolean };
      
      render(template: string, data: any): string {
        // Simple template rendering logic
        return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
          return this.options.escapeHtml ? this.escape(data[key]) : data[key];
        });
      }
      
      escape(html: string): string {
        return html
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      }
    }
    
    const engine = new CustomTemplateEngine({ escapeHtml: false });
    const html = engine.render('<div>{{content}}</div>', { content: userContent });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/markdown', (req, res) => {
    const markdown = req.query.markdown as string;
    
    class MarkdownRenderer {
      // ruleid: typescript-do-not-disable-html-auto-escape
      render(md: string, options: { sanitize: boolean } = { sanitize: true }): string {
        // Simplified markdown rendering
        let html = md
          .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
          .replace(/\*(.*?)\*/g, '<em>$1</em>')
          .replace(/\n/g, '<br>');
        
        // Skip sanitization if option is false
        if (!options.sanitize) {
          return html;
        }
        
        // Simple sanitization
        return html
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
      }
    }
    
    const renderer = new MarkdownRenderer();
    const html = renderer.render(markdown, { sanitize: false });
    res.send(`<div>${html}</div>`);
  });
}
// {/fact}

// TRUE NEGATIVES - Secure code examples

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const app = express();
  const env = nunjucks.configure('views', {
    // ok: typescript-do-not-disable-html-auto-escape
    autoescape: true,
    express: app
  });
  
  app.get('/profile', (req, res) => {
    const username = req.query.username as string;
    res.render('profile.html', { username });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.set('view engine', 'pug');
  
  app.get('/article', (req, res) => {
    const content = req.query.content as string;
    // ok: typescript-do-not-disable-html-auto-escape
    const html = pug.render(`div #{content}`, { content });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/comment', (req, res) => {
    const comment = req.query.comment as string;
    // ok: typescript-do-not-disable-html-auto-escape
    const html = ejs.render('<div><%= comment %></div>', { comment });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  // ok: typescript-do-not-disable-html-auto-escape
  handlebars.compile('{{username}}');
  
  app.get('/user', (req, res) => {
    const username = req.query.username as string;
    const template = handlebars.compile('<div>{{username}}</div>');
    res.send(template({ username }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/message', (req, res) => {
    const message = req.query.message as string;
    // ok: typescript-do-not-disable-html-auto-escape
    mustache.parse('<div>{{message}}</div>');
    const rendered = mustache.render('<div>{{message}}</div>', { message });
    res.send(rendered);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const engine = new Liquid({
    // ok: typescript-do-not-disable-html-auto-escape
    autoEscape: true
  });
  
  app.get('/post', (req, res) => {
    const content = req.query.content as string;
    const template = engine.parseAndRenderSync('<div>{{ content }}</div>', { content });
    res.send(template);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: typescript-do-not-disable-html-auto-escape
  Eta.configure({
    autoEscape: true
  });
  
  app.get('/review', (req, res) => {
    const review = req.query.review as string;
    const html = Eta.render('<div><%= it.review %></div>', { review });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/notification', (req, res) => {
    const notification = req.query.notification as string;
    // ok: typescript-do-not-disable-html-auto-escape
    const template = Hogan.compile('<div>{{notification}}</div>');
    res.send(template.render({ notification }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // ok: typescript-do-not-disable-html-auto-escape
  const twigEnv = Twig.twig({
    autoescape: true
  });
  
  app.get('/bio', (req, res) => {
    const bio = req.query.bio as string;
    const template = Twig.twig({
      data: '<div>{{ bio }}</div>',
      autoescape: true
    });
    res.send(template.render({ bio }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // ok: typescript-do-not-disable-html-auto-escape
  const swigEngine = new Swig({
    autoescape: true
  });
  
  app.get('/description', (req, res) => {
    const description = req.query.description as string;
    const template = swigEngine.compile('<div>{{ description }}</div>');
    res.send(template({ description }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/title', (req, res) => {
    const title = req.query.title as string;
    // ok: typescript-do-not-disable-html-auto-escape
    Dust.compile('<div>{title}</div>', 'title-template');
    Dust.loadSource(Dust.compile('<div>{title}</div>', 'title-template'));
    Dust.render('title-template', { title }, (err, out) => {
      res.send(out);
    });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  class SafeComponent extends React.Component<{ content: string }> {
    render() {
      // ok: typescript-do-not-disable-html-auto-escape
      return React.createElement('div', null, this.props.content);
    }
  }
  
  const app = express();
  app.get('/react', (req, res) => {
    const userInput = req.query.content as string;
    const html = ReactDOMServer.renderToString(
      React.createElement(SafeComponent, { content: userInput })
    );
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/template', (req, res) => {
    const content = req.query.content as string;
    
    // Helper function to escape HTML
    function escapeHtml(unsafe: string): string {
      return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }
    
    // ok: typescript-do-not-disable-html-auto-escape
    const safeContent = escapeHtml(content);
    const template = `
      <script>
        const escapedContent = "${safeContent}";
        document.getElementById('content').textContent = escapedContent;
      </script>
    `;
    res.send(template);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/custom-template', (req, res) => {
    const userContent = req.query.content as string;
    
    class CustomTemplateEngine {
      // ok: typescript-do-not-disable-html-auto-escape
      constructor(options: { escapeHtml: boolean } = { escapeHtml: true }) {
        this.options = options;
      }
      
      options: { escapeHtml: boolean };
      
      render(template: string, data: any): string {
        // Simple template rendering logic with escaping enabled by default
        return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
          return this.options.escapeHtml ? this.escape(data[key]) : data[key];
        });
      }
      
      escape(html: string): string {
        return html
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      }
    }
    
    const engine = new CustomTemplateEngine();
    const html = engine.render('<div>{{content}}</div>', { content: userContent });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/markdown', (req, res) => {
    const markdown = req.query.markdown as string;
    
    class MarkdownRenderer {
      // ok: typescript-do-not-disable-html-auto-escape
      render(md: string, options: { sanitize: boolean } = { sanitize: true }): string {
        // Simplified markdown rendering
        let html = md
          .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
          .replace(/\*(.*?)\*/g, '<em>$1</em>')
          .replace(/\n/g, '<br>');
        
        // Always sanitize by default
        return html
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
      }
    }
    
    const renderer = new MarkdownRenderer();
    const html = renderer.render(markdown);
    res.send(`<div>${html}</div>`);
  });
}
// {/fact}