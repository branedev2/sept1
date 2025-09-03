// File: auto_escape_examples.js

const express = require('express');
const app = express();
const handlebars = require('handlebars');
const pug = require('pug');
const ejs = require('ejs');
const nunjucks = require('nunjucks');
const mustache = require('mustache');
const React = require('react');
const ReactDOMServer = require('react-dom/server');
const Vue = require('vue');
const { renderToString } = require('vue/server-renderer');
const { marked } = require('marked');
const DOMPurify = require('dompurify');

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  // Using Handlebars with noEscape option
  const template = handlebars.compile('<div>{{{userContent}}}</div>', {
    // ruleid: javascript-do-not-disable-html-auto-escape
    noEscape: true
  });
  
  const userInput = req.query.content;
  return template({ userContent: userInput });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  // Using EJS with escape disabled
  app.set('view engine', 'ejs');
  
  // ruleid: javascript-do-not-disable-html-auto-escape
  app.set('view options', {
    escape: false
  });
  
  app.get('/profile', (req, res) => {
    res.render('profile', { userBio: req.query.bio });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  // Using Nunjucks with autoescape disabled
  const env = nunjucks.configure('views', {
    // ruleid: javascript-do-not-disable-html-auto-escape
    autoescape: false
  });
  
  app.get('/article', (req, res) => {
    const html = nunjucks.render('article.html', { content: req.body.content });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  // Using Pug with disabling escaping via unescaped interpolation
  app.get('/user', (req, res) => {
    const userName = req.query.name;
    // ruleid: javascript-do-not-disable-html-auto-escape
    const html = pug.compile('div !{userName}')({ userName });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  // Using Mustache with disabling HTML escaping
  app.get('/comment', (req, res) => {
    const comment = req.query.text;
    const template = '<div>{{{comment}}}</div>';
    // ruleid: javascript-do-not-disable-html-auto-escape
    const html = mustache.render(template, { comment });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  // Using React with dangerouslySetInnerHTML
  app.get('/post', (req, res) => {
    const userPost = req.query.post;
    
    const MyComponent = () => {
      return React.createElement('div', {
        // ruleid: javascript-do-not-disable-html-auto-escape
        dangerouslySetInnerHTML: { __html: userPost }
      });
    };
    
    const html = ReactDOMServer.renderToString(React.createElement(MyComponent));
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  // Using Vue with v-html directive
  app.get('/message', (req, res) => {
    const userMessage = req.query.message;
    
    const app = Vue.createApp({
      template: `
        <div>
          <!-- ruleid: javascript-do-not-disable-html-auto-escape -->
          <p v-html="message"></p>
        </div>
      `,
      data() {
        return {
          message: userMessage
        };
      }
    });
    
    const html = renderToString(app);
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  // Using innerHTML directly
  app.get('/content', (req, res) => {
    const userContent = req.query.content;
    
    const html = `
      <html>
        <body>
          <script>
            document.getElementById('output').innerHTML = '${userContent}'; // ruleid: javascript-do-not-disable-html-auto-escape
          </script>
          <div id="output"></div>
        </body>
      </html>
    `;
    
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  // Using marked with sanitize disabled
  app.get('/markdown', (req, res) => {
    const userMarkdown = req.query.md;
    
    // ruleid: javascript-do-not-disable-html-auto-escape
    marked.setOptions({
      sanitize: false
    });
    
    const html = marked(userMarkdown);
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  // Using custom template engine with escaping disabled
  class TemplateEngine {
    constructor(options = {}) {
      // ruleid: javascript-do-not-disable-html-auto-escape
      this.escapeHtml = options.escapeHtml === false ? false : true;
    }
    
    render(template, data) {
      if (!this.escapeHtml) {
        // Directly insert data without escaping
        return template.replace(/\{\{(.+?)\}\}/g, (match, key) => {
          return data[key.trim()] || '';
        });
      }
      // Escaping logic would be here
    }
  }
  
  const engine = new TemplateEngine({ escapeHtml: false });
  const html = engine.render('<div>{{content}}</div>', { content: req.query.content });
  return html;
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  // Using EJS with raw output tags
  app.get('/description', (req, res) => {
    const userDesc = req.query.desc;
    
    // ruleid: javascript-do-not-disable-html-auto-escape
    const html = ejs.render('<div><%-userDesc%></div>', { userDesc });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  // Using Handlebars with SafeString
  app.get('/title', (req, res) => {
    const userTitle = req.query.title;
    
    const template = handlebars.compile('<h1>{{title}}</h1>');
    // ruleid: javascript-do-not-disable-html-auto-escape
    const safeTitle = new handlebars.SafeString(userTitle);
    
    const html = template({ title: safeTitle });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  // Using a configuration object with multiple settings including disabling escaping
  const config = {
    debug: true,
    cache: true,
    // ruleid: javascript-do-not-disable-html-auto-escape
    autoescape: false,
    minify: true
  };
  
  nunjucks.configure('views', config);
  
  app.get('/page', (req, res) => {
    const html = nunjucks.render('page.html', { content: req.query.content });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  // Using template literals with unescaped user input in HTML
  app.get('/profile', (req, res) => {
    const userName = req.query.name;
    const userBio = req.query.bio;
    
    // ruleid: javascript-do-not-disable-html-auto-escape
    const html = `
      <html>
        <body>
          <h1>${userName}</h1>
          <div id="bio">${userBio}</div>
        </body>
      </html>
    `;
    
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  // Using a function that explicitly disables HTML escaping
  function renderTemplate(template, data, options = {}) {
    // ruleid: javascript-do-not-disable-html-auto-escape
    const escapeHtml = options.escapeHtml !== false;
    
    if (!escapeHtml) {
      return template.replace(/\{\{(.+?)\}\}/g, (match, key) => {
        return data[key.trim()] || '';
      });
    }
    
    // Escaping logic would be here
  }
  
  app.get('/comment', (req, res) => {
    const html = renderTemplate('<div>{{comment}}</div>', 
                               { comment: req.query.comment }, 
                               { escapeHtml: false });
    res.send(html);
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  // Using Handlebars with default escaping (not disabling it)
  // ok: javascript-do-not-disable-html-auto-escape
  const template = handlebars.compile('<div>{{userContent}}</div>');
  
  const userInput = req.query.content;
  return template({ userContent: userInput });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  // Using EJS with escape enabled (default)
  app.set('view engine', 'ejs');
  
  // ok: javascript-do-not-disable-html-auto-escape
  app.set('view options', {
    escape: true
  });
  
  app.get('/profile', (req, res) => {
    res.render('profile', { userBio: req.query.bio });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  // Using Nunjucks with autoescape enabled (default)
  // ok: javascript-do-not-disable-html-auto-escape
  const env = nunjucks.configure('views', {
    autoescape: true
  });
  
  app.get('/article', (req, res) => {
    const html = nunjucks.render('article.html', { content: req.body.content });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  // Using Pug with escaped interpolation
  app.get('/user', (req, res) => {
    const userName = req.query.name;
    // ok: javascript-do-not-disable-html-auto-escape
    const html = pug.compile('div #{userName}')({ userName });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  // Using Mustache with HTML escaping (default)
  app.get('/comment', (req, res) => {
    const comment = req.query.text;
    const template = '<div>{{comment}}</div>';
    // ok: javascript-do-not-disable-html-auto-escape
    const html = mustache.render(template, { comment });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  // Using React without dangerouslySetInnerHTML
  app.get('/post', (req, res) => {
    const userPost = req.query.post;
    
    // ok: javascript-do-not-disable-html-auto-escape
    const MyComponent = () => {
      return React.createElement('div', null, userPost);
    };
    
    const html = ReactDOMServer.renderToString(React.createElement(MyComponent));
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  // Using Vue with text interpolation instead of v-html
  app.get('/message', (req, res) => {
    const userMessage = req.query.message;
    
    // ok: javascript-do-not-disable-html-auto-escape
    const app = Vue.createApp({
      template: `
        <div>
          <p>{{ message }}</p>
        </div>
      `,
      data() {
        return {
          message: userMessage
        };
      }
    });
    
    const html = renderToString(app);
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  // Using textContent instead of innerHTML
  app.get('/content', (req, res) => {
    const userContent = req.query.content;
    
    const html = `
      <html>
        <body>
          <script>
            // ok: javascript-do-not-disable-html-auto-escape
            document.getElementById('output').textContent = '${userContent}';
          </script>
          <div id="output"></div>
        </body>
      </html>
    `;
    
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  // Using marked with sanitize enabled
  app.get('/markdown', (req, res) => {
    const userMarkdown = req.query.md;
    
    // ok: javascript-do-not-disable-html-auto-escape
    marked.setOptions({
      sanitize: true
    });
    
    const html = marked(userMarkdown);
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  // Using custom template engine with escaping enabled
  class TemplateEngine {
    constructor(options = {}) {
      // ok: javascript-do-not-disable-html-auto-escape
      this.escapeHtml = options.escapeHtml !== false;
    }
    
    render(template, data) {
      if (this.escapeHtml) {
        // Escape HTML before inserting
        return template.replace(/\{\{(.+?)\}\}/g, (match, key) => {
          const value = data[key.trim()] || '';
          return this._escape(value);
        });
      }
    }
    
    _escape(html) {
      return String(html)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
  }
  
  const engine = new TemplateEngine({ escapeHtml: true });
  const html = engine.render('<div>{{content}}</div>', { content: req.query.content });
  return html;
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  // Using EJS with escaped output tags
  app.get('/description', (req, res) => {
    const userDesc = req.query.desc;
    
    // ok: javascript-do-not-disable-html-auto-escape
    const html = ejs.render('<div><%=userDesc%></div>', { userDesc });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  // Using DOMPurify to sanitize HTML before rendering
  app.get('/title', (req, res) => {
    const userTitle = req.query.title;
    
    // ok: javascript-do-not-disable-html-auto-escape
    const sanitizedTitle = DOMPurify.sanitize(userTitle);
    
    const html = `<h1>${sanitizedTitle}</h1>`;
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  // Using a configuration object with explicit autoescape enabled
  const config = {
    debug: true,
    cache: true,
    // ok: javascript-do-not-disable-html-auto-escape
    autoescape: true,
    minify: true
  };
  
  nunjucks.configure('views', config);
  
  app.get('/page', (req, res) => {
    const html = nunjucks.render('page.html', { content: req.query.content });
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  // Using template literals with proper escaping function
  app.get('/profile', (req, res) => {
    const userName = req.query.name;
    const userBio = req.query.bio;
    
    function escapeHtml(unsafe) {
      return String(unsafe)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
    
    // ok: javascript-do-not-disable-html-auto-escape
    const html = `
      <html>
        <body>
          <h1>${escapeHtml(userName)}</h1>
          <div id="bio">${escapeHtml(userBio)}</div>
        </body>
      </html>
    `;
    
    res.send(html);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  // Using a function that explicitly enables HTML escaping
  function renderTemplate(template, data, options = {}) {
    // ok: javascript-do-not-disable-html-auto-escape
    const escapeHtml = options.escapeHtml !== false;
    
    function escape(html) {
      if (!escapeHtml) return html;
      return String(html)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
    
    return template.replace(/\{\{(.+?)\}\}/g, (match, key) => {
      return escape(data[key.trim()] || '');
    });
  }
  
  app.get('/comment', (req, res) => {
    const html = renderTemplate('<div>{{comment}}</div>', 
                               { comment: req.query.comment }, 
                               { escapeHtml: true });
    res.send(html);
  });
}
// {/fact}