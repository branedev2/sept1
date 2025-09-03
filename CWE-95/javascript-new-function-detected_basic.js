// This file contains examples of secure and insecure uses of the Function constructor in JavaScript
// Rule ID: javascript-new-function-detected
// CWE: 95 - Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

// ====== TRUE POSITIVES (VULNERABLE CODE) ======

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_1() {
  const express = require('express');
  const app = express();
  
  app.get('/execute', (req, res) => {
    const userCode = req.query.code;
    // ruleid: javascript-new-function-detected
    const dynamicFunction = new Function(userCode);
    dynamicFunction();
    res.send('Code executed');
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_2() {
  const http = require('http');
  
  http.createServer((req, res) => {
    if (req.url.startsWith('/api/execute')) {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        const data = JSON.parse(body);
        // ruleid: javascript-new-function-detected
        const userFunction = new Function('return ' + data.code)();
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({ result: userFunction }));
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_3() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/calculate', (req, res) => {
    const formula = req.body.formula;
    try {
      // ruleid: javascript-new-function-detected
      const calculator = new Function('return ' + formula);
      const result = calculator();
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: 'Invalid formula' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_4() {
  const http = require('http');
  const url = require('url');
  
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    if (parsedUrl.pathname === '/dynamic-template') {
      const template = parsedUrl.query.template || '';
      const data = { name: 'User', items: ['Item 1', 'Item 2'] };
      
      try {
        // ruleid: javascript-new-function-detected
        const templateFunction = new Function('data', `
          let result = "";
          ${template}
          return result;
        `);
        
        const output = templateFunction(data);
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(output);
      } catch (error) {
        res.writeHead(500);
        res.end('Template error');
      }
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_5() {
  const express = require('express');
  const app = express();
  
  app.get('/custom-filter', (req, res) => {
    const items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const filterCondition = req.query.filter || 'item > 5';
    
    try {
      // ruleid: javascript-new-function-detected
      const filterFunction = new Function('item', `return ${filterCondition};`);
      const filteredItems = items.filter(filterFunction);
      res.json(filteredItems);
    } catch (error) {
      res.status(400).json({ error: 'Invalid filter condition' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_6() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/execute-script', (req, res) => {
    const { script, parameters } = req.body;
    
    try {
      const paramNames = Object.keys(parameters || {});
      const paramValues = Object.values(parameters || {});
      
      // ruleid: javascript-new-function-detected
      const customFunction = new Function(...paramNames, script);
      const result = customFunction(...paramValues);
      
      res.json({ success: true, result });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_7() {
  const http = require('http');
  const querystring = require('querystring');
  
  http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/transform') {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        const data = querystring.parse(body);
        const inputArray = JSON.parse(data.array || '[]');
        const transformation = data.transform || 'item => item';
        
        try {
          // ruleid: javascript-new-function-detected
          const transformFn = new Function('return ' + transformation)();
          const result = inputArray.map(transformFn);
          
          res.writeHead(200, {'Content-Type': 'application/json'});
          res.end(JSON.stringify(result));
        } catch (error) {
          res.writeHead(400);
          res.end('Invalid transformation');
        }
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_8() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/validate', (req, res) => {
    const { data, validationRules } = req.body;
    const errors = [];
    
    try {
      for (const rule of validationRules) {
        const fieldName = rule.field;
        const condition = rule.condition;
        const errorMessage = rule.message;
        
        // ruleid: javascript-new-function-detected
        const validator = new Function('data', `
          return ${condition};
        `);
        
        if (!validator(data)) {
          errors.push({ field: fieldName, message: errorMessage });
        }
      }
      
      res.json({ valid: errors.length === 0, errors });
    } catch (error) {
      res.status(400).json({ error: 'Invalid validation rules' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_9() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    if (parsedUrl.pathname === '/render') {
      const template = parsedUrl.query.template || '';
      const context = { user: { name: 'John', role: 'user' } };
      
      try {
        // ruleid: javascript-new-function-detected
        const renderer = new Function('context', `
          with(context) {
            return \`${template}\`;
          }
        `);
        
        const rendered = renderer(context);
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(rendered);
      } catch (error) {
        res.writeHead(500);
        res.end('Rendering error');
      }
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_10() {
  const express = require('express');
  const app = express();
  
  app.get('/dynamic-component', (req, res) => {
    const componentCode = req.query.component || '';
    
    try {
      // ruleid: javascript-new-function-detected
      const createComponent = new Function('props', `
        return {
          render: function() {
            ${componentCode}
          }
        };
      `);
      
      const component = createComponent({ user: 'Guest' });
      res.json({ success: true });
    } catch (error) {
      res.status(400).json({ error: 'Invalid component code' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_11() {
  const http = require('http');
  
  http.createServer((req, res) => {
    if (req.url.startsWith('/api/query')) {
      const urlParts = req.url.split('?');
      const queryString = urlParts[1] || '';
      const params = new URLSearchParams(queryString);
      const queryLogic = params.get('query') || '';
      
      const data = [
        { id: 1, name: 'Alice', age: 30 },
        { id: 2, name: 'Bob', age: 25 },
        { id: 3, name: 'Charlie', age: 35 }
      ];
      
      try {
        // ruleid: javascript-new-function-detected
        const queryFunction = new Function('data', `
          return data.filter(item => ${queryLogic});
        `);
        
        const result = queryFunction(data);
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify(result));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid query');
      }
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_12() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/custom-sort', (req, res) => {
    const { items, sortLogic } = req.body;
    
    if (!Array.isArray(items)) {
      return res.status(400).json({ error: 'Items must be an array' });
    }
    
    try {
      // ruleid: javascript-new-function-detected
      const sorter = new Function('a', 'b', sortLogic);
      const sortedItems = [...items].sort(sorter);
      
      res.json({ sorted: sortedItems });
    } catch (error) {
      res.status(400).json({ error: 'Invalid sort logic' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_13() {
  const http = require('http');
  const querystring = require('querystring');
  
  http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/format-data') {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        const data = querystring.parse(body);
        const inputData = JSON.parse(data.input || '{}');
        const formatCode = data.format || '';
        
        try {
          // ruleid: javascript-new-function-detected
          const formatter = new Function('data', `
            const result = {};
            ${formatCode}
            return result;
          `);
          
          const formattedData = formatter(inputData);
          res.writeHead(200, {'Content-Type': 'application/json'});
          res.end(JSON.stringify(formattedData));
        } catch (error) {
          res.writeHead(400);
          res.end('Invalid format code');
        }
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_14() {
  const express = require('express');
  const app = express();
  
  app.get('/dynamic-html', (req, res) => {
    const htmlTemplate = req.query.template || '';
    const data = {
      title: 'Dynamic Page',
      content: 'This is dynamic content',
      user: { name: 'User', role: 'guest' }
    };
    
    try {
      // ruleid: javascript-new-function-detected
      const htmlGenerator = new Function('data', `
        return \`
          <!DOCTYPE html>
          <html>
            <head>
              <title>${data.title}</title>
            </head>
            <body>
              ${htmlTemplate}
            </body>
          </html>
        \`;
      `);
      
      const html = htmlGenerator(data);
      res.send(html);
    } catch (error) {
      res.status(400).send('Invalid template');
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_15() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    if (parsedUrl.pathname === '/execute-math') {
      const expression = parsedUrl.query.expr || '';
      
      try {
        // ruleid: javascript-new-function-detected
        const mathFunction = new Function(`return ${expression};`);
        const result = mathFunction();
        
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({ result }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid mathematical expression');
      }
    }
  }).listen(3000);
}
// {/fact}

// ====== TRUE NEGATIVES (SECURE CODE) ======

// {fact rule=code-injection@v1.0 defects=0}
function good_case_1() {
  const express = require('express');
  const app = express();
  
  app.get('/execute', (req, res) => {
    const userCode = req.query.code;
    // Instead of using new Function, use a whitelist approach
    // ok: javascript-new-function-detected
    const allowedCommands = {
      'add': (a, b) => a + b,
      'subtract': (a, b) => a - b,
      'multiply': (a, b) => a * b,
      'divide': (a, b) => a / b
    };
    
    const parts = userCode.split(':');
    if (parts.length === 3 && allowedCommands[parts[0]]) {
      const result = allowedCommands[parts[0]](Number(parts[1]), Number(parts[2]));
      res.send(`Result: ${result}`);
    } else {
      res.status(400).send('Invalid command');
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_2() {
  const http = require('http');
  
  http.createServer((req, res) => {
    if (req.url.startsWith('/api/execute')) {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        const data = JSON.parse(body);
        // ok: javascript-new-function-detected
        // Use a predefined function instead of dynamic execution
        const executeOperation = (operation, values) => {
          switch (operation) {
            case 'sum':
              return values.reduce((a, b) => a + b, 0);
            case 'average':
              return values.reduce((a, b) => a + b, 0) / values.length;
            default:
              throw new Error('Unsupported operation');
          }
        };
        
        try {
          const result = executeOperation(data.operation, data.values);
          res.writeHead(200, {'Content-Type': 'application/json'});
          res.end(JSON.stringify({ result }));
        } catch (error) {
          res.writeHead(400);
          res.end('Invalid operation');
        }
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_3() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/calculate', (req, res) => {
    const formula = req.body.formula;
    
    // ok: javascript-new-function-detected
    // Use a safe math expression evaluator instead of new Function
    const safeEval = (expr) => {
      // This is a simplified example - in production, use a proper math expression library
      const sanitized = expr.replace(/[^0-9+\-*/().]/g, '');
      return Function(`"use strict"; return (${sanitized})`)();
    };
    
    try {
      // Using a safer approach with input sanitization
      const result = safeEval(formula);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: 'Invalid formula' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_4() {
  const http = require('http');
  const url = require('url');
  const handlebars = require('handlebars'); // Assuming handlebars is installed
  
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    if (parsedUrl.pathname === '/template') {
      const templateId = parsedUrl.query.id;
      const data = { name: 'User', items: ['Item 1', 'Item 2'] };
      
      // ok: javascript-new-function-detected
      // Use a template engine instead of dynamic function creation
      const templates = {
        'welcome': 'Welcome, {{name}}!',
        'list': '<ul>{{#each items}}<li>{{this}}</li>{{/each}}</ul>',
        'default': 'Hello World'
      };
      
      const templateSource = templates[templateId] || templates.default;
      const template = handlebars.compile(templateSource);
      const output = template(data);
      
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end(output);
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_5() {
  const express = require('express');
  const app = express();
  
  app.get('/filter', (req, res) => {
    const items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const filterType = req.query.type;
    
    // ok: javascript-new-function-detected
    // Use a predefined set of filter functions instead of dynamic evaluation
    const filters = {
      'even': item => item % 2 === 0,
      'odd': item => item % 2 !== 0,
      'greater-than-5': item => item > 5,
      'less-than-5': item => item < 5
    };
    
    if (filters[filterType]) {
      const filteredItems = items.filter(filters[filterType]);
      res.json(filteredItems);
    } else {
      res.status(400).json({ error: 'Invalid filter type' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_6() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  // Predefined set of allowed operations
  const operations = {
    add: (a, b) => a + b,
    subtract: (a, b) => a - b,
    multiply: (a, b) => a * b,
    divide: (a, b) => b !== 0 ? a / b : null
  };
  
  app.post('/execute-operation', (req, res) => {
    const { operation, parameters } = req.body;
    
    // ok: javascript-new-function-detected
    // Use a predefined operation instead of dynamic function creation
    if (operations[operation] && Array.isArray(parameters)) {
      try {
        const result = operations[operation](...parameters);
        res.json({ success: true, result });
      } catch (error) {
        res.status(400).json({ success: false, error: 'Invalid parameters' });
      }
    } else {
      res.status(400).json({ success: false, error: 'Invalid operation' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_7() {
  const http = require('http');
  const querystring = require('querystring');
  
  http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/transform') {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        const data = querystring.parse(body);
        const inputArray = JSON.parse(data.array || '[]');
        const transformType = data.transform || 'identity';
        
        // ok: javascript-new-function-detected
        // Use predefined transformations instead of dynamic function creation
        const transformations = {
          'identity': item => item,
          'double': item => item * 2,
          'square': item => item * item,
          'negate': item => -item,
          'toString': item => String(item)
        };
        
        if (transformations[transformType]) {
          const result = inputArray.map(transformations[transformType]);
          res.writeHead(200, {'Content-Type': 'application/json'});
          res.end(JSON.stringify(result));
        } else {
          res.writeHead(400);
          res.end('Invalid transformation type');
        }
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_8() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  // Predefined validation functions
  const validationFunctions = {
    required: (value) => value !== undefined && value !== null && value !== '',
    minLength: (value, min) => String(value).length >= min,
    maxLength: (value, max) => String(value).length <= max,
    isEmail: (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
    isNumber: (value) => !isNaN(Number(value)),
    min: (value, min) => Number(value) >= min,
    max: (value, max) => Number(value) <= max
  };
  
  app.post('/validate', (req, res) => {
    const { data, validationRules } = req.body;
    const errors = [];
    
    // ok: javascript-new-function-detected
    // Use predefined validation functions instead of dynamic evaluation
    try {
      for (const rule of validationRules) {
        const fieldName = rule.field;
        const validationType = rule.type;
        const params = rule.params;
        const errorMessage = rule.message;
        
        if (validationFunctions[validationType]) {
          const isValid = validationFunctions[validationType](data[fieldName], ...(params || []));
          if (!isValid) {
            errors.push({ field: fieldName, message: errorMessage });
          }
        } else {
          errors.push({ field: fieldName, message: 'Unknown validation type' });
        }
      }
      
      res.json({ valid: errors.length === 0, errors });
    } catch (error) {
      res.status(400).json({ error: 'Invalid validation rules' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_9() {
  const http = require('http');
  const url = require('url');
  const handlebars = require('handlebars'); // Assuming handlebars is installed
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    if (parsedUrl.pathname === '/render') {
      const templateId = parsedUrl.query.id || 'default';
      const context = { user: { name: 'John', role: 'user' } };
      
      // ok: javascript-new-function-detected
      // Use a template engine instead of dynamic function creation
      const templates = {
        'greeting': 'Hello {{user.name}}!',
        'profile': '<div>Name: {{user.name}}<br>Role: {{user.role}}</div>',
        'default': '<p>Welcome to our site!</p>'
      };
      
      try {
        const templateSource = templates[templateId] || templates.default;
        const template = handlebars.compile(templateSource);
        const rendered = template(context);
        
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(rendered);
      } catch (error) {
        res.writeHead(500);
        res.end('Rendering error');
      }
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_10() {
  const express = require('express');
  const app = express();
  
  // Predefined component templates
  const componentTemplates = {
    'button': (props) => `<button class="${props.className || ''}">${props.label || 'Button'}</button>`,
    'card': (props) => `<div class="card">
      <div class="card-header">${props.title || 'Title'}</div>
      <div class="card-body">${props.content || ''}</div>
    </div>`,
    'alert': (props) => `<div class="alert alert-${props.type || 'info'}">${props.message || ''}</div>`
  };
  
  app.get('/component', (req, res) => {
    const componentType = req.query.type || 'button';
    const props = {
      label: req.query.label,
      className: req.query.className,
      title: req.query.title,
      content: req.query.content,
      type: req.query.alertType,
      message: req.query.message
    };
    
    // ok: javascript-new-function-detected
    // Use predefined component templates instead of dynamic function creation
    if (componentTemplates[componentType]) {
      const html = componentTemplates[componentType](props);
      res.send(html);
    } else {
      res.status(400).send('Unknown component type');
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_11() {
  const http = require('http');
  
  http.createServer((req, res) => {
    if (req.url.startsWith('/api/query')) {
      const urlParts = req.url.split('?');
      const queryString = urlParts[1] || '';
      const params = new URLSearchParams(queryString);
      const queryType = params.get('type') || '';
      const value = params.get('value') || '';
      
      const data = [
        { id: 1, name: 'Alice', age: 30 },
        { id: 2, name: 'Bob', age: 25 },
        { id: 3, name: 'Charlie', age: 35 }
      ];
      
      // ok: javascript-new-function-detected
      // Use predefined query functions instead of dynamic evaluation
      const queryFunctions = {
        'byName': (data, value) => data.filter(item => item.name === value),
        'byAge': (data, value) => data.filter(item => item.age === parseInt(value)),
        'olderThan': (data, value) => data.filter(item => item.age > parseInt(value)),
        'youngerThan': (data, value) => data.filter(item => item.age < parseInt(value))
      };
      
      if (queryFunctions[queryType]) {
        const result = queryFunctions[queryType](data, value);
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify(result));
      } else {
        res.writeHead(400);
        res.end('Invalid query type');
      }
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_12() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/sort', (req, res) => {
    const { items, sortBy, order } = req.body;
    
    if (!Array.isArray(items)) {
      return res.status(400).json({ error: 'Items must be an array' });
    }
    
    // ok: javascript-new-function-detected
    // Use predefined sort functions instead of dynamic evaluation
    const sortFunctions = {
      'numeric-asc': (a, b) => a - b,
      'numeric-desc': (a, b) => b - a,
      'string-asc': (a, b) => String(a).localeCompare(String(b)),
      'string-desc': (a, b) => String(b).localeCompare(String(a)),
      'date-asc': (a, b) => new Date(a) - new Date(b),
      'date-desc': (a, b) => new Date(b) - new Date(a)
    };
    
    const sortKey = `${sortBy}-${order}`;
    
    if (sortFunctions[sortKey]) {
      const sortedItems = [...items].sort(sortFunctions[sortKey]);
      res.json({ sorted: sortedItems });
    } else {
      res.status(400).json({ error: 'Invalid sort parameters' });
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_13() {
  const http = require('http');
  const querystring = require('querystring');
  
  http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/format-data') {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        const data = querystring.parse(body);
        const inputData = JSON.parse(data.input || '{}');
        const formatType = data.format || 'default';
        
        // ok: javascript-new-function-detected
        // Use predefined formatters instead of dynamic function creation
        const formatters = {
          'uppercase': (data) => {
            const result = {};
            for (const key in data) {
              result[key] = typeof data[key] === 'string' ? data[key].toUpperCase() : data[key];
            }
            return result;
          },
          'lowercase': (data) => {
            const result = {};
            for (const key in data) {
              result[key] = typeof data[key] === 'string' ? data[key].toLowerCase() : data[key];
            }
            return result;
          },
          'default': (data) => data
        };
        
        if (formatters[formatType]) {
          const formattedData = formatters[formatType](inputData);
          res.writeHead(200, {'Content-Type': 'application/json'});
          res.end(JSON.stringify(formattedData));
        } else {
          res.writeHead(400);
          res.end('Invalid format type');
        }
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_14() {
  const express = require('express');
  const app = express();
  const handlebars = require('handlebars'); // Assuming handlebars is installed
  
  // Predefined HTML templates
  const htmlTemplates = {
    'simple': `
      <!DOCTYPE html>
      <html>
        <head>
          <title>{{title}}</title>
        </head>
        <body>
          <h1>{{title}}</h1>
          <p>{{content}}</p>
        </body>
      </html>
    `,
    'dashboard': `
      <!DOCTYPE html>
      <html>
        <head>
          <title>{{title}}</title>
        </head>
        <body>
          <header>
            <h1>Welcome, {{user.name}}</h1>
          </header>
          <main>
            <h2>{{title}}</h2>
            <div>{{content}}</div>
          </main>
          <footer>
            <p>User role: {{user.role}}</p>
          </footer>
        </body>
      </html>
    `
  };
  
  app.get('/html', (req, res) => {
    const templateType = req.query.type || 'simple';
    const data = {
      title: req.query.title || 'Default Title',
      content: req.query.content || 'Default content',
      user: { name: req.query.name || 'User', role: req.query.role || 'guest' }
    };
    
    // ok: javascript-new-function-detected
    // Use a template engine instead of dynamic function creation
    if (htmlTemplates[templateType]) {
      const template = handlebars.compile(htmlTemplates[templateType]);
      const html = template(data);
      res.send(html);
    } else {
      res.status(400).send('Unknown template type');
    }
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_15() {
  const http = require('http');
  const url = require('url');
  
  // Safe math expression evaluator
  const mathOperations = {
    '+': (a, b) => a + b,
    '-': (a, b) => a - b,
    '*': (a, b) => a * b,
    '/': (a, b) => b !== 0 ? a / b : null,
    '^': (a, b) => Math.pow(a, b),
    'sqrt': (a) => Math.sqrt(a),
    'sin': (a) => Math.sin(a),
    'cos': (a) => Math.cos(a),
    'tan': (a) => Math.tan(a)
  };
  
  // Simple expression parser for basic operations
  const evaluateMathExpression = (expr) => {
    // This is a simplified parser for demonstration
    // In a real application, use a proper math expression parser
    const tokens = expr.match(/(\d+\.?\d*|\+|\-|\*|\/|\^|sqrt|sin|cos|tan|\(|\))/g) || [];
    
    // Very basic implementation - in real code, use a proper parser
    // This is just to demonstrate the concept of safe evaluation
    let result = 0;
    let currentOp = '+';
    
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      
      if (['+', '-', '*', '/'].includes(token)) {
        currentOp = token;
      } else {
        const num = parseFloat(token);
        if (!isNaN(num)) {
          result = mathOperations[currentOp](result, num);
        }
      }
    }
    
    return result;
  };
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    if (parsedUrl.pathname === '/calculate') {
      const expression = parsedUrl.query.expr || '';
      
      try {
        // ok: javascript-new-function-detected
        // Use a safe math evaluator instead of new Function
        const result = evaluateMathExpression(expression);
        
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({ result }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid mathematical expression');
      }
    }
  }).listen(3000);
}
// {/fact}