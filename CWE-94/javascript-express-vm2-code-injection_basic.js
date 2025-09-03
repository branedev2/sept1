const express = require('express');
const { VM } = require('vm2');
const bodyParser = require('body-parser');
const sanitize = require('sanitize-html');
const validator = require('validator');
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  app.get('/execute', (req, res) => {
    const userCode = req.query.code;
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(userCode);
      res.send({ result });
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  app.post('/evaluate', (req, res) => {
    const userScript = req.body.script;
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const output = vm.run(`
        function calculate() {
          return ${userScript};
        }
        calculate();
      `);
      res.json({ output });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  app.get('/calculator', (req, res) => {
    const expression = req.query.expr;
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(`(function() { return ${expression}; })()`);
      res.send(`Result: ${result}`);
    } catch (error) {
      res.send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  app.post('/template', (req, res) => {
    const template = req.body.template;
    const data = req.body.data;
    const vm = new VM({ sandbox: { data } });
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const rendered = vm.run(`
        function render(template, data) {
          return \`${template}\`;
        }
        render(template, data);
      `);
      res.send(rendered);
    } catch (error) {
      res.status(500).send(error.message);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  app.get('/dynamic-function', (req, res) => {
    const userFunction = req.query.func;
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(`(${userFunction})()`);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  app.post('/execute-with-context', (req, res) => {
    const code = req.body.code;
    const context = { x: 10, y: 20 };
    const vm = new VM({ sandbox: context });
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(code);
      res.json({ result });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  app.get('/eval-math', (req, res) => {
    const formula = req.query.formula;
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(`
        const math = {
          evaluate: function(formula) {
            return eval(formula);
          }
        };
        math.evaluate("${formula}");
      `);
      res.send(`Result: ${result}`);
    } catch (error) {
      res.status(400).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  app.post('/transform-data', (req, res) => {
    const transformation = req.body.transformation;
    const data = req.body.data;
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const transformed = vm.run(`
        const transform = ${transformation};
        transform(${JSON.stringify(data)});
      `);
      res.json({ transformed });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  app.get('/custom-filter', (req, res) => {
    const filterCode = req.query.filter;
    const items = [1, 2, 3, 4, 5];
    const vm = new VM({ sandbox: { items } });
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const filtered = vm.run(`items.filter(item => ${filterCode})`);
      res.json({ filtered });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  app.post('/dynamic-template', (req, res) => {
    const templateString = req.body.template;
    const values = req.body.values || {};
    const vm = new VM({ sandbox: { values } });
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(`
        function template(str) {
          return \`${templateString}\`;
        }
        template();
      `);
      res.send(result);
    } catch (error) {
      res.status(500).send(error.message);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  app.get('/execute-with-headers', (req, res) => {
    const script = req.headers['x-custom-script'];
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(script);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  app.post('/execute-with-cookie', (req, res) => {
    const cookieValue = req.cookies.userScript;
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(cookieValue);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  app.get('/conditional-execution', (req, res) => {
    const userInput = req.query.input;
    const condition = req.query.condition;
    const vm = new VM({ sandbox: { input: userInput } });
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(`
        let output;
        if (${condition}) {
          output = input.toUpperCase();
        } else {
          output = input.toLowerCase();
        }
        output;
      `);
      res.send(result);
    } catch (error) {
      res.status(400).send(error.message);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  app.post('/dynamic-import', (req, res) => {
    const moduleName = req.body.module;
    const vm = new VM();
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const result = vm.run(`
        const dynamicImport = (name) => {
          return require(name);
        };
        dynamicImport('${moduleName}');
      `);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  app.get('/format-string', (req, res) => {
    const format = req.query.format;
    const data = { name: 'John', age: 30 };
    const vm = new VM({ sandbox: { data } });
    
    try {
      // ruleid: javascript-express-vm2-code-injection
      const formatted = vm.run(`
        function formatString(format, data) {
          return \`${format}\`;
        }
        formatString('${format}', data);
      `);
      res.send(formatted);
    } catch (error) {
      res.status(400).send(error.message);
    }
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  app.get('/execute-safe', (req, res) => {
    const userCode = req.query.code;
    
    // Whitelist of allowed expressions
    const allowedExpressions = [
      '1 + 1',
      'Math.sqrt(16)',
      '2 * 3'
    ];
    
    if (allowedExpressions.includes(userCode)) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(userCode);
        res.send({ result });
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    } else {
      res.status(400).send({ error: 'Invalid expression' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  app.post('/evaluate-safe', (req, res) => {
    const userScript = req.body.script;
    
    // Validate input is a mathematical expression using regex
    if (/^[\d\s\+\-\*\/\(\)\.]+$/.test(userScript)) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const output = vm.run(`
          function calculate() {
            return ${userScript};
          }
          calculate();
        `);
        res.json({ output });
      } catch (err) {
        res.status(400).json({ error: err.message });
      }
    } else {
      res.status(400).json({ error: 'Invalid mathematical expression' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  app.get('/calculator-safe', (req, res) => {
    const expression = req.query.expr;
    
    // Sanitize and validate the expression
    const sanitizedExpr = expression.replace(/[^0-9+\-*/().]/g, '');
    
    if (sanitizedExpr === expression) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(`(function() { return ${sanitizedExpr}; })()`);
        res.send(`Result: ${result}`);
      } catch (error) {
        res.send(`Error: ${error.message}`);
      }
    } else {
      res.status(400).send('Invalid expression');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  app.post('/template-safe', (req, res) => {
    const template = req.body.template;
    const data = req.body.data;
    
    // Use a predefined template instead of user input
    const predefinedTemplates = {
      'greeting': 'Hello, ${data.name}!',
      'welcome': 'Welcome to our service, ${data.name}.',
      'farewell': 'Goodbye, ${data.name}. See you soon!'
    };
    
    const selectedTemplate = predefinedTemplates[template];
    
    if (selectedTemplate) {
      const vm = new VM({ sandbox: { data } });
      try {
        // ok: javascript-express-vm2-code-injection
        const rendered = vm.run(`
          function render(template, data) {
            return \`${selectedTemplate}\`;
          }
          render(template, data);
        `);
        res.send(rendered);
      } catch (error) {
        res.status(500).send(error.message);
      }
    } else {
      res.status(400).send('Invalid template selection');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  app.get('/dynamic-function-safe', (req, res) => {
    // Predefined functions instead of user input
    const functions = {
      'square': '(x) => x * x',
      'cube': '(x) => x * x * x',
      'double': '(x) => x * 2'
    };
    
    const funcName = req.query.func;
    const value = parseInt(req.query.value, 10);
    
    if (functions[funcName] && !isNaN(value)) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(`(${functions[funcName]})(${value})`);
        res.json({ result });
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'Invalid function or value' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  app.post('/execute-with-context-safe', (req, res) => {
    // Use a hardcoded script instead of user input
    const code = 'x + y';
    const context = { x: parseInt(req.body.x, 10), y: parseInt(req.body.y, 10) };
    
    if (!isNaN(context.x) && !isNaN(context.y)) {
      const vm = new VM({ sandbox: context });
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(code);
        res.json({ result });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'Invalid input values' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  app.get('/eval-math-safe', (req, res) => {
    const formula = req.query.formula;
    
    // Validate formula is a simple arithmetic expression
    if (validator.isNumeric(formula.replace(/[\+\-\*\/\(\)\s\.]/g, ''))) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(`
          const math = {
            evaluate: function(formula) {
              // Using Function instead of eval for better safety
              return new Function('return ' + formula)();
            }
          };
          math.evaluate("${formula.replace(/"/g, '\\"')}");
        `);
        res.send(`Result: ${result}`);
      } catch (error) {
        res.status(400).send(`Error: ${error.message}`);
      }
    } else {
      res.status(400).send('Invalid formula');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  app.post('/transform-data-safe', (req, res) => {
    const transformationType = req.body.type;
    const data = req.body.data;
    
    // Predefined transformations instead of user code
    const transformations = {
      'uppercase': 'function(data) { return data.map(item => typeof item === "string" ? item.toUpperCase() : item); }',
      'double': 'function(data) { return data.map(item => typeof item === "number" ? item * 2 : item); }',
      'reverse': 'function(data) { return [...data].reverse(); }'
    };
    
    if (transformations[transformationType] && Array.isArray(data)) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const transformed = vm.run(`
          const transform = ${transformations[transformationType]};
          transform(${JSON.stringify(data)});
        `);
        res.json({ transformed });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'Invalid transformation type or data' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  app.get('/custom-filter-safe', (req, res) => {
    const filterType = req.query.type;
    const items = [1, 2, 3, 4, 5];
    
    // Predefined filter functions
    const filters = {
      'even': 'item % 2 === 0',
      'odd': 'item % 2 !== 0',
      'greater-than-3': 'item > 3'
    };
    
    if (filters[filterType]) {
      const vm = new VM({ sandbox: { items } });
      try {
        // ok: javascript-express-vm2-code-injection
        const filtered = vm.run(`items.filter(item => ${filters[filterType]})`);
        res.json({ filtered });
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'Invalid filter type' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  app.post('/dynamic-template-safe', (req, res) => {
    const templateId = req.body.templateId;
    const values = req.body.values || {};
    
    // Predefined templates
    const templates = {
      'greeting': 'Hello, ${values.name}!',
      'invoice': 'Invoice #${values.id}: $${values.amount}',
      'notification': '${values.count} new messages'
    };
    
    const templateString = templates[templateId];
    
    if (templateString) {
      const vm = new VM({ sandbox: { values } });
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(`
          function template(str) {
            return \`${templateString}\`;
          }
          template();
        `);
        res.send(result);
      } catch (error) {
        res.status(500).send(error.message);
      }
    } else {
      res.status(400).send('Invalid template ID');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  app.get('/execute-with-headers-safe', (req, res) => {
    // Don't use headers directly, use a whitelist approach
    const scriptType = req.headers['x-script-type'];
    
    const safeScripts = {
      'hello': 'console.log("Hello, World!"); "Hello, World!"',
      'time': 'new Date().toISOString()',
      'random': 'Math.random()'
    };
    
    if (safeScripts[scriptType]) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(safeScripts[scriptType]);
        res.json({ result });
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'Invalid script type' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  app.post('/execute-with-cookie-safe', (req, res) => {
    // Instead of using cookie value directly, use it as a key to select predefined script
    const scriptId = req.cookies.scriptId;
    
    const allowedScripts = {
      'script1': '1 + 1',
      'script2': 'Math.PI.toFixed(5)',
      'script3': '"Hello".repeat(3)'
    };
    
    if (allowedScripts[scriptId]) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(allowedScripts[scriptId]);
        res.json({ result });
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'Invalid script ID' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  app.get('/conditional-execution-safe', (req, res) => {
    const userInput = req.query.input;
    const conditionType = req.query.condition;
    
    // Sanitize user input
    const sanitizedInput = sanitize(userInput, {
      allowedTags: [],
      allowedAttributes: {}
    });
    
    // Predefined conditions
    const conditions = {
      'length': 'input.length > 5',
      'uppercase': 'input.toUpperCase() === input',
      'hasNumber': '/\\d/.test(input)'
    };
    
    if (conditions[conditionType]) {
      const vm = new VM({ sandbox: { input: sanitizedInput } });
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(`
          let output;
          if (${conditions[conditionType]}) {
            output = input.toUpperCase();
          } else {
            output = input.toLowerCase();
          }
          output;
        `);
        res.send(result);
      } catch (error) {
        res.status(400).send(error.message);
      }
    } else {
      res.status(400).send('Invalid condition type');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  app.post('/dynamic-import-safe', (req, res) => {
    const moduleId = req.body.moduleId;
    
    // Whitelist of allowed modules
    const allowedModules = {
      'math': 'Math',
      'json': 'JSON',
      'date': 'Date'
    };
    
    if (allowedModules[moduleId]) {
      const vm = new VM();
      try {
        // ok: javascript-express-vm2-code-injection
        const result = vm.run(`
          const getBuiltin = (name) => {
            return global[name];
          };
          getBuiltin('${allowedModules[moduleId]}');
        `);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'Invalid module ID' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  app.get('/format-string-safe', (req, res) => {
    const formatId = req.query.format;
    const data = { name: sanitize(req.query.name || 'Guest'), age: parseInt(req.query.age, 10) || 0 };
    
    // Predefined format templates
    const formats = {
      'simple': 'Name: ${data.name}',
      'detailed': 'Name: ${data.name}, Age: ${data.age}',
      'greeting': 'Hello ${data.name}!'
    };
    
    if (formats[formatId]) {
      const vm = new VM({ sandbox: { data } });
      try {
        // ok: javascript-express-vm2-code-injection
        const formatted = vm.run(`
          function formatString(format, data) {
            return \`${formats[formatId]}\`;
          }
          formatString('format', data);
        `);
        res.send(formatted);
      } catch (error) {
        res.status(400).send(error.message);
      }
    } else {
      res.status(400).send('Invalid format ID');
    }
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});