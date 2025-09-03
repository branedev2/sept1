const express = require('express');
const app = express();
const { NodeVM } = require('vm2');
const sandbox = new NodeVM();
const vm = require('vm');
const { VM } = require('vm2');
const safeEval = require('safe-eval');

// Configure express to parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  app.get('/execute-code', (req, res) => {
    const userCode = req.query.code;
    const sandbox = new NodeVM();
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = sandbox.run(userCode);
      res.send({ result });
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  app.post('/evaluate-expression', (req, res) => {
    const userExpression = req.body.expression;
    const sandbox = new VM();
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = sandbox.run(userExpression);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  app.get('/calculate', (req, res) => {
    const formula = req.query.formula;
    const context = { Math };
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = vm.runInNewContext(formula, context);
      res.send(`Result: ${result}`);
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  app.post('/run-script', (req, res) => {
    const userScript = req.body.script;
    const sandbox = new NodeVM({
      console: 'inherit',
      sandbox: { customData: { value: 42 } }
    });
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const output = sandbox.run(userScript);
      res.json({ output });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  app.get('/execute', (req, res) => {
    const code = req.query.code;
    const sandbox = new VM();
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = sandbox.run(`return (${code})`);
      res.send({ result });
    } catch (error) {
      res.status(400).send({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  app.post('/dynamic-function', (req, res) => {
    const userFunction = req.body.function;
    const sandbox = new NodeVM();
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = sandbox.run(`module.exports = function() { ${userFunction} }`);
      res.json({ success: true, result: result() });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  app.get('/evaluate-math', (req, res) => {
    const expression = req.query.expression;
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = safeEval(expression);
      res.send(`Result: ${result}`);
    } catch (error) {
      res.status(400).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  app.post('/run-template', (req, res) => {
    const template = req.body.template;
    const sandbox = new VM();
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const compiledTemplate = sandbox.run(`
        module.exports = function(data) {
          return \`${template}\`;
        }
      `);
      
      const result = compiledTemplate({ user: 'John' });
      res.json({ result });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  app.get('/execute-with-timeout', (req, res) => {
    const userCode = req.query.code;
    const sandbox = new NodeVM();
    
    setTimeout(() => {
      try {
        // ruleid: javascript-sandbox-code-injection
        const result = sandbox.run(userCode);
        res.json({ result });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    }, 100);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  app.post('/run-with-context', (req, res) => {
    const userCode = req.body.code;
    const context = { 
      name: req.body.name || 'Anonymous',
      timestamp: Date.now()
    };
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = vm.runInNewContext(userCode, context);
      res.json({ result, context });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  app.get('/calculate-formula', (req, res) => {
    const formula = req.query.formula;
    let processedFormula = formula.replace(/\s+/g, '');
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = vm.runInNewContext(processedFormula, { Math });
      res.send(`Result: ${result}`);
    } catch (error) {
      res.status(400).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  app.post('/dynamic-import', (req, res) => {
    const moduleCode = req.body.module;
    const sandbox = new NodeVM({
      require: {
        external: true
      }
    });
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const module = sandbox.run(`module.exports = ${moduleCode}`);
      res.json({ success: true, module });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  app.get('/run-from-header', (req, res) => {
    const userCode = req.headers['x-custom-code'];
    const sandbox = new VM();
    
    if (!userCode) {
      return res.status(400).send('Missing code header');
    }
    
    try {
      // ruleid: javascript-sandbox-code-injection
      const result = sandbox.run(userCode);
      res.json({ result });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  app.post('/execute-batch', (req, res) => {
    const scripts = req.body.scripts || [];
    const sandbox = new NodeVM();
    const results = [];
    
    for (const script of scripts) {
      try {
        // ruleid: javascript-sandbox-code-injection
        const result = sandbox.run(script);
        results.push({ success: true, result });
      } catch (error) {
        results.push({ success: false, error: error.message });
      }
    }
    
    res.json({ results });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  app.get('/conditional-execution', (req, res) => {
    const userCode = req.query.code;
    const shouldExecute = req.query.execute === 'true';
    const sandbox = new VM();
    
    if (shouldExecute && userCode) {
      try {
        // ruleid: javascript-sandbox-code-injection
        const result = sandbox.run(userCode);
        res.json({ executed: true, result });
      } catch (error) {
        res.status(500).json({ executed: true, error: error.message });
      }
    } else {
      res.json({ executed: false });
    }
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  app.get('/execute-safe', (req, res) => {
    // Only allow predefined operations
    const allowedOperations = {
      'add': (a, b) => a + b,
      'subtract': (a, b) => a - b,
      'multiply': (a, b) => a * b,
      'divide': (a, b) => a / b
    };
    
    const operation = req.query.operation;
    const a = parseFloat(req.query.a);
    const b = parseFloat(req.query.b);
    
    if (!allowedOperations[operation]) {
      return res.status(400).send('Invalid operation');
    }
    
    if (isNaN(a) || isNaN(b)) {
      return res.status(400).send('Invalid numbers');
    }
    
    // ok: javascript-sandbox-code-injection
    const result = allowedOperations[operation](a, b);
    res.json({ result });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  app.post('/evaluate-safe', (req, res) => {
    // Predefined templates that can be safely executed
    const templates = {
      'greeting': 'Hello, {name}!',
      'welcome': 'Welcome to our platform, {name}!',
      'farewell': 'Goodbye, {name}. See you soon!'
    };
    
    const templateName = req.body.template;
    const name = req.body.name || 'Guest';
    
    if (!templates[templateName]) {
      return res.status(400).json({ error: 'Invalid template' });
    }
    
    // ok: javascript-sandbox-code-injection
    const result = templates[templateName].replace('{name}', name);
    res.json({ result });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  app.get('/calculate-safe', (req, res) => {
    // Use a whitelist of allowed mathematical operations
    const expression = req.query.expression || '';
    
    // Only allow digits, basic operators, and parentheses
    if (!/^[0-9+\-*/(). ]+$/.test(expression)) {
      return res.status(400).send('Invalid expression');
    }
    
    try {
      // ok: javascript-sandbox-code-injection
      // Using Function constructor with restricted context is safer than vm.runInNewContext
      const calculate = new Function('return ' + expression);
      const result = calculate();
      res.send(`Result: ${result}`);
    } catch (error) {
      res.status(400).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  app.post('/run-predefined', (req, res) => {
    const scriptId = req.body.scriptId;
    
    // Predefined scripts that are safe to run
    const safeScripts = {
      'hello': 'module.exports = "Hello, World!";',
      'timestamp': 'module.exports = Date.now();',
      'random': 'module.exports = Math.random();'
    };
    
    if (!safeScripts[scriptId]) {
      return res.status(400).json({ error: 'Invalid script ID' });
    }
    
    const sandbox = new NodeVM();
    
    try {
      // ok: javascript-sandbox-code-injection
      const result = sandbox.run(safeScripts[scriptId]);
      res.json({ result });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  app.get('/static-calculation', (req, res) => {
    // Fixed code that doesn't use user input
    const sandbox = new VM();
    
    try {
      // ok: javascript-sandbox-code-injection
      const result = sandbox.run('2 + 2 * 10');
      res.send({ result });
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  app.post('/validate-json', (req, res) => {
    const userJson = req.body.json;
    
    try {
      // ok: javascript-sandbox-code-injection
      // Using JSON.parse instead of sandbox execution
      const parsed = JSON.parse(userJson);
      res.json({ valid: true, parsed });
    } catch (error) {
      res.status(400).json({ valid: false, error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  app.get('/template-render', (req, res) => {
    const name = req.query.name || 'Guest';
    const age = parseInt(req.query.age) || 0;
    
    // ok: javascript-sandbox-code-injection
    // Using template literals directly instead of sandbox
    const message = `Hello ${name}, you are ${age} years old.`;
    res.send({ message });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  app.post('/process-data', (req, res) => {
    const data = req.body.data || [];
    
    // ok: javascript-sandbox-code-injection
    // Process data directly without sandbox
    const processed = data.map(item => item * 2);
    const sum = processed.reduce((a, b) => a + b, 0);
    
    res.json({ processed, sum });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  app.get('/format-date', (req, res) => {
    const timestamp = parseInt(req.query.timestamp) || Date.now();
    const format = req.query.format || 'short';
    
    // Predefined formats
    const formats = {
      'short': { year: 'numeric', month: 'short', day: 'numeric' },
      'long': { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' },
      'time': { hour: 'numeric', minute: 'numeric', second: 'numeric' }
    };
    
    // ok: javascript-sandbox-code-injection
    // Using built-in date formatting instead of sandbox
    const date = new Date(timestamp);
    const formatted = date.toLocaleDateString('en-US', formats[format] || formats.short);
    
    res.send({ formatted });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  app.post('/filter-data', (req, res) => {
    const items = req.body.items || [];
    const filterField = req.body.field;
    const filterValue = req.body.value;
    
    if (!Array.isArray(items)) {
      return res.status(400).json({ error: 'Items must be an array' });
    }
    
    // ok: javascript-sandbox-code-injection
    // Filtering data directly without sandbox
    const filtered = items.filter(item => 
      item && item[filterField] === filterValue
    );
    
    res.json({ filtered });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  app.get('/generate-report', (req, res) => {
    const reportType = req.query.type;
    const userId = req.query.userId;
    
    // Predefined report generators
    const reportGenerators = {
      'summary': (id) => ({ type: 'summary', userId: id, generated: new Date() }),
      'detailed': (id) => ({ type: 'detailed', userId: id, generated: new Date(), details: ['item1', 'item2'] }),
      'metrics': (id) => ({ type: 'metrics', userId: id, generated: new Date(), metrics: { views: 100, clicks: 50 } })
    };
    
    if (!reportGenerators[reportType]) {
      return res.status(400).json({ error: 'Invalid report type' });
    }
    
    // ok: javascript-sandbox-code-injection
    const report = reportGenerators[reportType](userId);
    res.json(report);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  app.post('/transform-data', (req, res) => {
    const data = req.body.data;
    const transformType = req.body.transform;
    
    // Predefined transformations
    const transformations = {
      'uppercase': (str) => String(str).toUpperCase(),
      'lowercase': (str) => String(str).toLowerCase(),
      'reverse': (str) => String(str).split('').reverse().join(''),
      'trim': (str) => String(str).trim()
    };
    
    if (!transformations[transformType]) {
      return res.status(400).json({ error: 'Invalid transformation' });
    }
    
    // ok: javascript-sandbox-code-injection
    const transformed = transformations[transformType](data);
    res.json({ original: data, transformed });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  app.get('/static-template', (req, res) => {
    const userName = req.query.name || 'Guest';
    const userRole = req.query.role || 'User';
    
    // Static template with interpolation
    const template = `
      <div class="user-card">
        <h2>Welcome, {{name}}!</h2>
        <p>Your role: {{role}}</p>
      </div>
    `;
    
    // ok: javascript-sandbox-code-injection
    // Simple string replacement instead of sandbox evaluation
    const rendered = template
      .replace('{{name}}', userName)
      .replace('{{role}}', userRole);
    
    res.send(rendered);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  app.post('/validate-input', (req, res) => {
    const input = req.body.input || '';
    const validationType = req.body.type || 'text';
    
    // Validation functions
    const validators = {
      'email': (val) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val),
      'phone': (val) => /^\d{10}$/.test(val),
      'zipcode': (val) => /^\d{5}(-\d{4})?$/.test(val),
      'text': (val) => typeof val === 'string' && val.length > 0
    };
    
    if (!validators[validationType]) {
      return res.status(400).json({ error: 'Invalid validation type' });
    }
    
    // ok: javascript-sandbox-code-injection
    const isValid = validators[validationType](input);
    res.json({ input, type: validationType, valid: isValid });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  app.get('/format-currency', (req, res) => {
    const amount = parseFloat(req.query.amount) || 0;
    const currency = req.query.currency || 'USD';
    
    // Supported currencies
    const currencies = {
      'USD': { symbol: '$', locale: 'en-US' },
      'EUR': { symbol: '€', locale: 'de-DE' },
      'GBP': { symbol: '£', locale: 'en-GB' },
      'JPY': { symbol: '¥', locale: 'ja-JP' }
    };
    
    if (!currencies[currency]) {
      return res.status(400).json({ error: 'Unsupported currency' });
    }
    
    // ok: javascript-sandbox-code-injection
    // Using built-in formatting instead of sandbox
    const formatted = new Intl.NumberFormat(currencies[currency].locale, {
      style: 'currency',
      currency: currency
    }).format(amount);
    
    res.json({ amount, currency, formatted });
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});