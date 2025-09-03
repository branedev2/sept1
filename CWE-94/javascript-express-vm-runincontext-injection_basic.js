const vm = require('vm');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const sanitize = require('sanitize-html');
const { URL } = require('url');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// True Positives (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  app.get('/execute-code', (req, res) => {
    const userCode = req.query.code;
    const sandbox = { result: null, console: console };
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    vm.runInContext(userCode, context);
    
    res.send(`Result: ${sandbox.result}`);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  app.post('/evaluate-expression', (req, res) => {
    const userExpression = req.body.expression;
    const sandbox = { x: 1, y: 2 };
    const context = vm.createContext(sandbox);
    
    try {
      // ruleid: javascript-express-vm-runincontext-injection
      const result = vm.runInContext(userExpression, context);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  app.get('/compile-script', (req, res) => {
    const userScript = req.query.script;
    const sandbox = { output: '' };
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    const script = new vm.Script(userScript);
    script.runInContext(context);
    
    res.send(sandbox.output);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  app.post('/run-template', (req, res) => {
    const template = req.body.template;
    const data = req.body.data || {};
    const sandbox = { 
      template: template,
      data: data,
      result: ''
    };
    
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    vm.runInContext(`result = eval("(" + template + ")")(data)`, context);
    
    res.json({ rendered: sandbox.result });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  app.get('/calculate', (req, res) => {
    const formula = req.query.formula;
    const sandbox = { result: 0 };
    const context = vm.createContext(sandbox);
    
    try {
      // ruleid: javascript-express-vm-runincontext-injection
      vm.runInContext(`result = ${formula}`, context);
      res.send(`The result is: ${sandbox.result}`);
    } catch (error) {
      res.status(400).send('Invalid formula');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  app.get('/dynamic-function', (req, res) => {
    const userCode = req.query.code;
    const sandbox = { console: console, output: '' };
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    vm.runInContext(`(function() { ${userCode} })()`, context);
    
    res.send(`Output: ${sandbox.output}`);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  app.post('/execute-with-timeout', (req, res) => {
    const code = req.body.code;
    const timeout = req.body.timeout || 1000;
    const sandbox = { result: null };
    const context = vm.createContext(sandbox);
    
    try {
      // ruleid: javascript-express-vm-runincontext-injection
      vm.runInContext(code, context, { timeout: timeout });
      res.json({ result: sandbox.result });
    } catch (error) {
      res.status(400).json({ error: 'Execution timed out or error occurred' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  app.get('/run-with-headers', (req, res) => {
    const scriptContent = req.headers['x-custom-script'];
    const sandbox = { data: {}, result: null };
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    vm.runInContext(scriptContent, context);
    
    res.json({ result: sandbox.result });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  app.post('/conditional-execution', (req, res) => {
    const userInput = req.body.input;
    const condition = req.body.condition;
    const sandbox = { input: userInput, output: null };
    const context = vm.createContext(sandbox);
    
    if (condition === 'evaluate') {
      // ruleid: javascript-express-vm-runincontext-injection
      vm.runInContext(`output = eval(input)`, context);
    } else {
      sandbox.output = 'Condition not met';
    }
    
    res.json({ output: sandbox.output });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  app.get('/process-url-param', (req, res) => {
    const encodedScript = req.params.script;
    const decodedScript = decodeURIComponent(encodedScript);
    const sandbox = { result: null };
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    vm.runInContext(decodedScript, context);
    
    res.send(`Execution complete. Result: ${sandbox.result}`);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  app.post('/compile-and-run', (req, res) => {
    const userCode = req.body.code;
    const filename = req.body.filename || 'script.js';
    const sandbox = { console: console, output: '' };
    
    try {
      const script = new vm.Script(userCode, { filename });
      const context = vm.createContext(sandbox);
      
      // ruleid: javascript-express-vm-runincontext-injection
      script.runInContext(context);
      
      res.json({ output: sandbox.output });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  app.get('/template-engine', (req, res) => {
    const templateString = req.query.template;
    const data = { user: req.query.user || 'Guest' };
    const sandbox = { template: templateString, data: data, result: '' };
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    vm.runInContext(`
      result = template.replace(/\\${([^}]+)}/g, (_, expr) => {
        return eval(expr);
      });
    `, context);
    
    res.send(sandbox.result);
  });
// {/fact}

}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  app.post('/execute-multiple', (req, res) => {
    const scripts = req.body.scripts || [];
    const sandbox = { results: [], console: console };
    const context = vm.createContext(sandbox);
    
    scripts.forEach((script, index) => {
      try {
        // ruleid: javascript-express-vm-runincontext-injection
        vm.runInContext(script, context);
        sandbox.results.push({ index, success: true });
      } catch (error) {
        sandbox.results.push({ index, success: false, error: error.message });
      }
    });
    
    res.json({ results: sandbox.results });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  app.get('/dynamic-import', (req, res) => {
    const moduleName = req.query.module;
    const sandbox = { module: { exports: {} }, require: require, console: console };
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    vm.runInContext(`
      try {
        const imported = require('${moduleName}');
        module.exports = imported;
      } catch (e) {
        console.error(e);
      }
    `, context);
    
    res.json({ module: sandbox.module.exports });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  app.post('/json-transform', (req, res) => {
    const jsonData = req.body.data;
    const transformation = req.body.transform;
    const sandbox = { 
      data: JSON.parse(jsonData), 
      result: null,
      JSON: JSON
    };
    const context = vm.createContext(sandbox);
    
    // ruleid: javascript-express-vm-runincontext-injection
    vm.runInContext(`result = ${transformation}`, context);
    
    res.json({ transformed: sandbox.result });
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  app.get('/execute-safe-code', (req, res) => {
    // Predefined allowed code patterns
    const allowedPatterns = {
      'add': 'result = x + y',
      'subtract': 'result = x - y',
      'multiply': 'result = x * y',
      'divide': 'result = x / y'
    };
    
    const operation = req.query.operation;
    const x = parseInt(req.query.x, 10);
    const y = parseInt(req.query.y, 10);
    
    if (!allowedPatterns[operation]) {
      return res.status(400).send('Invalid operation');
    }
    
    const sandbox = { x, y, result: null };
    const context = vm.createContext(sandbox);
    
    // ok: javascript-express-vm-runincontext-injection
    vm.runInContext(allowedPatterns[operation], context);
    
    res.send(`Result: ${sandbox.result}`);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  app.post('/evaluate-safe-expression', (req, res) => {
    const expression = req.body.expression;
    
    // Validate expression using regex to allow only safe math operations
    if (!/^[\d\s\+\-\*\/\(\)\.]+$/.test(expression)) {
      return res.status(400).json({ error: 'Invalid expression. Only basic math operations allowed.' });
    }
    
    const sandbox = {};
    const context = vm.createContext(sandbox);
    
    try {
      // ok: javascript-express-vm-runincontext-injection
      const result = vm.runInContext(`(${expression})`, context);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  app.get('/compile-safe-script', (req, res) => {
    // Predefined script templates
    const scriptTemplates = {
      'greet': 'output = `Hello, ${name}!`;',
      'farewell': 'output = `Goodbye, ${name}!`;'
    };
    
    const templateName = req.query.template;
    const name = sanitize(req.query.name || 'Guest');
    
    if (!scriptTemplates[templateName]) {
      return res.status(400).send('Unknown template');
    }
    
    const sandbox = { name, output: '' };
    const context = vm.createContext(sandbox);
    
    // ok: javascript-express-vm-runincontext-injection
    const script = new vm.Script(scriptTemplates[templateName]);
    script.runInContext(context);
    
    res.send(sandbox.output);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  app.post('/run-safe-template', (req, res) => {
    // Use a predefined template function instead of evaluating user input
    const templateFunctions = {
      'welcome': (data) => `Welcome, ${data.name}!`,
      'alert': (data) => `Alert: ${data.message}`
    };
    
    const templateName = req.body.template;
    const data = req.body.data || {};
    
    if (!templateFunctions[templateName]) {
      return res.status(400).json({ error: 'Unknown template' });
    }
    
    // ok: javascript-express-vm-runincontext-injection
    const result = templateFunctions[templateName](data);
    
    res.json({ rendered: result });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  app.get('/calculate-safe', (req, res) => {
    const formula = req.query.formula;
    
    // Validate formula to ensure it only contains allowed characters
    if (!/^[\d\s\+\-\*\/\(\)\.]+$/.test(formula)) {
      return res.status(400).send('Invalid formula. Only basic math operations allowed.');
    }
    
    const sandbox = { result: 0 };
    const context = vm.createContext(sandbox);
    
    try {
      // ok: javascript-express-vm-runincontext-injection
      vm.runInContext(`result = ${formula}`, context);
      res.send(`The result is: ${sandbox.result}`);
    } catch (error) {
      res.status(400).send('Error calculating formula');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  app.get('/safe-function-execution', (req, res) => {
    // Predefined functions that can be executed
    const allowedFunctions = {
      'uppercase': 'output = input.toUpperCase();',
      'lowercase': 'output = input.toLowerCase();',
      'reverse': 'output = input.split("").reverse().join("");'
    };
    
    const functionName = req.query.function;
    const input = sanitize(req.query.input || '');
    
    if (!allowedFunctions[functionName]) {
      return res.status(400).send('Unknown function');
    }
    
    const sandbox = { input, output: '' };
    const context = vm.createContext(sandbox);
    
    // ok: javascript-express-vm-runincontext-injection
    vm.runInContext(allowedFunctions[functionName], context);
    
    res.send(`Output: ${sandbox.output}`);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  app.post('/safe-execution-with-timeout', (req, res) => {
    // Predefined code blocks
    const codeBlocks = {
      'fibonacci': 'function fib(n) { return n <= 1 ? n : fib(n-1) + fib(n-2); }; result = fib(10);',
      'factorial': 'function fact(n) { return n <= 1 ? 1 : n * fact(n-1); }; result = fact(5);'
    };
    
    const blockName = req.body.block;
    const timeout = Math.min(req.body.timeout || 1000, 5000); // Cap at 5 seconds
    
    if (!codeBlocks[blockName]) {
      return res.status(400).json({ error: 'Unknown code block' });
    }
    
    const sandbox = { result: null };
    const context = vm.createContext(sandbox);
    
    try {
      // ok: javascript-express-vm-runincontext-injection
      vm.runInContext(codeBlocks[blockName], context, { timeout });
      res.json({ result: sandbox.result });
    } catch (error) {
      res.status(400).json({ error: 'Execution timed out or error occurred' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  app.get('/safe-header-execution', (req, res) => {
    // Use a whitelist of allowed script identifiers
    const allowedScripts = {
      'getTime': 'result = new Date().toISOString();',
      'getRandomNumber': 'result = Math.floor(Math.random() * 100);'
    };
    
    const scriptId = req.headers['x-script-id'];
    
    if (!allowedScripts[scriptId]) {
      return res.status(400).json({ error: 'Invalid script identifier' });
    }
    
    const sandbox = { result: null };
    const context = vm.createContext(sandbox);
    
    // ok: javascript-express-vm-runincontext-injection
    vm.runInContext(allowedScripts[scriptId], context);
    
    res.json({ result: sandbox.result });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  app.post('/safe-conditional-execution', (req, res) => {
    const userInput = sanitize(req.body.input || '');
    const condition = req.body.condition;
    
    // Predefined operations based on condition
    const operations = {
      'uppercase': (input) => input.toUpperCase(),
      'lowercase': (input) => input.toLowerCase(),
      'trim': (input) => input.trim()
    };
    
    let output;
    
    if (operations[condition]) {
      // ok: javascript-express-vm-runincontext-injection
      output = operations[condition](userInput);
    } else {
      output = 'Invalid condition';
    }
    
    res.json({ output });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  app.get('/safe-url-param-processing', (req, res) => {
    // Predefined script templates
    const scriptTemplates = {
      'welcome': 'result = `Welcome, ${user}!`;',
      'goodbye': 'result = `Goodbye, ${user}!`;'
    };
    
    const templateId = req.params.templateId;
    const user = sanitize(req.query.user || 'Guest');
    
    if (!scriptTemplates[templateId]) {
      return res.status(400).send('Unknown template');
    }
    
    const sandbox = { user, result: '' };
    const context = vm.createContext(sandbox);
    
    // ok: javascript-express-vm-runincontext-injection
    vm.runInContext(scriptTemplates[templateId], context);
    
    res.send(sandbox.result);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  app.post('/safe-compile-and-run', (req, res) => {
    // Use a whitelist of allowed code blocks
    const allowedCodeBlocks = {
      'calculateSum': 'function sum(arr) { return arr.reduce((a, b) => a + b, 0); }; output = sum(numbers);',
      'calculateAverage': 'function avg(arr) { return arr.reduce((a, b) => a + b, 0) / arr.length; }; output = avg(numbers);'
    };
    
    const blockId = req.body.blockId;
    const numbers = req.body.numbers || [];
    
    // Validate numbers array contains only numbers
    if (!Array.isArray(numbers) || !numbers.every(n => typeof n === 'number')) {
      return res.status(400).json({ error: 'Invalid numbers array' });
    }
    
    if (!allowedCodeBlocks[blockId]) {
      return res.status(400).json({ error: 'Unknown code block' });
    }
    
    const sandbox = { numbers, output: null };
    const context = vm.createContext(sandbox);
    
    try {
      // ok: javascript-express-vm-runincontext-injection
      const script = new vm.Script(allowedCodeBlocks[blockId]);
      script.runInContext(context);
      
      res.json({ output: sandbox.output });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  app.get('/safe-template-engine', (req, res) => {
    // Use a safe template processing approach
    const templates = {
      'greeting': 'Hello, {{user}}!',
      'welcome': 'Welcome to our site, {{user}}!'
    };
    
    const templateId = req.query.template;
    const user = sanitize(req.query.user || 'Guest');
    
    if (!templates[templateId]) {
      return res.status(400).send('Unknown template');
    }
    
    // ok: javascript-express-vm-runincontext-injection
    const result = templates[templateId].replace(/\{\{user\}\}/g, user);
    
    res.send(result);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  app.post('/safe-execute-multiple', (req, res) => {
    // Predefined script functions
    const scriptFunctions = {
      'add': (a, b) => a + b,
      'subtract': (a, b) => a - b,
      'multiply': (a, b) => a * b,
      'divide': (a, b) => b !== 0 ? a / b : 'Cannot divide by zero'
    };
    
    const operations = req.body.operations || [];
    const results = [];
    
    operations.forEach((op, index) => {
      const { type, params } = op;
      
      if (scriptFunctions[type] && Array.isArray(params) && params.length === 2 && 
          typeof params[0] === 'number' && typeof params[1] === 'number') {
        try {
          // ok: javascript-express-vm-runincontext-injection
          const result = scriptFunctions[type](params[0], params[1]);
          results.push({ index, success: true, result });
        } catch (error) {
          results.push({ index, success: false, error: error.message });
        }
      } else {
        results.push({ index, success: false, error: 'Invalid operation or parameters' });
      }
    });
    
    res.json({ results });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  app.get('/safe-module-usage', (req, res) => {
    // Whitelist of allowed modules
    const allowedModules = {
      'path': require('path'),
      'url': require('url'),
      'querystring': require('querystring')
    };
    
    const moduleName = req.query.module;
    
    if (!allowedModules[moduleName]) {
      return res.status(400).json({ error: 'Module not allowed' });
    }
    
    // ok: javascript-express-vm-runincontext-injection
    const moduleExports = allowedModules[moduleName];
    
    res.json({ 
      module: moduleName,
      methods: Object.keys(moduleExports)
    });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  app.post('/safe-json-transform', (req, res) => {
    // Predefined transformation functions
    const transformations = {
      'uppercase': (data) => {
        if (typeof data === 'string') return data.toUpperCase();
        if (typeof data === 'object') {
          const result = {};
          for (const key in data) {
            if (typeof data[key] === 'string') {
              result[key] = data[key].toUpperCase();
            } else {
              result[key] = data[key];
            }
          }
          return result;
        }
        return data;
      },
      'addTimestamp': (data) => {
        if (typeof data === 'object') {
          return { ...data, timestamp: new Date().toISOString() };
        }
        return data;
      }
    };
    
    try {
      const jsonData = JSON.parse(req.body.data);
      const transformType = req.body.transform;
      
      if (!transformations[transformType]) {
        return res.status(400).json({ error: 'Unknown transformation' });
      }
      
      // ok: javascript-express-vm-runincontext-injection
      const transformed = transformations[transformType](jsonData);
      
      res.json({ transformed });
    } catch (error) {
      res.status(400).json({ error: 'Invalid JSON data' });
    }
  });
}
// {/fact}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});