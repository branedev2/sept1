import express from 'express';
import { VM, NodeVM } from 'vm2';
import * as fs from 'fs';
import * as path from 'path';
import { sanitize } from 'some-sanitizer-library';
import { validate } from 'some-validator-library';
import dotenv from 'dotenv';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  app.get('/execute-code', (req, res) => {
    const userCode = req.query.code as string;
    const vm = new VM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(userCode);
      res.send({ result });
    } catch (error) {
      res.status(500).send({ error: 'Execution failed' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  app.post('/evaluate-expression', (req, res) => {
    const expression = req.body.expression;
    const vm = new VM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(`return ${expression};`);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: 'Invalid expression' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  app.get('/calculate', (req, res) => {
    const formula = req.query.formula as string;
    const vm = new VM({
      timeout: 1000,
      sandbox: {}
    });
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(`(function() { return ${formula}; })()`);
      res.send(`Result: ${result}`);
    } catch (err) {
      res.status(500).send('Error in calculation');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  app.post('/run-node-code', (req, res) => {
    const code = req.body.code;
    const nodeVm = new NodeVM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = nodeVm.run(code);
      res.json({ output: result });
    } catch (error) {
      res.status(500).json({ error: 'Execution error' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  app.get('/template-render', (req, res) => {
    const template = req.query.template as string;
    const data = { name: 'User', age: 25 };
    const vm = new VM({ sandbox: { data } });
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const rendered = vm.run(`\`${template}\``);
      res.send(rendered);
    } catch (error) {
      res.status(400).send('Template rendering failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  app.post('/execute-with-context', (req, res) => {
    const userScript = req.body.script;
    const context = { x: 10, y: 20 };
    const vm = new VM({ sandbox: context });
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(userScript);
      res.json({ result });
    } catch (error) {
      res.status(500).json({ error: 'Script execution failed' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  app.get('/dynamic-function', (req, res) => {
    const functionBody = req.query.body as string;
    const vm = new VM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(`(function() { ${functionBody} })()`);
      res.send({ result });
    } catch (error) {
      res.status(400).send('Function execution failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  app.post('/eval-math', (req, res) => {
    const expression = req.body.math;
    const vm = new VM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(`Math.eval('${expression}')`);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: 'Invalid math expression' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  app.get('/process-data', (req, res) => {
    const userInput = req.query.data as string;
    const processor = req.query.processor as string;
    const vm = new VM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(`
        const data = '${userInput}';
        ${processor}(data);
      `);
      res.send({ processed: result });
    } catch (error) {
      res.status(500).send('Processing failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  app.post('/custom-calculator', (req, res) => {
    const { a, b, operation } = req.body;
    const vm = new VM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(`
        const calculate = (a, b) => {
          return ${operation};
        };
        calculate(${a}, ${b});
      `);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: 'Calculation failed' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  app.get('/execute-from-header', (req, res) => {
    const scriptToRun = req.headers['x-custom-script'] as string;
    const vm = new VM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(scriptToRun);
      res.send({ output: result });
    } catch (error) {
      res.status(500).send('Script execution failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  app.post('/dynamic-template', (req, res) => {
    const templateEngine = req.body.engine;
    const templateData = req.body.data;
    const vm = new NodeVM({
      console: 'inherit',
      sandbox: { data: templateData }
    });
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const compiledTemplate = vm.run(`
        module.exports = function() {
          ${templateEngine}
          return render(data);
        }
      `);
      res.send(compiledTemplate());
    } catch (error) {
      res.status(500).send('Template compilation failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  app.get('/transform-data', (req, res) => {
    const data = JSON.parse(req.query.data as string);
    const transformer = req.query.transformer as string;
    const vm = new VM({ sandbox: { inputData: data } });
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(`
        function transform(data) {
          ${transformer}
        }
        transform(inputData);
      `);
      res.json({ transformed: result });
    } catch (error) {
      res.status(500).json({ error: 'Transformation failed' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  app.post('/execute-with-timeout', (req, res) => {
    const code = req.body.code;
    const timeout = parseInt(req.body.timeout) || 1000;
    const vm = new VM({ timeout });
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(code);
      res.json({ result });
    } catch (error) {
      res.status(500).json({ error: 'Execution timed out or failed' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  app.get('/conditional-execution', (req, res) => {
    const condition = req.query.condition as string;
    const trueCode = req.query.ifTrue as string;
    const falseCode = req.query.ifFalse as string;
    const vm = new VM();
    
    try {
      // ruleid: typescript-express-vm2-code-injection
      const result = vm.run(`
        if (${condition}) {
          ${trueCode}
        } else {
          ${falseCode}
        }
      `);
      res.send({ result });
    } catch (error) {
      res.status(400).send('Execution failed');
    }
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  app.get('/execute-safe-code', (req, res) => {
    const userCode = req.query.code as string;
    
    // Whitelist of allowed expressions
    const allowedExpressions = ['1+1', '2*2', 'Math.sqrt(16)'];
    
    if (allowedExpressions.includes(userCode)) {
      const vm = new VM();
      try {
        // ok: typescript-express-vm2-code-injection
        const result = vm.run(userCode);
        res.send({ result });
      } catch (error) {
        res.status(500).send({ error: 'Execution failed' });
      }
    } else {
      res.status(403).send({ error: 'Unauthorized code' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  app.post('/evaluate-safe-expression', (req, res) => {
    const expression = req.body.expression;
    
    // Validate expression using regex to ensure it only contains safe math operations
    if (/^[0-9+\-*/().]+$/.test(expression)) {
      const vm = new VM();
      try {
        // ok: typescript-express-vm2-code-injection
        const result = vm.run(`return ${expression};`);
        res.json({ result });
      } catch (error) {
        res.status(400).json({ error: 'Invalid expression' });
      }
    } else {
      res.status(403).json({ error: 'Unauthorized expression' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  app.get('/calculate-safe', (req, res) => {
    // Use predefined templates instead of user input
    const formulaId = req.query.formulaId as string;
    const formulas: Record<string, string> = {
      'area-circle': 'Math.PI * r * r',
      'area-rectangle': 'l * w',
      'volume-cube': 'a * a * a'
    };
    
    const formula = formulas[formulaId];
    if (!formula) {
      return res.status(400).send('Unknown formula');
    }
    
    const vm = new VM({
      timeout: 1000,
      sandbox: { 
        r: 5, 
        l: 10, 
        w: 5, 
        a: 3 
      }
    });
    
    try {
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(`(function() { return ${formula}; })()`);
      res.send(`Result: ${result}`);
    } catch (err) {
      res.status(500).send('Error in calculation');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  app.post('/run-safe-node-code', (req, res) => {
    // Use predefined code modules instead of user input
    const moduleId = req.body.moduleId;
    const modules: Record<string, string> = {
      'hello-world': 'module.exports = "Hello, World!";',
      'current-time': 'module.exports = new Date().toISOString();',
      'random-number': 'module.exports = Math.random();'
    };
    
    const code = modules[moduleId];
    if (!code) {
      return res.status(400).json({ error: 'Unknown module' });
    }
    
    const nodeVm = new NodeVM();
    try {
      // ok: typescript-express-vm2-code-injection
      const result = nodeVm.run(code);
      res.json({ output: result });
    } catch (error) {
      res.status(500).json({ error: 'Execution error' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  app.get('/template-render-safe', (req, res) => {
    const templateId = req.query.templateId as string;
    
    // Use predefined templates
    const templates: Record<string, string> = {
      'greeting': 'Hello ${data.name}!',
      'profile': 'Name: ${data.name}, Age: ${data.age}',
      'welcome': 'Welcome to our service, ${data.name}!'
    };
    
    const template = templates[templateId];
    if (!template) {
      return res.status(400).send('Unknown template');
    }
    
    const data = { name: 'User', age: 25 };
    const vm = new VM({ sandbox: { data } });
    
    try {
      // ok: typescript-express-vm2-code-injection
      const rendered = vm.run(`\`${template}\``);
      res.send(rendered);
    } catch (error) {
      res.status(400).send('Template rendering failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  app.post('/execute-sanitized', (req, res) => {
    let userScript = req.body.script;
    
    // Sanitize the input to remove potentially dangerous constructs
    userScript = sanitize(userScript);
    
    // Additional validation to ensure only math operations
    if (validate(userScript, 'mathExpression')) {
      const vm = new VM();
      try {
        // ok: typescript-express-vm2-code-injection
        const result = vm.run(userScript);
        res.json({ result });
      } catch (error) {
        res.status(500).json({ error: 'Script execution failed' });
      }
    } else {
      res.status(403).json({ error: 'Invalid script content' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  app.get('/safe-dynamic-function', (req, res) => {
    // Use a predefined set of function templates
    const functionId = req.query.functionId as string;
    const functions: Record<string, string> = {
      'square': 'return x * x;',
      'cube': 'return x * x * x;',
      'double': 'return x + x;'
    };
    
    const functionBody = functions[functionId];
    if (!functionBody) {
      return res.status(400).send('Unknown function');
    }
    
    const x = parseInt(req.query.x as string) || 0;
    const vm = new VM({ sandbox: { x } });
    
    try {
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(`(function() { ${functionBody} })()`);
      res.send({ result });
    } catch (error) {
      res.status(400).send('Function execution failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  app.post('/safe-math-eval', (req, res) => {
    const expression = req.body.math;
    
    // Validate that the expression only contains allowed math characters
    if (!/^[0-9+\-*/().sqrt\s]+$/.test(expression)) {
      return res.status(403).json({ error: 'Invalid math expression' });
    }
    
    // Replace potentially dangerous functions with safe alternatives
    const safeExpression = expression
      .replace(/sqrt\(/g, 'Math.sqrt(')
      .replace(/sin\(/g, 'Math.sin(')
      .replace(/cos\(/g, 'Math.cos(');
    
    const vm = new VM();
    try {
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(`${safeExpression}`);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: 'Invalid math expression' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  app.get('/process-data-safely', (req, res) => {
    const userInput = req.query.data as string;
    
    // Use predefined processors instead of user-provided code
    const processorId = req.query.processorId as string;
    const processors: Record<string, string> = {
      'uppercase': 'data.toUpperCase()',
      'lowercase': 'data.toLowerCase()',
      'reverse': 'data.split("").reverse().join("")'
    };
    
    const processor = processors[processorId];
    if (!processor) {
      return res.status(400).send('Unknown processor');
    }
    
    const vm = new VM();
    try {
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(`
        const data = '${userInput.replace(/'/g, "\\'")}';
        ${processor};
      `);
      res.send({ processed: result });
    } catch (error) {
      res.status(500).send('Processing failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  app.post('/safe-calculator', (req, res) => {
    const { a, b, operation } = req.body;
    
    // Whitelist of allowed operations
    const allowedOperations: Record<string, string> = {
      'add': 'a + b',
      'subtract': 'a - b',
      'multiply': 'a * b',
      'divide': 'b !== 0 ? a / b : "Cannot divide by zero"'
    };
    
    const operationCode = allowedOperations[operation];
    if (!operationCode) {
      return res.status(400).json({ error: 'Unsupported operation' });
    }
    
    const vm = new VM();
    try {
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(`
        const calculate = (a, b) => {
          return ${operationCode};
        };
        calculate(${a}, ${b});
      `);
      res.json({ result });
    } catch (error) {
      res.status(400).json({ error: 'Calculation failed' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  app.get('/execute-predefined-script', (req, res) => {
    const scriptId = req.headers['x-script-id'] as string;
    
    // Use predefined scripts from a secure source
    const scripts: Record<string, string> = {
      'hello': '"Hello, World!"',
      'timestamp': 'new Date().toISOString()',
      'random': 'Math.random()'
    };
    
    const scriptToRun = scripts[scriptId];
    if (!scriptToRun) {
      return res.status(400).send('Unknown script ID');
    }
    
    const vm = new VM();
    try {
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(scriptToRun);
      res.send({ output: result });
    } catch (error) {
      res.status(500).send('Script execution failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  app.post('/safe-template-engine', (req, res) => {
    const templateId = req.body.templateId;
    const templateData = req.body.data;
    
    // Predefined template engines
    const engines: Record<string, string> = {
      'simple': 'function render(data) { return `Hello ${data.name}!`; }',
      'detailed': 'function render(data) { return `Name: ${data.name}, Age: ${data.age}`; }',
      'list': 'function render(data) { return data.items.map(item => `- ${item}`).join("\\n"); }'
    };
    
    const templateEngine = engines[templateId];
    if (!templateEngine) {
      return res.status(400).send('Unknown template engine');
    }
    
    const vm = new NodeVM({
      console: 'inherit',
      sandbox: { data: templateData }
    });
    
    try {
      // ok: typescript-express-vm2-code-injection
      const compiledTemplate = vm.run(`
        module.exports = function() {
          ${templateEngine}
          return render(data);
        }
      `);
      res.send(compiledTemplate());
    } catch (error) {
      res.status(500).send('Template compilation failed');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  app.get('/transform-data-safely', (req, res) => {
    const data = JSON.parse(req.query.data as string);
    
    // Use predefined transformers
    const transformerId = req.query.transformerId as string;
    const transformers: Record<string, string> = {
      'uppercase': 'return data.map(item => item.toUpperCase());',
      'double': 'return data.map(item => item * 2);',
      'keys': 'return Object.keys(data);'
    };
    
    const transformer = transformers[transformerId];
    if (!transformer) {
      return res.status(400).json({ error: 'Unknown transformer' });
    }
    
    const vm = new VM({ sandbox: { inputData: data } });
    try {
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(`
        function transform(data) {
          ${transformer}
        }
        transform(inputData);
      `);
      res.json({ transformed: result });
    } catch (error) {
      res.status(500).json({ error: 'Transformation failed' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  app.post('/execute-from-config', (req, res) => {
    // Load code from a secure configuration file instead of user input
    const scriptName = req.body.scriptName;
    
    // Validate that the script name only contains alphanumeric characters
    if (!/^[a-zA-Z0-9_-]+$/.test(scriptName)) {
      return res.status(400).json({ error: 'Invalid script name' });
    }
    
    try {
      // Read from a predefined directory with controlled scripts
      const scriptPath = path.join(__dirname, 'safe-scripts', `${scriptName}.js`);
      const code = fs.readFileSync(scriptPath, 'utf8');
      
      const vm = new VM();
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(code);
      res.json({ result });
    } catch (error) {
      res.status(500).json({ error: 'Script not found or execution failed' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  app.get('/safe-conditional', (req, res) => {
    // Use predefined conditions and code blocks
    const conditionId = req.query.conditionId as string;
    const conditions: Record<string, { condition: string, trueCode: string, falseCode: string }> = {
      'age': {
        condition: 'data.age >= 18',
        trueCode: 'return "Adult";',
        falseCode: 'return "Minor";'
      },
      'score': {
        condition: 'data.score >= 70',
        trueCode: 'return "Pass";',
        falseCode: 'return "Fail";'
      }
    };
    
    const selectedCondition = conditions[conditionId];
    if (!selectedCondition) {
      return res.status(400).send('Unknown condition');
    }
    
    const data = {
      age: parseInt(req.query.age as string) || 0,
      score: parseInt(req.query.score as string) || 0
    };
    
    const vm = new VM({ sandbox: { data } });
    try {
      // ok: typescript-express-vm2-code-injection
      const result = vm.run(`
        if (${selectedCondition.condition}) {
          ${selectedCondition.trueCode}
        } else {
          ${selectedCondition.falseCode}
        }
      `);
      res.send({ result });
    } catch (error) {
      res.status(400).send('Execution failed');
    }
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});