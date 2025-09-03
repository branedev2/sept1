import * as express from 'express';
import * as vm from 'vm';
import { Request, Response } from 'express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// Bad Case 1: Direct use of query parameter in vm.runInNewContext
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userCode = req.query.code as string;
    const sandbox = { result: null };
    
    // ruleid: typescript-express-vm-runincontext-injection
    vm.runInNewContext(userCode, sandbox);
    
    res.send(`Result: ${sandbox.result}`);
}
// {/fact}

// Bad Case 2: Using POST body in vm.runInContext
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userScript = req.body.script;
    const context = vm.createContext({ console: console, result: null });
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInContext(userScript, context);
        res.json({ result: context.result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 3: Using request header in vm.compileFunction
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const userCode = req.headers['x-user-code'] as string;
    const params = ['a', 'b'];
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        const fn = vm.compileFunction(userCode, params);
        const result = fn(5, 10);
        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 4: Using URL parameter with minimal processing
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userCode = req.params.code;
    const sandbox = { output: '', console: { log: (msg: string) => { sandbox.output += msg + '\n'; } } };
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInNewContext(userCode, sandbox);
        res.send(sandbox.output);
    } catch (error) {
        res.status(400).send('Invalid code');
    }
}
// {/fact}

// Bad Case 5: Using cookie data in vm.runInThisContext
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const userScript = req.cookies.userScript;
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        const result = vm.runInThisContext(userScript);
        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 6: Using request body with JSON parsing
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const { code, input } = req.body;
    const sandbox = { input, output: null };
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInNewContext(`output = ${code}(input)`, sandbox);
        res.json({ result: sandbox.output });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 7: Using query parameter with template literals
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const expression = req.query.expr as string;
    const sandbox = { x: 10, y: 20, result: 0 };
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInNewContext(`result = ${expression}`, sandbox);
        res.send(`Result: ${sandbox.result}`);
    } catch (error) {
        res.status(400).send('Invalid expression');
    }
}
// {/fact}

// Bad Case 8: Using multiple request inputs combined
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const operation = req.query.op as string;
    const value = req.body.value;
    const code = `${operation}(${value})`;
    const context = vm.createContext({ 
        add: (x: number) => x + 1,
        multiply: (x: number) => x * 2,
        result: 0
    });
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInContext(code, context);
        res.json({ result: context.result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 9: Using vm.Script with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const userCode = req.query.code as string;
    const sandbox = { result: null };
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        const script = new vm.Script(userCode);
        script.runInNewContext(sandbox);
        res.json({ result: sandbox.result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 10: Using request body in async context
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_10(req: Request, res: Response) {
    const userCode = req.body.code;
    const sandbox = { 
        setTimeout,
        clearTimeout,
        result: null 
    };
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInNewContext(userCode, sandbox);
        await new Promise(resolve => setTimeout(resolve, 100));
        res.json({ result: sandbox.result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 11: Using request parameters with string concatenation
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const a = parseInt(req.query.a as string) || 0;
    const b = parseInt(req.query.b as string) || 0;
    const op = req.query.op as string;
    
    const code = "result = " + a + " " + op + " " + b;
    const sandbox = { result: 0 };
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInNewContext(code, sandbox);
        res.send(`Result: ${sandbox.result}`);
    } catch (error) {
        res.status(400).send('Invalid operation');
    }
}
// {/fact}

// Bad Case 12: Using vm with user input in a loop
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const expressions = req.body.expressions as string[];
    const results = [];
    const sandbox = { x: 10, y: 20 };
    
    for (const expr of expressions) {
        try {
            // ruleid: typescript-express-vm-runincontext-injection
            const result = vm.runInNewContext(expr, sandbox);
            results.push(result);
        } catch (error) {
            results.push(`Error: ${error.message}`);
        }
    }
    
    res.json({ results });
}
// {/fact}

// Bad Case 13: Using vm with conditional based on user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const mode = req.query.mode as string;
    const code = req.body.code;
    const sandbox = { result: null };
    
    try {
        if (mode === 'strict') {
            sandbox['use strict'] = true;
        }
        
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInNewContext(code, sandbox);
        res.json({ result: sandbox.result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 14: Using vm with user input after transformation
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    let userCode = req.body.code;
    userCode = userCode.replace(/console\.log/g, 'output.push');
    
    const sandbox = { output: [], result: null };
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInNewContext(userCode, sandbox);
        res.json({ output: sandbox.output, result: sandbox.result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Bad Case 15: Using vm with user input from multiple sources
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const functionName = req.query.fn as string;
    const args = req.body.args;
    const code = `${functionName}(${JSON.stringify(args)})`;
    
    const sandbox = {
        add: (args: number[]) => args.reduce((a, b) => a + b, 0),
        multiply: (args: number[]) => args.reduce((a, b) => a * b, 1),
        result: null
    };
    
    try {
        // ruleid: typescript-express-vm-runincontext-injection
        vm.runInNewContext(`result = ${code}`, sandbox);
        res.json({ result: sandbox.result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// Good Case 1: Using predefined templates with user parameters
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const a = parseInt(req.query.a as string) || 0;
    const b = parseInt(req.query.b as string) || 0;
    
    // Define allowed operations
    const operations = {
        add: 'result = a + b',
        subtract: 'result = a - b',
        multiply: 'result = a * b',
        divide: 'result = a / b'
    };
    
    const op = req.query.op as string;
    if (!operations[op]) {
        return res.status(400).send('Invalid operation');
    }
    
    const sandbox = { a, b, result: 0 };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(operations[op], sandbox);
    
    res.send(`Result: ${sandbox.result}`);
}
// {/fact}

// Good Case 2: Using a whitelist of allowed expressions
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const expressionId = req.query.expr as string;
    
    // Whitelist of allowed expressions
    const allowedExpressions = {
        'square': 'result = x * x',
        'cube': 'result = x * x * x',
        'double': 'result = x + x',
        'half': 'result = x / 2'
    };
    
    if (!allowedExpressions[expressionId]) {
        return res.status(400).send('Invalid expression');
    }
    
    const x = parseInt(req.query.x as string) || 0;
    const sandbox = { x, result: 0 };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(allowedExpressions[expressionId], sandbox);
    
    res.json({ result: sandbox.result });
}
// {/fact}

// Good Case 3: Using static code with user parameters
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const a = parseInt(req.query.a as string) || 0;
    const b = parseInt(req.query.b as string) || 0;
    
    const staticCode = 'result = a + b';
    const sandbox = { a, b, result: 0 };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(staticCode, sandbox);
    
    res.json({ result: sandbox.result });
}
// {/fact}

// Good Case 4: Using vm with hardcoded script
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const x = parseInt(req.query.x as string) || 0;
    const y = parseInt(req.query.y as string) || 0;
    
    const sandbox = { x, y, result: 0 };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext('result = Math.pow(x, 2) + Math.pow(y, 2)', sandbox);
    
    res.json({ result: sandbox.result });
}
// {/fact}

// Good Case 5: Using vm with validated input from a limited set
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const operation = req.query.op as string;
    
    // Validate operation is one of the allowed values
    const allowedOps = ['add', 'subtract', 'multiply', 'divide'];
    if (!allowedOps.includes(operation)) {
        return res.status(400).send('Invalid operation');
    }
    
    const a = parseInt(req.query.a as string) || 0;
    const b = parseInt(req.query.b as string) || 0;
    
    const opMap = {
        'add': 'a + b',
        'subtract': 'a - b',
        'multiply': 'a * b',
        'divide': 'a / b'
    };
    
    const sandbox = { a, b, result: 0 };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(`result = ${opMap[operation]}`, sandbox);
    
    res.json({ result: sandbox.result });
}
// {/fact}

// Good Case 6: Using vm with JSON schema validation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const input = req.body;
    
    // Simple schema validation
    if (!input || typeof input !== 'object' || 
        !('a' in input) || !('b' in input) || 
        typeof input.a !== 'number' || typeof input.b !== 'number') {
        return res.status(400).send('Invalid input');
    }
    
    const sandbox = { 
        a: input.a, 
        b: input.b, 
        result: 0 
    };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext('result = Math.max(a, b)', sandbox);
    
    res.json({ result: sandbox.result });
}
// {/fact}

// Good Case 7: Using vm with completely static code
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const sandbox = { result: null };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext('result = Math.random() * 100', sandbox);
    
    res.json({ random: sandbox.result });
}
// {/fact}

// Good Case 8: Using vm with parsed numeric inputs
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const numbers = [];
    
    // Parse query parameters as numbers
    if (req.query.numbers) {
        const inputNumbers = (req.query.numbers as string).split(',');
        for (const num of inputNumbers) {
            const parsed = parseFloat(num);
            if (!isNaN(parsed)) {
                numbers.push(parsed);
            }
        }
    }
    
    const sandbox = { numbers, result: 0 };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext('result = numbers.reduce((sum, n) => sum + n, 0)', sandbox);
    
    res.json({ sum: sandbox.result });
}
// {/fact}

// Good Case 9: Using vm with template literals but static code
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const min = parseInt(req.query.min as string) || 0;
    const max = parseInt(req.query.max as string) || 100;
    
    const sandbox = { min, max, result: 0 };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(`result = Math.floor(Math.random() * (max - min + 1)) + min`, sandbox);
    
    res.json({ randomNumber: sandbox.result });
}
// {/fact}

// Good Case 10: Using vm with static code and dynamic context
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const userData = req.body;
    const context = vm.createContext({ 
        data: userData, 
        processed: {},
        console: console
    });
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInContext(`
        processed.name = data.name ? data.name.toUpperCase() : '';
        processed.age = data.age ? parseInt(data.age) : 0;
        processed.timestamp = Date.now();
    `, context);
    
    res.json(context.processed);
}
// {/fact}

// Good Case 11: Using vm with static code in a loop
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const count = parseInt(req.query.count as string) || 5;
    const results = [];
    
    for (let i = 0; i < Math.min(count, 20); i++) {
        const sandbox = { index: i, result: 0 };
        
        // ok: typescript-express-vm-runincontext-injection
        vm.runInNewContext('result = index * index', sandbox);
        
        results.push(sandbox.result);
    }
    
    res.json({ results });
}
// {/fact}

// Good Case 12: Using vm with static code and user-provided context
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const userConfig = req.body;
    
    // Validate user config
    if (!userConfig || typeof userConfig !== 'object') {
        return res.status(400).send('Invalid configuration');
    }
    
    // Create a safe sandbox with user data
    const sandbox = {
        config: userConfig,
        validated: {},
        errors: []
    };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(`
        if (typeof config.timeout === 'number') {
            validated.timeout = Math.min(config.timeout, 30000);
        } else {
            errors.push('Invalid timeout');
        }
        
        if (typeof config.retries === 'number') {
            validated.retries = Math.min(config.retries, 5);
        } else {
            errors.push('Invalid retries');
        }
    `, sandbox);
    
    if (sandbox.errors.length > 0) {
        res.status(400).json({ errors: sandbox.errors });
    } else {
        res.json({ config: sandbox.validated });
    }
}
// {/fact}

// Good Case 13: Using vm with static code and safe function execution
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const functionName = req.query.fn as string;
    
    // Whitelist of allowed functions
    const allowedFunctions = ['sum', 'average', 'min', 'max'];
    
    if (!allowedFunctions.includes(functionName)) {
        return res.status(400).send('Invalid function');
    }
    
    const numbers = req.body.numbers || [];
    
    // Validate numbers
    if (!Array.isArray(numbers) || !numbers.every(n => typeof n === 'number')) {
        return res.status(400).send('Invalid numbers array');
    }
    
    const sandbox = {
        numbers,
        result: null
    };
    
    const functionMap = {
        'sum': 'numbers.reduce((a, b) => a + b, 0)',
        'average': 'numbers.length ? numbers.reduce((a, b) => a + b, 0) / numbers.length : 0',
        'min': 'Math.min(...numbers)',
        'max': 'Math.max(...numbers)'
    };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(`result = ${functionMap[functionName]}`, sandbox);
    
    res.json({ result: sandbox.result });
}
// {/fact}

// Good Case 14: Using vm with static code and safe object creation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const name = req.query.name as string || '';
    const age = parseInt(req.query.age as string) || 0;
    
    const sandbox = {
        name: name.trim(),
        age,
        result: {}
    };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(`
        result = {
            formattedName: name.toUpperCase(),
            isAdult: age >= 18,
            greeting: 'Hello, ' + name
        };
    `, sandbox);
    
    res.json(sandbox.result);
}
// {/fact}

// Good Case 15: Using vm with static code and safe array operations
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const items = req.body.items || [];
    
    // Validate items
    if (!Array.isArray(items)) {
        return res.status(400).send('Items must be an array');
    }
    
    const sandbox = {
        items: items.map(item => String(item)),
        result: {}
    };
    
    // ok: typescript-express-vm-runincontext-injection
    vm.runInNewContext(`
        result = {
            count: items.length,
            sorted: [...items].sort(),
            joined: items.join(', '),
            first: items[0] || null,
            last: items[items.length - 1] || null
        };
    `, sandbox);
    
    res.json(sandbox.result);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

export default app;