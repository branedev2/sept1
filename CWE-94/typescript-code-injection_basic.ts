import * as http from 'http';
import * as url from 'url';
import * as express from 'express';
import * as fs from 'fs';
import * as child_process from 'child_process';

// TRUE POSITIVES (Vulnerable Code)

// Bad Case 1: Using eval with user input from query parameter
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: express.Request, res: express.Response) {
    const userInput = req.query.code as string;
    
    // ruleid: typescript-code-injection
    eval(userInput);
    
    res.send('Code executed');
}
// {/fact}

// Bad Case 2: Using Function constructor with user input from POST body
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: express.Request, res: express.Response) {
    const userCode = req.body.userCode;
    
    // ruleid: typescript-code-injection
    const dynamicFunc = new Function(userCode);
    dynamicFunc();
    
    res.send('Function executed');
}
// {/fact}

// Bad Case 3: Using setTimeout with string argument from request parameter
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: express.Request, res: express.Response) {
    const userScript = req.query.script as string;
    
    // ruleid: typescript-code-injection
    setTimeout(userScript, 1000);
    
    res.send('Script scheduled');
}
// {/fact}

// Bad Case 4: Using setInterval with string argument from request header
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: express.Request, res: express.Response) {
    const userCode = req.headers['x-custom-code'] as string;
    
    // ruleid: typescript-code-injection
    setInterval(userCode, 5000);
    
    res.send('Interval set');
}
// {/fact}

// Bad Case 5: Using indirect eval through window object with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: express.Request, res: express.Response) {
    const userInput = req.query.input as string;
    
    // ruleid: typescript-code-injection
    (0, eval)(userInput);
    
    res.send('Executed via indirect eval');
}
// {/fact}

// Bad Case 6: Using eval with template literal containing user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: express.Request, res: express.Response) {
    const userValue = req.query.value as string;
    
    // ruleid: typescript-code-injection
    eval(`const result = ${userValue}; console.log(result);`);
    
    res.send('Template eval executed');
}
// {/fact}

// Bad Case 7: Using Function constructor with multiple arguments including user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: express.Request, res: express.Response) {
    const userParam = req.query.param as string;
    const userBody = req.body.code as string;
    
    // ruleid: typescript-code-injection
    const dynamicFunc = new Function('a', 'b', userBody);
    dynamicFunc(1, 2);
    
    res.send('Function with parameters executed');
}
// {/fact}

// Bad Case 8: Using eval in a conditional statement with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: express.Request, res: express.Response) {
    const userCondition = req.query.condition as string;
    
    if (req.query.execute === 'true') {
        // ruleid: typescript-code-injection
        eval(`if(${userCondition}) { console.log('Condition met'); }`);
    }
    
    res.send('Conditional evaluation complete');
}
// {/fact}

// Bad Case 9: Using setTimeout with concatenated user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: express.Request, res: express.Response) {
    const userId = req.params.id;
    
    // ruleid: typescript-code-injection
    setTimeout("fetchUserData('" + userId + "')", 100);
    
    res.send('User data fetch scheduled');
}
// {/fact}

// Bad Case 10: Using eval with processed but still unsafe user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req: express.Request, res: express.Response) {
    let userInput = req.query.command as string;
    userInput = userInput.replace(/['"]/g, ''); // Insufficient sanitization
    
    // ruleid: typescript-code-injection
    eval(userInput);
    
    res.send('Processed command executed');
}
// {/fact}

// Bad Case 11: Using Function constructor with user input in a loop
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: express.Request, res: express.Response) {
    const commands = req.body.commands as string[];
    
    for (const cmd of commands) {
        // ruleid: typescript-code-injection
        const execFunc = new Function(cmd);
        execFunc();
    }
    
    res.send('All commands executed');
}
// {/fact}

// Bad Case 12: Using eval with JSON.parse and user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req: express.Request, res: express.Response) {
    const jsonStr = req.body.jsonData as string;
    
    try {
        // ruleid: typescript-code-injection
        const data = eval('(' + jsonStr + ')');
        res.json(data);
    } catch (e) {
        res.status(400).send('Invalid JSON');
    }
}
// {/fact}

// Bad Case 13: Using window.setTimeout with user input (browser context)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: express.Request, res: express.Response) {
    const script = req.query.callback as string;
    
    const html = `
        <script>
            // ruleid: typescript-code-injection
            window.setTimeout("${script}", 1000);
        </script>
    `;
    
    res.send(html);
}
// {/fact}

// Bad Case 14: Using eval in error handling with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
    const userHandler = req.query.errorHandler as string;
    
    try {
        throw new Error('Test error');
    } catch (e) {
        // ruleid: typescript-code-injection
        eval(userHandler + '(e)');
    }
    
    res.send('Error handled');
}
// {/fact}

// Bad Case 15: Using Function constructor with user input from cookie
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
    const cookieValue = req.cookies.userFunction;
    
    if (cookieValue) {
        // ruleid: typescript-code-injection
        const cookieFunc = new Function('return ' + cookieValue)();
        res.send('Cookie function executed');
    } else {
        res.send('No cookie function found');
    }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Good Case 1: Using JSON.parse instead of eval for JSON
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: express.Request, res: express.Response) {
    const jsonStr = req.body.jsonData as string;
    
    try {
        // ok: typescript-code-injection
        const data = JSON.parse(jsonStr);
        res.json(data);
    } catch (e) {
        res.status(400).send('Invalid JSON');
    }
}
// {/fact}

// Good Case 2: Using setTimeout with function reference instead of string
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: express.Request, res: express.Response) {
    const userId = req.params.id;
    
    // ok: typescript-code-injection
    setTimeout(() => {
        fetchUserData(userId);
    }, 100);
    
    res.send('User data fetch scheduled safely');
}
// {/fact}

// Good Case 3: Using a predefined function instead of dynamic evaluation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: express.Request, res: express.Response) {
    const operation = req.query.op as string;
    const a = parseInt(req.query.a as string);
    const b = parseInt(req.query.b as string);
    
    // ok: typescript-code-injection
    const result = performOperation(operation, a, b);
    res.send(`Result: ${result}`);
}
// {/fact}

function performOperation(op: string, a: number, b: number): number {
    switch (op) {
        case 'add': return a + b;
        case 'subtract': return a - b;
        case 'multiply': return a * b;
        case 'divide': return a / b;
        default: return 0;
    }
}

// Good Case 4: Using a whitelist for allowed commands
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: express.Request, res: express.Response) {
    const command = req.query.cmd as string;
    
    const allowedCommands: {[key: string]: () => void} = {
        'showUsers': () => console.log('Showing users'),
        'showProducts': () => console.log('Showing products'),
        'showOrders': () => console.log('Showing orders')
    };
    
    // ok: typescript-code-injection
    if (command in allowedCommands) {
        allowedCommands[command]();
        res.send(`Executed: ${command}`);
    } else {
        res.status(400).send('Invalid command');
    }
}
// {/fact}

// Good Case 5: Using setInterval with function reference
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: express.Request, res: express.Response) {
    const userId = req.query.id as string;
    
    // ok: typescript-code-injection
    setInterval(() => {
        console.log(`Checking updates for user ${userId}`);
    }, 5000);
    
    res.send('Update check scheduled');
}
// {/fact}

// Good Case 6: Using template literals without eval
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: express.Request, res: express.Response) {
    const userName = req.query.name as string;
    
    // ok: typescript-code-injection
    const greeting = `Hello, ${userName}!`;
    res.send(greeting);
}
// {/fact}

// Good Case 7: Using a map of functions instead of dynamic evaluation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: express.Request, res: express.Response) {
    const functionName = req.query.func as string;
    const param = req.query.param as string;
    
    const functionMap: {[key: string]: (p: string) => string} = {
        'uppercase': (p: string) => p.toUpperCase(),
        'lowercase': (p: string) => p.toLowerCase(),
        'reverse': (p: string) => p.split('').reverse().join('')
    };
    
    // ok: typescript-code-injection
    if (functionName in functionMap) {
        const result = functionMap[functionName](param);
        res.send(result);
    } else {
        res.status(400).send('Unknown function');
    }
}
// {/fact}

// Good Case 8: Using a switch statement instead of eval
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: express.Request, res: express.Response) {
    const action = req.query.action as string;
    const value = req.query.value as string;
    
    let result: string;
    
    // ok: typescript-code-injection
    switch (action) {
        case 'greet':
            result = `Hello, ${value}!`;
            break;
        case 'farewell':
            result = `Goodbye, ${value}!`;
            break;
        default:
            result = 'Unknown action';
    }
    
    res.send(result);
}
// {/fact}

// Good Case 9: Safe dynamic property access
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: express.Request, res: express.Response) {
    const propertyName = req.query.prop as string;
    
    const safeObject = {
        name: 'John',
        age: 30,
        city: 'New York'
    };
    
    // ok: typescript-code-injection
    if (propertyName in safeObject) {
        res.send(`${propertyName}: ${safeObject[propertyName as keyof typeof safeObject]}`);
    } else {
        res.status(400).send('Property not found');
    }
}
// {/fact}

// Good Case 10: Using a configuration object instead of dynamic code
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: express.Request, res: express.Response) {
    const configName = req.query.config as string;
    
    const configurations = {
        'development': {
            debug: true,
            logLevel: 'verbose',
            apiUrl: 'http://dev-api.example.com'
        },
        'production': {
            debug: false,
            logLevel: 'error',
            apiUrl: 'https://api.example.com'
        }
    };
    
    // ok: typescript-code-injection
    const config = configurations[configName as keyof typeof configurations] || configurations.development;
    res.json(config);
}
// {/fact}

// Good Case 11: Using Function.prototype methods safely
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: express.Request, res: express.Response) {
    const numbers = [1, 2, 3, 4, 5];
    const operation = req.query.op as string;
    
    let result;
    
    // ok: typescript-code-injection
    if (operation === 'sum') {
        result = numbers.reduce((a, b) => a + b, 0);
    } else if (operation === 'product') {
        result = numbers.reduce((a, b) => a * b, 1);
    } else {
        result = numbers;
    }
    
    res.json({ result });
}
// {/fact}

// Good Case 12: Using a validator function before processing
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: express.Request, res: express.Response) {
    const input = req.body.data;
    
    // ok: typescript-code-injection
    if (isValidInput(input)) {
        const processedData = processData(input);
        res.json(processedData);
    } else {
        res.status(400).send('Invalid input');
    }
}
// {/fact}

function isValidInput(input: any): boolean {
    return typeof input === 'object' && input !== null && !Array.isArray(input);
}

function processData(data: any): any {
    return { processed: true, ...data };
}

// Good Case 13: Using a module system instead of dynamic code loading
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: express.Request, res: express.Response) {
    const moduleName = req.query.module as string;
    
    const modules = {
        'users': {
            getAll: () => ['user1', 'user2', 'user3'],
            getById: (id: string) => ({ id, name: `User ${id}` })
        },
        'products': {
            getAll: () => ['product1', 'product2'],
            getById: (id: string) => ({ id, name: `Product ${id}` })
        }
    };
    
    // ok: typescript-code-injection
    if (moduleName in modules) {
        const selectedModule = modules[moduleName as keyof typeof modules];
        res.json(selectedModule.getAll());
    } else {
        res.status(404).send('Module not found');
    }
}
// {/fact}

// Good Case 14: Using a strategy pattern instead of dynamic evaluation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
    const strategyName = req.query.strategy as string;
    const value = parseInt(req.query.value as string);
    
    const strategies = {
        'double': (x: number) => x * 2,
        'square': (x: number) => x * x,
        'increment': (x: number) => x + 1
    };
    
    // ok: typescript-code-injection
    if (strategyName in strategies) {
        const result = strategies[strategyName as keyof typeof strategies](value);
        res.send(`Result: ${result}`);
    } else {
        res.status(400).send('Unknown strategy');
    }
}
// {/fact}

// Good Case 15: Using a template engine instead of dynamic HTML generation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req: express.Request, res: express.Response) {
    const userName = req.query.name as string;
    const userRole = req.query.role as string;
    
    // ok: typescript-code-injection
    const templateData = {
        user: {
            name: userName,
            role: userRole,
            permissions: getPermissionsForRole(userRole)
        },
        date: new Date().toLocaleDateString()
    };
    
    // In a real app, you would use a template engine like Handlebars, EJS, etc.
    res.render('dashboard', templateData);
}
// {/fact}

function getPermissionsForRole(role: string): string[] {
    const permissions: {[key: string]: string[]} = {
        'admin': ['read', 'write', 'delete'],
        'editor': ['read', 'write'],
        'viewer': ['read']
    };
    
    return permissions[role] || [];
}