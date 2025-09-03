import express from 'express';
import { Sandbox } from 'some-sandbox-library';
import * as http from 'http';
import axios from 'axios';
import { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { URL } from 'url';

// Initialize sandbox
const sandbox = new Sandbox();

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: express.Request, res: express.Response) {
    const userCode = req.query.code as string;
    
    // ruleid: typescript-sandbox-code-injection
    sandbox.run(userCode);
    
    res.send('Code executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: express.Request, res: express.Response) {
    const userCode = req.body.script;
    const options = { timeout: 5000 };
    
    // ruleid: typescript-sandbox-code-injection
    sandbox.run(userCode, options);
    
    res.json({ status: 'executed' });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: express.Request, res: express.Response) {
    const userCode = req.headers['x-custom-code'] as string;
    
    try {
        // ruleid: typescript-sandbox-code-injection
        const result = sandbox.run(userCode);
        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: 'Execution failed' });
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: express.Request, res: express.Response) {
    const userCode = req.cookies.savedCode;
    
    if (userCode) {
        // ruleid: typescript-sandbox-code-injection
        sandbox.run(userCode);
    }
    
    res.send('Executed saved code');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: express.Request, res: express.Response) {
    let userCode = req.query.code as string;
    userCode = userCode + '\nconsole.log("Execution completed");';
    
    // ruleid: typescript-sandbox-code-injection
    sandbox.run(userCode);
    
    res.send('Code executed with logging');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: express.Request, res: express.Response) {
    const fileName = req.query.file as string;
    const userCode = fs.readFileSync(fileName, 'utf8');
    
    // ruleid: typescript-sandbox-code-injection
    sandbox.run(userCode);
    
    res.send('File executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: express.Request, res: express.Response) {
    const userCode = req.query.code as string;
    const transformedCode = `
        try {
            ${userCode}
        } catch (e) {
            console.error(e);
        }
    `;
    
    // ruleid: typescript-sandbox-code-injection
    sandbox.run(transformedCode);
    
    res.send('Code executed with error handling');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: express.Request, res: express.Response) {
    const apiUrl = req.query.codeUrl as string;
    
    http.get(apiUrl, (response) => {
        let userCode = '';
        
        response.on('data', (chunk) => {
            userCode += chunk;
        });
        
        response.on('end', () => {
            // ruleid: typescript-sandbox-code-injection
            sandbox.run(userCode);
            res.send('Remote code executed');
        });
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: express.Request, res: express.Response) {
    const userCode = Buffer.from(req.query.encodedCode as string, 'base64').toString();
    
    // ruleid: typescript-sandbox-code-injection
    sandbox.run(userCode);
    
    res.send('Decoded code executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req: express.Request, res: express.Response) {
    const parts = [
        req.query.part1,
        req.query.part2,
        req.query.part3
    ];
    
    const userCode = parts.join('\n');
    
    // ruleid: typescript-sandbox-code-injection
    sandbox.run(userCode);
    
    res.send('Combined code executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: express.Request, res: express.Response) {
    const userTemplate = req.query.template as string;
    const data = { name: 'User', id: 123 };
    
    const userCode = userTemplate.replace(/\{\{(\w+)\}\}/g, (_, key) => {
        return data[key] || '';
    });
    
    // ruleid: typescript-sandbox-code-injection
    sandbox.run(userCode);
    
    res.send('Template code executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_12(req: express.Request, res: express.Response) {
    const codeUrl = req.query.url as string;
    
    try {
        const response = await axios.get(codeUrl);
        const userCode = response.data;
        
        // ruleid: typescript-sandbox-code-injection
        sandbox.run(userCode);
        
        res.send('Fetched code executed');
    } catch (error) {
        res.status(500).send('Failed to fetch code');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: express.Request, res: express.Response) {
    const userCode = req.query.code as string;
    
    setTimeout(() => {
        // ruleid: typescript-sandbox-code-injection
        sandbox.run(userCode);
        res.send('Delayed code execution');
    }, 1000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
    const userInput = JSON.parse(req.body.data);
    const userCode = userInput.code;
    
    if (userInput.execute) {
        // ruleid: typescript-sandbox-code-injection
        sandbox.run(userCode);
    }
    
    res.json({ status: 'processed' });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
    const eventHandlers: Record<string, string> = {};
    
    eventHandlers.onClick = req.body.clickHandler;
    eventHandlers.onLoad = req.body.loadHandler;
    
    for (const [event, handler] of Object.entries(eventHandlers)) {
        if (handler) {
            // ruleid: typescript-sandbox-code-injection
            sandbox.run(handler);
        }
    }
    
    res.json({ status: 'handlers registered' });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: express.Request, res: express.Response) {
    const userCode = req.query.code as string;
    
    // Only allow specific predefined code patterns
    const allowedPatterns = [
        'console.log("Hello World")',
        'return 1 + 1',
        'return Math.random()'
    ];
    
    if (allowedPatterns.includes(userCode)) {
        // ok: typescript-sandbox-code-injection
        sandbox.run(userCode);
    } else {
        res.status(400).send('Invalid code pattern');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: express.Request, res: express.Response) {
    // Using predefined code, not user input
    const predefinedCode = 'console.log("Hello World")';
    
    // ok: typescript-sandbox-code-injection
    sandbox.run(predefinedCode);
    
    res.send('Predefined code executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: express.Request, res: express.Response) {
    // Using hardcoded code templates with safe interpolation
    const userName = req.query.name as string;
    const sanitizedName = userName.replace(/[^\w\s]/g, ''); // Simple sanitization
    
    const safeCode = `console.log("Hello, ${sanitizedName}!")`;
    
    // ok: typescript-sandbox-code-injection
    sandbox.run(safeCode);
    
    res.send('Safe template executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: express.Request, res: express.Response) {
    // Using a whitelist of allowed operations
    const operation = req.query.op as string;
    const a = parseInt(req.query.a as string) || 0;
    const b = parseInt(req.query.b as string) || 0;
    
    let code: string;
    
    switch (operation) {
        case 'add':
            code = `return ${a} + ${b}`;
            break;
        case 'subtract':
            code = `return ${a} - ${b}`;
            break;
        case 'multiply':
            code = `return ${a} * ${b}`;
            break;
        case 'divide':
            code = b !== 0 ? `return ${a} / ${b}` : 'return "Cannot divide by zero"';
            break;
        default:
            res.status(400).send('Invalid operation');
            return;
    }
    
    // ok: typescript-sandbox-code-injection
    const result = sandbox.run(code);
    res.json({ result });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: express.Request, res: express.Response) {
    // Using code from a trusted source
    const trustedCodePath = path.join(__dirname, 'trusted-scripts', 'script.js');
    const trustedCode = fs.readFileSync(trustedCodePath, 'utf8');
    
    // ok: typescript-sandbox-code-injection
    sandbox.run(trustedCode);
    
    res.send('Trusted code executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: express.Request, res: express.Response) {
    // Using a code validator before execution
    const userCode = req.query.code as string;
    
    function isCodeSafe(code: string): boolean {
        // Check for potentially dangerous operations
        const dangerousPatterns = [
            /eval\s*\(/,
            /Function\s*\(/,
            /setTimeout\s*\(/,
            /setInterval\s*\(/,
            /new\s+Function/,
            /process/,
            /require\s*\(/,
            /import\s+/,
            /fs\./,
            /http\./
        ];
        
        return !dangerousPatterns.some(pattern => pattern.test(code));
    }
    
    if (isCodeSafe(userCode)) {
        // ok: typescript-sandbox-code-injection
        sandbox.run(userCode);
        res.send('Safe code executed');
    } else {
        res.status(400).send('Potentially unsafe code detected');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: express.Request, res: express.Response) {
    // Using a code transformer to make user input safe
    const userInput = req.query.expression as string;
    
    // Only allow mathematical expressions
    function transformToSafeExpression(input: string): string {
        // Remove all non-math characters
        const sanitized = input.replace(/[^\d+\-*/(). ]/g, '');
        return `return ${sanitized}`;
    }
    
    const safeCode = transformToSafeExpression(userInput);
    
    // ok: typescript-sandbox-code-injection
    const result = sandbox.run(safeCode);
    res.json({ result });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: express.Request, res: express.Response) {
    // Using predefined code blocks with user-selected parameters
    const blockType = req.query.block as string;
    const iterations = Math.min(parseInt(req.query.iterations as string) || 1, 100); // Limit iterations
    
    let code: string;
    
    if (blockType === 'loop') {
        code = `
            let result = 0;
            for (let i = 0; i < ${iterations}; i++) {
                result += i;
            }
            return result;
        `;
    } else if (blockType === 'map') {
        code = `
            const arr = Array(${iterations}).fill(1);
            return arr.map((x, i) => x + i);
        `;
    } else {
        res.status(400).send('Invalid block type');
        return;
    }
    
    // ok: typescript-sandbox-code-injection
    const result = sandbox.run(code);
    res.json({ result });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: express.Request, res: express.Response) {
    // Using AST validation for user code
    const userCode = req.query.code as string;
    
    // Mock AST validator (in real code, use a proper parser like acorn/esprima)
    function validateAst(code: string): boolean {
        try {
            // This is a simplified mock. In reality, you'd parse the code to AST
            // and check for unsafe nodes/patterns
            if (code.includes('eval') || code.includes('require')) {
                return false;
            }
            return true;
        } catch (e) {
            return false;
        }
    }
    
    if (validateAst(userCode)) {
        // ok: typescript-sandbox-code-injection
        sandbox.run(userCode);
        res.send('AST-validated code executed');
    } else {
        res.status(400).send('Code failed AST validation');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: express.Request, res: express.Response) {
    // Using code templates with safe user parameters
    const templateName = req.query.template as string;
    const param1 = parseInt(req.query.param1 as string) || 0;
    const param2 = parseInt(req.query.param2 as string) || 0;
    
    const templates: Record<string, (p1: number, p2: number) => string> = {
        'calculator': (p1, p2) => `return ${p1} + ${p2}`,
        'arrayGenerator': (size, value) => `return Array(${size}).fill(${value})`,
        'counter': (start, end) => `
            let count = ${start};
            let result = [];
            while (count <= ${end}) {
                result.push(count++);
            }
            return result;
        `
    };
    
    if (templates[templateName]) {
        const code = templates[templateName](param1, param2);
        // ok: typescript-sandbox-code-injection
        const result = sandbox.run(code);
        res.json({ result });
    } else {
        res.status(400).send('Invalid template');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: express.Request, res: express.Response) {
    // Using a code builder with strict typing
    const operation = req.query.op as string;
    
    type SafeOperation = 'sum' | 'product' | 'average';
    
    function buildSafeCode(op: SafeOperation, values: number[]): string {
        const safeValues = values.map(v => isNaN(v) ? 0 : v);
        
        switch (op) {
            case 'sum':
                return `return [${safeValues.join(',')}].reduce((a, b) => a + b, 0)`;
            case 'product':
                return `return [${safeValues.join(',')}].reduce((a, b) => a * b, 1)`;
            case 'average':
                return `
                    const values = [${safeValues.join(',')}];
                    return values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;
                `;
            default:
                throw new Error('Invalid operation');
        }
    }
    
    try {
        const values = (req.query.values as string).split(',').map(Number);
        const code = buildSafeCode(operation as SafeOperation, values);
        
        // ok: typescript-sandbox-code-injection
        const result = sandbox.run(code);
        res.json({ result });
    } catch (error) {
        res.status(400).send('Invalid operation or values');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: express.Request, res: express.Response) {
    // Using environment-controlled code execution
    const environment = process.env.NODE_ENV || 'production';
    
    if (environment === 'development') {
        const devCode = req.query.devCode as string;
        // This is safe because it's only allowed in development environment
        // ok: typescript-sandbox-code-injection
        sandbox.run(devCode);
        res.send('Development code executed');
    } else {
        // In production, only run predefined code
        const prodCode = 'return "Running in production"';
        // ok: typescript-sandbox-code-injection
        const result = sandbox.run(prodCode);
        res.json({ result });
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: express.Request, res: express.Response) {
    // Using code signing for verification
    const userCode = req.query.code as string;
    const signature = req.query.signature as string;
    
    function verifyCodeSignature(code: string, sig: string): boolean {
        // In a real implementation, this would use crypto to verify
        // that the code was signed by a trusted source
        const trustedSignatures = ['valid-sig-1', 'valid-sig-2'];
        return trustedSignatures.includes(sig);
    }
    
    if (verifyCodeSignature(userCode, signature)) {
        // ok: typescript-sandbox-code-injection
        sandbox.run(userCode);
        res.send('Verified code executed');
    } else {
        res.status(401).send('Code signature verification failed');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
    // Using a permission system for code execution
    const userCode = req.query.code as string;
    const userRole = req.headers['x-user-role'] as string;
    
    function userHasExecutePermission(role: string): boolean {
        const rolesWithPermission = ['admin', 'developer'];
        return rolesWithPermission.includes(role);
    }
    
    if (userHasExecutePermission(userRole)) {
        // This is safe because only authorized users can execute code
        // ok: typescript-sandbox-code-injection
        sandbox.run(userCode);
        res.send('Authorized code execution');
    } else {
        res.status(403).send('Insufficient permissions for code execution');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req: express.Request, res: express.Response) {
    // Using code from a trusted database
    const scriptId = req.query.id as string;
    
    // Mock database lookup
    function getScriptFromDatabase(id: string): string | null {
        const trustedScripts: Record<string, string> = {
            'script1': 'return "Hello from script 1"',
            'script2': 'return [1, 2, 3].map(x => x * 2)',
            'script3': 'return { status: "success", timestamp: Date.now() }'
        };
        
        return trustedScripts[id] || null;
    }
    
    const trustedCode = getScriptFromDatabase(scriptId);
    
    if (trustedCode) {
        // ok: typescript-sandbox-code-injection
        const result = sandbox.run(trustedCode);
        res.json({ result });
    } else {
        res.status(404).send('Script not found');
    }
}
// {/fact}