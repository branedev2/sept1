// Import necessary modules
const express = require('express');
const app = express();
const vm = require('vm');
const { JSDOM } = require('jsdom');
const DOMPurify = require('dompurify');
const sanitizeHtml = require('sanitize-html');

// Configure middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.input;
    // ruleid: javascript-code-injection
    eval(userInput);
    res.send('Executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req, res) {
    const userCode = req.body.code;
    // ruleid: javascript-code-injection
    new Function(userCode)();
    res.send('Function executed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req, res) {
    const expression = req.query.expr;
    // ruleid: javascript-code-injection
    vm.runInNewContext(expression);
    res.send('Expression evaluated');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req, res) {
    const template = req.body.template;
    const context = { data: req.body.data };
    // ruleid: javascript-code-injection
    const compiledTemplate = new Function('context', `with(context) { return \`${template}\`; }`);
    const result = compiledTemplate(context);
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req, res) {
    const scriptContent = req.query.script;
    // ruleid: javascript-code-injection
    const script = document.createElement('script');
    script.textContent = scriptContent;
    document.body.appendChild(script);
    res.send('Script added');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req, res) {
    const userInput = req.headers['x-custom-code'];
    // ruleid: javascript-code-injection
    setTimeout(userInput, 1000);
    res.send('Code scheduled');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req, res) {
    const userCode = req.cookies.code;
    // ruleid: javascript-code-injection
    const result = vm.runInThisContext(userCode);
    res.send(`Result: ${result}`);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req, res) {
    const formula = req.body.formula;
    // ruleid: javascript-code-injection
    const calculator = new Function('return ' + formula);
    const result = calculator();
    res.json({ result });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req, res) {
    const userEvent = req.query.event;
    const element = document.getElementById('target');
    // ruleid: javascript-code-injection
    element.setAttribute('onclick', userEvent);
    res.send('Event handler set');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req, res) {
    const dom = new JSDOM(`<!DOCTYPE html><p>Hello</p>`);
    const userScript = req.body.script;
    // ruleid: javascript-code-injection
    dom.window.eval(userScript);
    res.send(dom.serialize());
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req, res) {
    const userInput = req.query.input;
    let command = '';
    if (userInput.length > 10) {
        command = userInput.substring(0, 10);
    } else {
        command = userInput;
    }
    // ruleid: javascript-code-injection
    eval('console.log(' + command + ')');
    res.send('Logged');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req, res) {
    const code = [];
    code.push('const x = 1;');
    code.push(req.body.userCode);
    code.push('return x + y;');
    
    // ruleid: javascript-code-injection
    const func = new Function(code.join('\n'));
    const result = func();
    res.json({ result });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req, res) {
    const userInput = req.query.input || '';
    const sanitized = userInput.replace(/[<>]/g, '');
    // Still vulnerable - insufficient sanitization
    // ruleid: javascript-code-injection
    eval(sanitized);
    res.send('Processed');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req, res) {
    let scriptContent = '';
    for (const key in req.query) {
        if (key === 'script') {
            scriptContent = req.query[key];
        }
    }
    // ruleid: javascript-code-injection
    const scriptElement = document.createElement('script');
    scriptElement.innerHTML = scriptContent;
    document.head.appendChild(scriptElement);
    res.send('Script added');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req, res) {
    const template = `
        function render() {
            ${req.body.renderLogic}
            return result;
        }
    `;
    // ruleid: javascript-code-injection
    const renderer = new Function(template + '; return render;')();
    const output = renderer();
    res.send(output);
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req, res) {
    const userInput = req.query.input;
    // ok: javascript-code-injection
    const safeValue = String(userInput).replace(/[^\w\s]/gi, '');
    eval(`console.log("Safe input: ${safeValue}")`);
    res.send('Executed safely');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req, res) {
    const allowedFunctions = {
        add: (a, b) => a + b,
        subtract: (a, b) => a - b,
        multiply: (a, b) => a * b,
        divide: (a, b) => a / b
    };
    
    const operation = req.query.operation;
    const a = parseInt(req.query.a, 10);
    const b = parseInt(req.query.b, 10);
    
    // ok: javascript-code-injection
    if (allowedFunctions.hasOwnProperty(operation)) {
        const result = allowedFunctions[operation](a, b);
        res.json({ result });
    } else {
        res.status(400).send('Invalid operation');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req, res) {
    const userTemplate = req.body.template;
    // ok: javascript-code-injection
    const sanitizedTemplate = DOMPurify.sanitize(userTemplate);
    const element = document.createElement('div');
    element.innerHTML = sanitizedTemplate;
    res.send('Template rendered safely');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req, res) {
    const expression = req.query.expr;
    // ok: javascript-code-injection
    const safeContext = { Math: Math, Date: Date };
    const sandbox = vm.createContext(safeContext);
    try {
        const result = vm.runInContext(expression, sandbox, { timeout: 1000 });
        res.json({ result });
    } catch (error) {
        res.status(400).send('Invalid expression');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req, res) {
    const userHtml = req.body.html;
    // ok: javascript-code-injection
    const clean = sanitizeHtml(userHtml, {
        allowedTags: ['b', 'i', 'em', 'strong', 'p'],
        allowedAttributes: {}
    });
    res.send(clean);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req, res) {
    const scriptUrl = req.query.scriptUrl;
    const allowedDomains = ['trusted-cdn.com', 'company-scripts.org'];
    
    try {
        const url = new URL(scriptUrl);
        // ok: javascript-code-injection
        if (allowedDomains.includes(url.hostname)) {
            const script = document.createElement('script');
            script.src = scriptUrl;
            document.body.appendChild(script);
            res.send('Script added from trusted domain');
        } else {
            res.status(403).send('Domain not allowed');
        }
    } catch (e) {
        res.status(400).send('Invalid URL');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req, res) {
    const userCommand = req.body.command;
    const allowedCommands = ['help', 'status', 'version'];
    
    // ok: javascript-code-injection
    if (allowedCommands.includes(userCommand)) {
        const result = executeCommand(userCommand);
        res.json({ result });
    } else {
        res.status(403).send('Command not allowed');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req, res) {
    const formula = req.body.formula;
    // ok: javascript-code-injection
    if (/^[\d+\-*/().]+$/.test(formula)) {
        const calculator = new Function('return ' + formula);
        const result = calculator();
        res.json({ result });
    } else {
        res.status(400).send('Invalid formula');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req, res) {
    const eventName = req.query.event;
    const allowedEvents = ['click', 'mouseover', 'mouseout'];
    const element = document.getElementById('target');
    
    // ok: javascript-code-injection
    if (allowedEvents.includes(eventName)) {
        element.addEventListener(eventName, () => {
            console.log(`Event ${eventName} triggered`);
        });
        res.send('Event handler set');
    } else {
        res.status(400).send('Event not allowed');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req, res) {
    const template = req.body.template;
    const data = {
        user: {
            name: req.body.name,
            role: req.body.role
        }
    };
    
    // ok: javascript-code-injection
    const handlebars = require('handlebars');
    const compiledTemplate = handlebars.compile(template);
    const result = compiledTemplate(data);
    res.send(result);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req, res) {
    const userInput = req.query.input;
    
    // ok: javascript-code-injection
    console.log(`User provided: ${userInput}`);
    res.send('Input logged safely');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req, res) {
    const code = req.body.code;
    // ok: javascript-code-injection
    try {
        const ast = require('acorn').parse(code, { ecmaVersion: 2020 });
        // Process AST safely instead of executing the code
        const analysis = analyzeAst(ast);
        res.json(analysis);
    } catch (error) {
        res.status(400).send('Invalid code');
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req, res) {
    const scriptContent = req.query.script;
    // ok: javascript-code-injection
    // Instead of executing, store it for review
    const fs = require('fs');
    const path = require('path');
    const filename = path.join(__dirname, 'scripts', Date.now() + '.js');
    fs.writeFileSync(filename, `// Pending review\n${scriptContent}`);
    res.send('Script submitted for review');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req, res) {
    const userConfig = JSON.parse(req.body.config);
    // ok: javascript-code-injection
    const safeConfig = {
        theme: userConfig.theme || 'default',
        fontSize: parseInt(userConfig.fontSize, 10) || 12,
        showToolbar: Boolean(userConfig.showToolbar)
    };
    
    applyConfiguration(safeConfig);
    res.send('Configuration applied');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req, res) {
    const expression = req.query.expr;
    // ok: javascript-code-injection
    const mathjs = require('mathjs');
    try {
        const result = mathjs.evaluate(expression);
        res.json({ result });
    } catch (error) {
        res.status(400).send('Invalid math expression');
    }
}
// {/fact}

// Helper functions
function executeCommand(cmd) {
    // Implementation for good_case_7
    return `Executed: ${cmd}`;
}

function analyzeAst(ast) {
    // Implementation for good_case_12
    return { nodeCount: ast.body.length, type: 'Program' };
}

function applyConfiguration(config) {
    // Implementation for good_case_14
    console.log('Applied configuration:', config);
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});