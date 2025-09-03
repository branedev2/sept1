import { chromium, firefox, webkit, Browser, Page } from 'playwright';
import express from 'express';
import http from 'http';
import axios from 'axios';

// True Positive Examples (Vulnerable Code)

// Example 1: Basic evaluate with user input from query parameter
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1() {
    const app = express();
    app.get('/screenshot', async (req, res) => {
        const userScript = req.query.script as string;
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(userScript);
        
        res.json({ result });
        await browser.close();
    });
    app.listen(3000);
}
// {/fact}

// Example 2: Using evaluateHandle with user input from POST body
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2() {
    const app = express();
    app.use(express.json());
    app.post('/execute', async (req, res) => {
        const userCode = req.body.code;
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const jsHandle = await page.evaluateHandle(userCode);
        
        const result = await jsHandle.jsonValue();
        res.json({ result });
        await browser.close();
    });
    app.listen(3001);
}
// {/fact}

// Example 3: Using evaluate with template literal containing user input
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3() {
    const app = express();
    app.get('/run-script', async (req, res) => {
        const userInput = req.query.input as string;
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(`
            const data = "${userInput}";
            return document.querySelector(data);
        `);
        
        res.send({ result });
        await browser.close();
    });
    app.listen(3002);
}
// {/fact}

// Example 4: Using evaluateHandle with function and user input as argument
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4() {
    const app = express();
    app.get('/dom-query', async (req, res) => {
        const selector = req.query.selector as string;
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const handle = await page.evaluateHandle((sel) => document.querySelector(sel), selector);
        
        res.send('Done');
        await browser.close();
    });
    app.listen(3003);
}
// {/fact}

// Example 5: Using evaluate with user input from request header
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5() {
    const app = express();
    app.get('/header-exec', async (req, res) => {
        const scriptFromHeader = req.headers['x-custom-script'] as string;
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(scriptFromHeader);
        
        res.json({ success: true });
        await browser.close();
    });
    app.listen(3004);
}
// {/fact}

// Example 6: Using evaluate with user input from cookie
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6() {
    const app = express();
    app.get('/cookie-exec', async (req, res) => {
        const cookieValue = req.cookies.userScript;
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        await page.evaluate(cookieValue);
        
        res.send('Script executed');
        await browser.close();
    });
    app.listen(3005);
}
// {/fact}

// Example 7: Using evaluateHandle with indirect user input after minimal processing
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7() {
    const app = express();
    app.get('/process-exec', async (req, res) => {
        let userScript = req.query.script as string;
        userScript = userScript.replace(/console\.log/g, 'alert');
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const handle = await page.evaluateHandle(userScript);
        
        res.send('Processed and executed');
        await browser.close();
    });
    app.listen(3006);
}
// {/fact}

// Example 8: Using evaluate with user input in a more complex scenario
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8() {
    const app = express();
    app.use(express.json());
    app.post('/complex-exec', async (req, res) => {
        const { selector, attribute, value } = req.body;
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(`
            document.querySelector("${selector}")
                .setAttribute("${attribute}", "${value}");
            return true;
        `);
        
        res.json({ success: result });
        await browser.close();
    });
    app.listen(3007);
}
// {/fact}

// Example 9: Using evaluate with user input in an arrow function
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9() {
    const app = express();
    app.get('/arrow-exec', async (req, res) => {
        const userSelector = req.query.selector as string;
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const count = await page.evaluate((sel) => {
            return document.querySelectorAll(sel).length;
        }, userSelector);
        
        res.json({ count });
        await browser.close();
    });
    app.listen(3008);
}
// {/fact}

// Example 10: Using evaluate with user input after JSON parsing
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10() {
    const app = express();
    app.use(express.json());
    app.post('/json-exec', async (req, res) => {
        const data = JSON.parse(req.body.jsonData);
        const scriptToRun = data.script;
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        await page.evaluate(scriptToRun);
        
        res.send('JSON script executed');
        await browser.close();
    });
    app.listen(3009);
}
// {/fact}

// Example 11: Using evaluate with user input from URL path parameter
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11() {
    const app = express();
    app.get('/path/:script', async (req, res) => {
        const scriptFromPath = req.params.script;
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(scriptFromPath);
        
        res.json({ result });
        await browser.close();
    });
    app.listen(3010);
}
// {/fact}

// Example 12: Using evaluateHandle with user input from a form submission
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12() {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.post('/form-exec', async (req, res) => {
        const formScript = req.body.userScript;
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        await page.evaluateHandle(formScript);
        
        res.send('Form script executed');
        await browser.close();
    });
    app.listen(3011);
}
// {/fact}

// Example 13: Using evaluate with user input after concatenation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13() {
    const app = express();
    app.get('/concat-exec', async (req, res) => {
        const part1 = req.query.part1 as string;
        const part2 = req.query.part2 as string;
        const fullScript = part1 + part2;
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        await page.evaluate(fullScript);
        
        res.send('Concatenated script executed');
        await browser.close();
    });
    app.listen(3012);
}
// {/fact}

// Example 14: Using evaluate with user input from external API
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14() {
    const app = express();
    app.get('/api-exec', async (req, res) => {
        const apiUrl = req.query.apiUrl as string;
        const response = await axios.get(apiUrl);
        const scriptFromApi = response.data.script;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        await page.evaluate(scriptFromApi);
        
        res.send('API script executed');
        await browser.close();
    });
    app.listen(3013);
}
// {/fact}

// Example 15: Using evaluate with user input in a conditional flow
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15() {
    const app = express();
    app.get('/conditional-exec', async (req, res) => {
        const userInput = req.query.input as string;
        let scriptToRun;
        
        if (userInput.startsWith('query:')) {
            scriptToRun = userInput.substring(6);
        } else {
            scriptToRun = `console.log("${userInput}")`;
        }
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        await page.evaluate(scriptToRun);
        
        res.send('Conditional script executed');
        await browser.close();
    });
    app.listen(3014);
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using evaluate with hardcoded script
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1() {
    const app = express();
    app.get('/safe-screenshot', async (req, res) => {
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(() => {
            return document.title;
        });
        
        res.json({ title: result });
        await browser.close();
    });
    app.listen(4000);
}
// {/fact}

// Example 2: Using evaluateHandle with hardcoded script
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2() {
    const app = express();
    app.get('/safe-handle', async (req, res) => {
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const jsHandle = await page.evaluateHandle(() => document.body);
        
        const result = await jsHandle.jsonValue();
        res.json({ result });
        await browser.close();
    });
    app.listen(4001);
}
// {/fact}

// Example 3: Using evaluate with sanitized user input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3() {
    const app = express();
    app.get('/safe-selector', async (req, res) => {
        let userSelector = req.query.selector as string;
        
        // Sanitize by only allowing specific safe selectors
        const allowedSelectors = ['h1', 'p', 'div', 'span', 'a'];
        if (!allowedSelectors.includes(userSelector)) {
            userSelector = 'body';
        }
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const count = await page.evaluate((sel) => {
            return document.querySelectorAll(sel).length;
        }, userSelector);
        
        res.json({ count });
        await browser.close();
    });
    app.listen(4002);
}
// {/fact}

// Example 4: Using evaluate with validated numeric input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4() {
    const app = express();
    app.get('/safe-numeric', async (req, res) => {
        let userValue = req.query.value as string;
        const numValue = parseInt(userValue, 10);
        
        // Validate it's a proper number
        if (isNaN(numValue)) {
            return res.status(400).send('Invalid number');
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate((num) => {
            return Array(num).fill(0).map((_, i) => i);
        }, numValue);
        
        res.json({ result });
        await browser.close();
    });
    app.listen(4003);
}
// {/fact}

// Example 5: Using evaluate with hardcoded function and safe parameter passing
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5() {
    const app = express();
    app.get('/safe-param', async (req, res) => {
        const userColor = req.query.color as string;
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        await page.evaluate((color) => {
            document.body.style.backgroundColor = color;
        }, userColor);
        
        res.send('Color applied');
        await browser.close();
    });
    app.listen(4004);
}
// {/fact}

// Example 6: Using evaluate with strict validation for user input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6() {
    const app = express();
    app.get('/safe-validation', async (req, res) => {
        const userOption = req.query.option as string;
        
        // Strict validation
        if (!/^[a-zA-Z0-9]+$/.test(userOption)) {
            return res.status(400).send('Invalid option format');
        }
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate((opt) => {
            const element = document.getElementById(opt);
            return element ? element.textContent : null;
        }, userOption);
        
        res.json({ result });
        await browser.close();
    });
    app.listen(4005);
}
// {/fact}

// Example 7: Using evaluate with enum-based input validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7() {
    const app = express();
    app.get('/safe-enum', async (req, res) => {
        const userAction = req.query.action as string;
        
        // Validate against allowed actions
        const allowedActions = ['click', 'hover', 'focus'];
        if (!allowedActions.includes(userAction)) {
            return res.status(400).send('Invalid action');
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        await page.evaluate((action) => {
            const button = document.querySelector('button');
            if (button) {
                if (action === 'click') button.click();
                else if (action === 'hover') button.dispatchEvent(new MouseEvent('mouseover'));
                else if (action === 'focus') button.focus();
            }
        }, userAction);
        
        res.send('Action performed');
        await browser.close();
    });
    app.listen(4006);
}
// {/fact}

// Example 8: Using evaluate with hardcoded script and no user input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8() {
    const app = express();
    app.get('/safe-fixed', async (req, res) => {
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const metrics = await page.evaluate(() => {
            return {
                width: document.documentElement.clientWidth,
                height: document.documentElement.clientHeight,
                devicePixelRatio: window.devicePixelRatio
            };
        });
        
        res.json(metrics);
        await browser.close();
    });
    app.listen(4007);
}
// {/fact}

// Example 9: Using evaluateHandle with safe object parameter
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9() {
    const app = express();
    app.use(express.json());
    app.post('/safe-object', async (req, res) => {
        const userConfig = {
            x: parseInt(req.body.x) || 0,
            y: parseInt(req.body.y) || 0,
            color: req.body.color || 'black'
        };
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        await page.evaluateHandle((config) => {
            const div = document.createElement('div');
            div.style.position = 'absolute';
            div.style.left = `${config.x}px`;
            div.style.top = `${config.y}px`;
            div.style.backgroundColor = config.color;
            div.style.width = '100px';
            div.style.height = '100px';
            document.body.appendChild(div);
        }, userConfig);
        
        res.send('Element created');
        await browser.close();
    });
    app.listen(4008);
}
// {/fact}

// Example 10: Using evaluate with safe JSON parameter
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10() {
    const app = express();
    app.use(express.json());
    app.post('/safe-json', async (req, res) => {
        // Extract and validate user data
        const userData = {
            name: String(req.body.name || ''),
            age: Number(req.body.age || 0),
            email: String(req.body.email || '')
        };
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate((data) => {
            const userDiv = document.createElement('div');
            userDiv.textContent = `Name: ${data.name}, Age: ${data.age}, Email: ${data.email}`;
            document.body.appendChild(userDiv);
            return true;
        }, userData);
        
        res.json({ success: result });
        await browser.close();
    });
    app.listen(4009);
}
// {/fact}

// Example 11: Using evaluate with safe array parameter
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11() {
    const app = express();
    app.get('/safe-array', async (req, res) => {
        const userItems = (req.query.items as string || '').split(',')
            .map(item => item.trim())
            .filter(item => item.length > 0);
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate((items) => {
            const list = document.createElement('ul');
            items.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                list.appendChild(li);
            });
            document.body.appendChild(list);
            return items.length;
        }, userItems);
        
        res.json({ count: result });
        await browser.close();
    });
    app.listen(4010);
}
// {/fact}

// Example 12: Using evaluate with safe boolean parameter
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12() {
    const app = express();
    app.get('/safe-boolean', async (req, res) => {
        const showDetails = req.query.details === 'true';
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const content = await page.evaluate((showAll) => {
            if (showAll) {
                return document.documentElement.outerHTML;
            } else {
                return document.title;
            }
        }, showDetails);
        
        res.send(content);
        await browser.close();
    });
    app.listen(4011);
}
// {/fact}

// Example 13: Using evaluate with safe numeric array parameter
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13() {
    const app = express();
    app.get('/safe-numeric-array', async (req, res) => {
        const userValues = (req.query.values as string || '').split(',')
            .map(val => parseInt(val, 10))
            .filter(val => !isNaN(val));
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const sum = await page.evaluate((nums) => {
            return nums.reduce((a, b) => a + b, 0);
        }, userValues);
        
        res.json({ sum });
        await browser.close();
    });
    app.listen(4012);
}
// {/fact}

// Example 14: Using evaluate with safe date parameter
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14() {
    const app = express();
    app.get('/safe-date', async (req, res) => {
        const userDateStr = req.query.date as string;
        const userDate = new Date(userDateStr);
        
        // Validate date
        if (isNaN(userDate.getTime())) {
            return res.status(400).send('Invalid date');
        }
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const formatted = await page.evaluate((date) => {
            return new Date(date).toLocaleDateString();
        }, userDate.toISOString());
        
        res.json({ formatted });
        await browser.close();
    });
    app.listen(4013);
}
// {/fact}

// Example 15: Using evaluate with safe regex pattern
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15() {
    const app = express();
    app.get('/safe-regex', async (req, res) => {
        let userPattern = req.query.pattern as string;
        
        try {
            // Test if it's a valid regex
            new RegExp(userPattern);
        } catch (e) {
            userPattern = '.*'; // Default safe pattern
        }
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const matches = await page.evaluate((pattern) => {
            const regex = new RegExp(pattern);
            const text = document.body.textContent || '';
            return text.match(regex) || [];
        }, userPattern);
        
        res.json({ matches });
        await browser.close();
    });
    app.listen(4014);
}
// {/fact}