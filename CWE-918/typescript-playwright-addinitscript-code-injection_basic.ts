import { chromium, firefox, webkit } from 'playwright';
import express from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Basic user input directly passed to addInitScript
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1() {
    const app = express();
    app.get('/launch-browser', async (req, res) => {
        const userScript = req.query.script as string;
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(userScript);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Browser launched');
    });
    app.listen(3000);
}
// {/fact}

// Example 2: User input passed via template literal
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2() {
    const app = express();
    app.get('/execute-script', async (req, res) => {
        const userInput = req.query.input as string;
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`console.log("User input: ${userInput}");`);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Script executed');
    });
    app.listen(3001);
}
// {/fact}

// Example 3: User input from POST body
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3() {
    const app = express();
    app.use(express.json());
    app.post('/run-script', async (req, res) => {
        const scriptContent = req.body.script;
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Script executed');
    });
    app.listen(3002);
}
// {/fact}

// Example 4: User input from HTTP header
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4() {
    const app = express();
    app.get('/header-script', async (req, res) => {
        const scriptFromHeader = req.headers['x-custom-script'] as string;
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptFromHeader);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Script from header executed');
    });
    app.listen(3003);
}
// {/fact}

// Example 5: User input with minimal processing
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5() {
    const app = express();
    app.get('/process-script', async (req, res) => {
        let userScript = req.query.code as string;
        userScript = userScript.replace(/^\s+|\s+$/g, ''); // Just trim whitespace
        
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(userScript);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Processed script executed');
    });
    app.listen(3004);
}
// {/fact}

// Example 6: User input from cookie
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6() {
    const app = express();
    app.use(express.json());
    app.get('/cookie-script', async (req, res) => {
        const scriptFromCookie = req.cookies.userScript;
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptFromCookie);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Script from cookie executed');
    });
    app.listen(3005);
}
// {/fact}

// Example 7: User input with conditional logic
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7() {
    const app = express();
    app.get('/conditional-script', async (req, res) => {
        const userScript = req.query.script as string;
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        if (userScript && userScript.length > 0) {
            // ruleid: playwright-addinitscript-code-injection-ts-rule
            await context.addInitScript(userScript);
        } else {
            await context.addInitScript('console.log("Default script")');
        }
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Conditional script executed');
    });
    app.listen(3006);
}
// {/fact}

// Example 8: User input from URL parameter with string concatenation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8() {
    const app = express();
    app.get('/concat-script', async (req, res) => {
        const userParam = req.query.param as string;
        const scriptContent = 'console.log("Parameter: ' + userParam + '");';
        
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Concatenated script executed');
    });
    app.listen(3007);
}
// {/fact}

// Example 9: User input with object path
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9() {
    const app = express();
    app.use(express.json());
    app.post('/object-script', async (req, res) => {
        const scriptContent = req.body.config.scripts.init;
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Object script executed');
    });
    app.listen(3008);
}
// {/fact}

// Example 10: User input from query with array access
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10() {
    const app = express();
    app.get('/array-script', async (req, res) => {
        const scripts = req.query.scripts as string[];
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        if (scripts && scripts.length > 0) {
            // ruleid: playwright-addinitscript-code-injection-ts-rule
            await context.addInitScript(scripts[0]);
        }
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Array script executed');
    });
    app.listen(3009);
}
// {/fact}

// Example 11: User input with async/await flow
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11() {
    const app = express();
    app.get('/async-script', async (req, res) => {
        const userInput = req.query.input as string;
        
        const fetchData = async () => {
            return new Promise<string>(resolve => {
                setTimeout(() => resolve(userInput), 100);
            });
        };
        
        const scriptContent = await fetchData();
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Async script executed');
    });
    app.listen(3010);
}
// {/fact}

// Example 12: User input with try/catch
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12() {
    const app = express();
    app.get('/try-catch-script', async (req, res) => {
        try {
            const userScript = req.query.script as string;
            const browser = await webkit.launch();
            const context = await browser.newContext();
            
            // ruleid: playwright-addinitscript-code-injection-ts-rule
            await context.addInitScript(userScript);
            
            const page = await context.newPage();
            await page.goto('https://example.com');
            res.send('Script executed with try/catch');
        } catch (error) {
            res.status(500).send('Error executing script');
        }
    });
    app.listen(3011);
}
// {/fact}

// Example 13: User input with switch statement
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13() {
    const app = express();
    app.get('/switch-script', async (req, res) => {
        const scriptType = req.query.type as string;
        const scriptContent = req.query.content as string;
        
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        switch (scriptType) {
            case 'log':
                // ruleid: playwright-addinitscript-code-injection-ts-rule
                await context.addInitScript(`console.log(${scriptContent});`);
                break;
            case 'alert':
                // ruleid: playwright-addinitscript-code-injection-ts-rule
                await context.addInitScript(`alert(${scriptContent});`);
                break;
            default:
                // ruleid: playwright-addinitscript-code-injection-ts-rule
                await context.addInitScript(scriptContent);
        }
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Switch script executed');
    });
    app.listen(3012);
}
// {/fact}

// Example 14: User input with HTTP request to get script
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14() {
    const app = express();
    app.get('/http-script', async (req, res) => {
        const scriptUrl = req.query.url as string;
        
        const fetchScript = async (url: string): Promise<string> => {
            return new Promise((resolve, reject) => {
                https.get(url, (response) => {
                    let data = '';
                    response.on('data', (chunk) => {
                        data += chunk;
                    });
                    response.on('end', () => {
                        resolve(data);
                    });
                }).on('error', (err) => {
                    reject(err);
                });
            });
        };
        
        try {
            const scriptContent = await fetchScript(scriptUrl);
            const browser = await firefox.launch();
            const context = await browser.newContext();
            
            // ruleid: playwright-addinitscript-code-injection-ts-rule
            await context.addInitScript(scriptContent);
            
            const page = await context.newPage();
            await page.goto('https://example.com');
            res.send('HTTP script executed');
        } catch (error) {
            res.status(500).send('Error fetching script');
        }
    });
    app.listen(3013);
}
// {/fact}

// Example 15: User input with function path
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15() {
    const app = express();
    app.use(express.json());
    app.post('/function-script', async (req, res) => {
        const scriptPath = req.body.path;
        const scriptContent = getScriptByPath(scriptPath, req.body);
        
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Function path script executed');
    });
    
    function getScriptByPath(path: string, data: any): string {
        let result = '';
        const parts = path.split('.');
        let current = data;
        
        for (const part of parts) {
            if (current[part]) {
                current = current[part];
            } else {
                return '';
            }
        }
        
        return current as string;
    }
    
    app.listen(3014);
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Example 1: Using hardcoded script
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1() {
    const app = express();
    app.get('/safe-script', async (req, res) => {
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript('console.log("This is a safe hardcoded script")');
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Safe script executed');
    });
    app.listen(4000);
}
// {/fact}

// Example 2: Using script from a trusted file
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2() {
    const fs = require('fs');
    const path = require('path');
    
    const app = express();
    app.get('/file-script', async (req, res) => {
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        const scriptContent = fs.readFileSync(path.join(__dirname, 'trusted-scripts', 'init.js'), 'utf8');
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('File script executed');
    });
    app.listen(4001);
}
// {/fact}

// Example 3: Using a function for the script
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3() {
    const app = express();
    app.get('/function-safe-script', async (req, res) => {
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(() => {
            console.log('This is a safe function script');
            document.title = 'Modified by script';
        });
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Function script executed');
    });
    app.listen(4002);
}
// {/fact}

// Example 4: Using script with sanitized user input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4() {
    const app = express();
    app.get('/sanitized-script', async (req, res) => {
        const userName = req.query.name as string;
        const sanitizedName = userName ? userName.replace(/[^\w\s]/g, '') : 'Guest';
        
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we sanitized the input
            document.getElementById('greeting').textContent = 'Hello, ${sanitizedName}!';
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Sanitized script executed');
    });
    app.listen(4003);
}
// {/fact}

// Example 5: Using a predefined script template with safe parameter insertion
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5() {
    const app = express();
    app.get('/template-script', async (req, res) => {
        const count = parseInt(req.query.count as string) || 5;
        const safeCount = Math.min(Math.max(count, 1), 10); // Limit between 1 and 10
        
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we validated the numeric input
            for (let i = 0; i < ${safeCount}; i++) {
                console.log('Iteration ' + i);
            }
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Template script executed');
    });
    app.listen(4004);
}
// {/fact}

// Example 6: Using a script with environment variables
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6() {
    const app = express();
    app.get('/env-script', async (req, res) => {
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            console.log('Running in ${process.env.NODE_ENV || 'development'} mode');
            document.title = '${process.env.APP_TITLE || 'Default Title'}';
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Environment script executed');
    });
    app.listen(4005);
}
// {/fact}

// Example 7: Using a script from a trusted configuration
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7() {
    const app = express();
    app.get('/config-script', async (req, res) => {
        const config = {
            scripts: {
                init: 'console.log("Initialized from trusted config");'
            }
        };
        
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(config.scripts.init);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Config script executed');
    });
    app.listen(4006);
}
// {/fact}

// Example 8: Using a script with safe JSON stringification
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8() {
    const app = express();
    app.get('/json-script', async (req, res) => {
        const userPreferences = {
            theme: req.query.theme || 'light',
            fontSize: parseInt(req.query.fontSize as string) || 16
        };
        
        // Validate theme
        if (!['light', 'dark', 'blue'].includes(userPreferences.theme as string)) {
            userPreferences.theme = 'light';
        }
        
        // Validate fontSize
        if (userPreferences.fontSize < 12 || userPreferences.fontSize > 24) {
            userPreferences.fontSize = 16;
        }
        
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we validated all inputs
            const preferences = ${JSON.stringify(userPreferences)};
            document.body.classList.add(preferences.theme);
            document.body.style.fontSize = preferences.fontSize + 'px';
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('JSON script executed');
    });
    app.listen(4007);
}
// {/fact}

// Example 9: Using a script with whitelisted options
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9() {
    const app = express();
    app.get('/whitelist-script', async (req, res) => {
        const requestedAction = req.query.action as string;
        
        // Whitelist of allowed actions
        const allowedActions: Record<string, string> = {
            'highlight': 'document.body.style.backgroundColor = "yellow";',
            'enlarge': 'document.body.style.fontSize = "1.2em";',
            'reset': 'document.body.style = null;'
        };
        
        const scriptToRun = allowedActions[requestedAction] || allowedActions['reset'];
        
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptToRun);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Whitelisted script executed');
    });
    app.listen(4008);
}
// {/fact}

// Example 10: Using a script with proper input validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10() {
    const app = express();
    app.get('/validated-script', async (req, res) => {
        const userId = req.query.id as string;
        
        // Validate userId is a number
        if (!/^\d+$/.test(userId)) {
            res.status(400).send('Invalid user ID');
            return;
        }
        
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we validated the ID is numeric
            console.log('Loading data for user ${userId}');
            document.getElementById('user-id').textContent = '${userId}';
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Validated script executed');
    });
    app.listen(4009);
}
// {/fact}

// Example 11: Using a script with boolean flags
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11() {
    const app = express();
    app.get('/boolean-script', async (req, res) => {
        const enableFeature = req.query.enable === 'true';
        
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we're only using a boolean value
            window.featureEnabled = ${enableFeature};
            console.log('Feature enabled: ' + ${enableFeature});
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Boolean script executed');
    });
    app.listen(4010);
}
// {/fact}

// Example 12: Using a script with numeric validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12() {
    const app = express();
    app.get('/numeric-script', async (req, res) => {
        let timeout = parseInt(req.query.timeout as string);
        
        // Validate and set bounds
        if (isNaN(timeout) || timeout < 100 || timeout > 5000) {
            timeout = 1000; // Default value
        }
        
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we validated the numeric input
            setTimeout(() => {
                console.log('Timeout completed');
            }, ${timeout});
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Numeric script executed');
    });
    app.listen(4011);
}
// {/fact}

// Example 13: Using a script with enum validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13() {
    const app = express();
    app.get('/enum-script', async (req, res) => {
        const requestedColor = req.query.color as string;
        
        // Validate color is in allowed list
        const allowedColors = ['red', 'green', 'blue', 'yellow'];
        const color = allowedColors.includes(requestedColor) ? requestedColor : 'blue';
        
        const browser = await chromium.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we validated against an enum
            document.body.style.backgroundColor = '${color}';
            console.log('Color set to: ${color}');
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Enum script executed');
    });
    app.listen(4012);
}
// {/fact}

// Example 14: Using a script with path validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14() {
    const app = express();
    app.get('/path-script', async (req, res) => {
        const requestedPath = req.query.path as string;
        
        // Validate path is alphanumeric with limited special chars
        if (!/^[a-zA-Z0-9_\-\/]+$/.test(requestedPath)) {
            res.status(400).send('Invalid path');
            return;
        }
        
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we validated the path format
            console.log('Loading resource from: ${requestedPath}');
            fetch('https://example.com/api/${requestedPath}')
                .then(response => console.log('Resource loaded'));
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Path script executed');
    });
    app.listen(4013);
}
// {/fact}

// Example 15: Using a script with object path validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15() {
    const app = express();
    app.use(express.json());
    app.post('/object-safe-script', async (req, res) => {
        const configPath = req.body.path;
        
        // Validate path is a string and has limited depth
        if (typeof configPath !== 'string' || configPath.split('.').length > 3) {
            res.status(400).send('Invalid configuration path');
            return;
        }
        
        // Whitelist of allowed configuration paths
        const allowedPaths = ['ui.theme', 'ui.language', 'features.enabled'];
        if (!allowedPaths.includes(configPath)) {
            res.status(400).send('Unauthorized configuration path');
            return;
        }
        
        const browser = await webkit.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            // This is safe because we validated against a whitelist
            console.log('Setting configuration for: ${configPath}');
            // Implementation would set the configuration safely
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Object path script executed safely');
    });
    app.listen(4014);
}
// {/fact}