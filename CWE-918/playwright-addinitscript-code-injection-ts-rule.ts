import { chromium, firefox, webkit, Browser, BrowserContext, Page } from 'playwright';
import express from 'express';
import http from 'http';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

// True Positives (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Get user input from query parameter
    const app = express();
    app.get('/execute', async (req, res) => {
        const userScript = req.query.script as string;
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(userScript);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Script executed');
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2() {
    const browser = await webkit.launch();
    const page = await browser.newPage();
    
    // Get user input from request body
    const app = express();
    app.post('/inject', express.json(), async (req, res) => {
        const userCode = req.body.code;
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript({
            content: userCode
        });
        
        await page.goto('https://example.com');
        res.send('Code injected');
    });
    
    app.listen(3001);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3() {
    // Get user input from URL parameter and use it in a browser context
    const app = express();
    app.get('/browser-script', async (req, res) => {
        const scriptContent = req.query.content as string;
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Browser script added');
    });
    
    app.listen(3002);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Get user input from HTTP headers
    const app = express();
    app.get('/header-script', async (req, res) => {
        const scriptContent = req.headers['x-custom-script'] as string;
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript({
            content: scriptContent
        });
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Script from header added');
    });
    
    app.listen(3003);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5() {
    // Get user input from cookies
    const app = express();
    app.get('/cookie-script', async (req, res) => {
        const scriptContent = req.cookies.userScript;
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(scriptContent);
        
        await page.goto('https://example.com');
        res.send('Script from cookie added');
    });
    
    app.listen(3004);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Get user input from POST request
    const app = express();
    app.post('/script-path', express.json(), async (req, res) => {
        const scriptPath = req.body.path;
        const scriptContent = fs.readFileSync(scriptPath, 'utf8');
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Script loaded from path');
    });
    
    app.listen(3005);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7() {
    // Fetch script from user-provided URL
    const app = express();
    app.get('/remote-script', async (req, res) => {
        const scriptUrl = req.query.url as string;
        const response = await axios.get(scriptUrl);
        const scriptContent = response.data;
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(scriptContent);
        
        await page.goto('https://example.com');
        res.send('Remote script added');
    });
    
    app.listen(3006);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Get user input from query parameter with minimal processing
    const app = express();
    app.get('/script-with-prefix', async (req, res) => {
        const userScript = req.query.script as string;
        const scriptWithPrefix = `console.log("Prefixed:"); ${userScript}`;
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptWithPrefix);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Prefixed script executed');
    });
    
    app.listen(3007);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9() {
    // Process multiple user inputs into a script
    const app = express();
    app.post('/combined-script', express.json(), async (req, res) => {
        const { varName, varValue, additionalCode } = req.body;
        const combinedScript = `let ${varName} = "${varValue}"; ${additionalCode}`;
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript({
            content: combinedScript
        });
        
        await page.goto('https://example.com');
        res.send('Combined script added');
    });
    
    app.listen(3008);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Get user input from query parameter with conditional logic
    const app = express();
    app.get('/conditional-script', async (req, res) => {
        const userScript = req.query.script as string;
        let finalScript = userScript;
        
        if (req.query.debug === 'true') {
            finalScript = `console.debug("Debug mode:"); ${finalScript}`;
        }
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(finalScript);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Conditional script executed');
    });
    
    app.listen(3009);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11() {
    // Use user input in a script object
    const app = express();
    app.post('/script-object', express.json(), async (req, res) => {
        const { scriptContent } = req.body;
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript({
            content: scriptContent
        });
        
        await page.goto('https://example.com');
        res.send('Script object added');
    });
    
    app.listen(3010);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Get user input from a custom request parameter
    const app = express();
    app.get('/custom-param-script', async (req, res) => {
        const customParam = req.query.customParam as string;
        const base64Script = Buffer.from(customParam, 'base64').toString('utf-8');
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(base64Script);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Base64 decoded script executed');
    });
    
    app.listen(3011);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13() {
    // Use user input in a function that eventually calls addInitScript
    const app = express();
    app.post('/indirect-script', express.json(), async (req, res) => {
        const { code } = req.body;
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        const injectCode = (scriptContent: string) => {
            // ruleid: playwright-addinitscript-code-injection-ts-rule
            return page.addInitScript(scriptContent);
        };
        
        await injectCode(code);
        await page.goto('https://example.com');
        res.send('Indirect script added');
    });
    
    app.listen(3012);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Get user input from URL fragment
    const app = express();
    app.get('/fragment-script', async (req, res) => {
        const fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
        const fragment = new URL(fullUrl).hash.substring(1); // Remove the # character
        const decodedFragment = decodeURIComponent(fragment);
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(decodedFragment);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Fragment script executed');
    });
    
    app.listen(3013);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15() {
    // Use user input from multiple sources combined
    const app = express();
    app.post('/multi-source-script', express.json(), async (req, res) => {
        const headerScript = req.headers['x-script-header'] as string;
        const bodyScript = req.body.script;
        const queryScript = req.query.script as string;
        
        const combinedScript = `${headerScript || ''}; ${bodyScript || ''}; ${queryScript || ''}`;
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(combinedScript);
        
        await page.goto('https://example.com');
        res.send('Multi-source script added');
    });
    
    app.listen(3014);
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Using hardcoded script instead of user input
    const app = express();
    app.get('/safe-execute', async (req, res) => {
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`console.log("This is a safe hardcoded script");`);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Safe script executed');
    });
    
    app.listen(4000);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2() {
    const browser = await webkit.launch();
    const page = await browser.newPage();
    
    // Using a predefined script object
    const app = express();
    app.post('/safe-inject', express.json(), async (req, res) => {
        // ok: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript({
            content: `document.addEventListener('DOMContentLoaded', () => {
                console.log('Page loaded safely');
            });`
        });
        
        await page.goto('https://example.com');
        res.send('Safe code injected');
    });
    
    app.listen(4001);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3() {
    // Using a script from a trusted file
    const app = express();
    app.get('/safe-browser-script', async (req, res) => {
        const scriptContent = fs.readFileSync(path.join(__dirname, 'trusted-scripts', 'init.js'), 'utf8');
        const browser = await firefox.launch();
        const context = await browser.newContext();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(scriptContent);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Safe browser script added');
    });
    
    app.listen(4002);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Using a function reference instead of a string
    const app = express();
    app.get('/safe-function-script', async (req, res) => {
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(() => {
            window.addEventListener('load', () => {
                console.log('Page loaded via function script');
            });
        });
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send('Safe function script added');
    });
    
    app.listen(4003);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5() {
    // Using a predefined script with parameters
    const app = express();
    app.get('/safe-parameterized-script', async (req, res) => {
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        const safeValue = "Hello, world!";
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(params => {
            window.myValue = params.value;
            console.log(`Initialized with: ${params.value}`);
        }, { value: safeValue });
        
        await page.goto('https://example.com');
        res.send('Safe parameterized script added');
    });
    
    app.listen(4004);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Using a script from a predefined set
    const app = express();
    app.post('/safe-script-selection', express.json(), async (req, res) => {
        const scriptType = req.body.type;
        
        const safeScripts = {
            logger: `console.log('Logging initialized');`,
            tracker: `console.log('Tracking initialized');`,
            helper: `console.log('Helper functions initialized');`
        };
        
        if (scriptType && scriptType in safeScripts) {
            // ok: playwright-addinitscript-code-injection-ts-rule
            await context.addInitScript(safeScripts[scriptType as keyof typeof safeScripts]);
            
            const page = await context.newPage();
            await page.goto('https://example.com');
            res.send(`Safe ${scriptType} script added`);
        } else {
            res.status(400).send('Invalid script type');
        }
    });
    
    app.listen(4005);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7() {
    // Using a script from a trusted module
    const app = express();
    app.get('/safe-module-script', async (req, res) => {
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // Import a trusted script module
        const trustedModule = require('./trusted-scripts/module');
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(trustedModule.getInitScript());
        
        await page.goto('https://example.com');
        res.send('Safe module script added');
    });
    
    app.listen(4006);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Using a script with safe user configuration
    const app = express();
    app.get('/safe-configured-script', async (req, res) => {
        const theme = req.query.theme as string;
        const allowedThemes = ['light', 'dark', 'blue'];
        
        if (theme && allowedThemes.includes(theme)) {
            // ok: playwright-addinitscript-code-injection-ts-rule
            await context.addInitScript(`
                document.addEventListener('DOMContentLoaded', () => {
                    document.body.classList.add('theme-${theme}');
                });
            `);
            
            const page = await context.newPage();
            await page.goto('https://example.com');
            res.send(`Safe configured script with theme ${theme} added`);
        } else {
            res.status(400).send('Invalid theme');
        }
    });
    
    app.listen(4007);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9() {
    // Using a script with safe numeric configuration
    const app = express();
    app.post('/safe-numeric-script', express.json(), async (req, res) => {
        let refreshInterval = parseInt(req.body.refreshInterval as string);
        
        // Validate and sanitize the input
        if (isNaN(refreshInterval) || refreshInterval < 1000) {
            refreshInterval = 5000; // Default safe value
        }
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(`
            setInterval(() => {
                console.log('Refreshing content...');
                // Refresh logic here
            }, ${refreshInterval});
        `);
        
        await page.goto('https://example.com');
        res.send(`Safe script with ${refreshInterval}ms refresh interval added`);
    });
    
    app.listen(4008);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Using a script with safe boolean configuration
    const app = express();
    app.get('/safe-boolean-script', async (req, res) => {
        const debugMode = req.query.debug === 'true';
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            window.DEBUG_MODE = ${debugMode};
            if (window.DEBUG_MODE) {
                console.log('Debug mode enabled');
            }
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send(`Safe script with debug mode ${debugMode ? 'enabled' : 'disabled'} added`);
    });
    
    app.listen(4009);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11() {
    // Using a script with safe JSON configuration
    const app = express();
    app.post('/safe-json-script', express.json(), async (req, res) => {
        const config = {
            enableLogging: req.body.logging === true,
            logLevel: ['info', 'warn', 'error'].includes(req.body.logLevel) ? req.body.logLevel : 'info',
            maxEntries: Math.min(parseInt(req.body.maxEntries) || 100, 1000)
        };
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(`
            window.APP_CONFIG = ${JSON.stringify(config)};
            console.log('Configuration loaded:', window.APP_CONFIG);
        `);
        
        await page.goto('https://example.com');
        res.send('Safe JSON configuration script added');
    });
    
    app.listen(4010);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Using a script with safe array configuration
    const app = express();
    app.get('/safe-array-script', async (req, res) => {
        const featureFlags = [];
        
        if (req.query.darkMode === 'true') featureFlags.push('darkMode');
        if (req.query.betaFeatures === 'true') featureFlags.push('betaFeatures');
        if (req.query.analytics === 'true') featureFlags.push('analytics');
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            window.ENABLED_FEATURES = ${JSON.stringify(featureFlags)};
            console.log('Enabled features:', window.ENABLED_FEATURES);
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send(`Safe script with feature flags ${featureFlags.join(', ')} added`);
    });
    
    app.listen(4011);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13() {
    // Using a script from a path with validation
    const app = express();
    app.post('/safe-path-script', express.json(), async (req, res) => {
        const scriptName = req.body.scriptName;
        const allowedScripts = ['analytics.js', 'helpers.js', 'tracking.js'];
        
        if (!scriptName || !allowedScripts.includes(scriptName)) {
            return res.status(400).send('Invalid script name');
        }
        
        const scriptPath = path.join(__dirname, 'safe-scripts', scriptName);
        const scriptContent = fs.readFileSync(scriptPath, 'utf8');
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(scriptContent);
        
        await page.goto('https://example.com');
        res.send(`Safe script ${scriptName} loaded from path`);
    });
    
    app.listen(4012);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    
    // Using a script with safe template literals
    const app = express();
    app.get('/safe-template-script', async (req, res) => {
        const username = req.query.username as string;
        const sanitizedUsername = username ? username.replace(/[^\w\s]/g, '') : 'Guest';
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await context.addInitScript(`
            document.addEventListener('DOMContentLoaded', () => {
                const welcomeElement = document.getElementById('welcome');
                if (welcomeElement) {
                    welcomeElement.textContent = 'Welcome, ${sanitizedUsername}!';
                }
            });
        `);
        
        const page = await context.newPage();
        await page.goto('https://example.com');
        res.send(`Safe template script for user ${sanitizedUsername} added`);
    });
    
    app.listen(4013);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15() {
    // Using a script with safe dynamic content from a whitelist
    const app = express();
    app.post('/safe-dynamic-script', express.json(), async (req, res) => {
        const widgetType = req.body.widgetType;
        const widgetConfig = req.body.config || {};
        
        const allowedWidgets = {
            counter: {
                init: 'initCounter',
                maxValue: 100
            },
            timer: {
                init: 'initTimer',
                maxDuration: 3600
            },
            chart: {
                init: 'initChart',
                maxDataPoints: 50
            }
        };
        
        if (!widgetType || !(widgetType in allowedWidgets)) {
            return res.status(400).send('Invalid widget type');
        }
        
        const widget = allowedWidgets[widgetType as keyof typeof allowedWidgets];
        const safeConfig = {
            type: widgetType,
            initFunction: widget.init,
            maxValue: Math.min(parseInt(widgetConfig.maxValue) || widget.maxValue, widget.maxValue),
            container: 'widget-container'
        };
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        
        // ok: playwright-addinitscript-code-injection-ts-rule
        await page.addInitScript(`
            window.WIDGET_CONFIG = ${JSON.stringify(safeConfig)};
            document.addEventListener('DOMContentLoaded', () => {
                if (typeof window[window.WIDGET_CONFIG.initFunction] === 'function') {
                    window[window.WIDGET_CONFIG.initFunction](window.WIDGET_CONFIG);
                }
            });
        `);
        
        await page.goto('https://example.com');
        res.send(`Safe dynamic widget script for ${widgetType} added`);
    });
    
    app.listen(4014);
}
// {/fact}