import { chromium, firefox, webkit, Browser, BrowserContext, Page } from 'playwright';
import express from 'express';
import * as http from 'http';
import { Request, Response } from 'express';

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Direct injection into page.evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1() {
    const app = express();
    app.get('/vulnerable', async (req: Request, res: Response) => {
        const userInput = req.query.userScript as string;
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(userInput);
        
        res.send(result);
        await browser.close();
    });
    app.listen(3000);
}
// {/fact}

// Example 2: Injection into page.evaluateHandle
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2() {
    const app = express();
    app.post('/process', async (req: Request, res: Response) => {
        const userCode = req.body.code;
        const browser = await firefox.launch();
        const context = await browser.newContext();
        const page = await context.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const jsHandle = await page.evaluateHandle(userCode);
        
        const result = await jsHandle.jsonValue();
        res.json({ result });
        await browser.close();
    });
    app.listen(3001);
}
// {/fact}

// Example 3: Template literal injection in page.evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3() {
    const app = express();
    app.get('/search', async (req: Request, res: Response) => {
        const searchTerm = req.query.q as string;
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const results = await page.evaluate(`
            document.querySelectorAll('a[href*="${searchTerm}"]').length
        `);
        
        res.send(`Found ${results} results`);
        await browser.close();
    });
    app.listen(3002);
}
// {/fact}

// Example 4: Injection into page.$eval
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4() {
    const app = express();
    app.get('/extract', async (req: Request, res: Response) => {
        const selector = req.query.selector as string;
        const userFunction = req.query.func as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const data = await page.$eval(selector, new Function('el', userFunction));
        
        res.json({ data });
        await browser.close();
    });
    app.listen(3003);
}
// {/fact}

// Example 5: Injection into page.$$eval
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5() {
    const app = express();
    app.get('/extract-all', async (req: Request, res: Response) => {
        const selector = req.query.selector as string;
        const extractCode = req.query.code as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const elements = await page.$$eval(selector, new Function('elements', extractCode));
        
        res.json({ elements });
        await browser.close();
    });
    app.listen(3004);
}
// {/fact}

// Example 6: Injection into worker.evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6() {
    const app = express();
    app.post('/worker-task', async (req: Request, res: Response) => {
        const userScript = req.body.script;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        const worker = await page.workers()[0];
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await worker.evaluate(userScript);
        
        res.json({ result });
        await browser.close();
    });
    app.listen(3005);
}
// {/fact}

// Example 7: Injection into frame.evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7() {
    const app = express();
    app.get('/frame-content', async (req: Request, res: Response) => {
        const userCode = req.query.code as string;
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        const frame = page.frames()[0];
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const content = await frame.evaluate(userCode);
        
        res.send(content);
        await browser.close();
    });
    app.listen(3006);
}
// {/fact}

// Example 8: Injection with minimal processing
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8() {
    const app = express();
    app.get('/process-data', async (req: Request, res: Response) => {
        let userCode = req.query.code as string;
        // Minimal processing that doesn't sanitize
        userCode = userCode.replace(/console\.log/g, 'console.warn');
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(userCode);
        
        res.json({ result });
        await browser.close();
    });
    app.listen(3007);
}
// {/fact}

// Example 9: Injection via HTTP header
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9() {
    const app = express();
    app.get('/header-injection', async (req: Request, res: Response) => {
        const scriptFromHeader = req.headers['x-custom-script'] as string;
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(scriptFromHeader);
        
        res.send(result);
        await browser.close();
    });
    app.listen(3008);
}
// {/fact}

// Example 10: Injection via cookie
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10() {
    const app = express();
    app.get('/cookie-injection', async (req: Request, res: Response) => {
        const scriptFromCookie = req.cookies.userScript;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(scriptFromCookie);
        
        res.send(result);
        await browser.close();
    });
    app.listen(3009);
}
// {/fact}

// Example 11: Injection with string concatenation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11() {
    const app = express();
    app.get('/concat-injection', async (req: Request, res: Response) => {
        const userParam = req.query.param as string;
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate("function run() { return document.querySelector('" + userParam + "').innerText; } run();");
        
        res.send(result);
        await browser.close();
    });
    app.listen(3010);
}
// {/fact}

// Example 12: Injection via JSON body
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12() {
    const app = express();
    app.post('/json-injection', async (req: Request, res: Response) => {
        const scriptObj = req.body;
        const scriptToRun = scriptObj.code;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(scriptToRun);
        
        res.json({ output: result });
        await browser.close();
    });
    app.listen(3011);
}
// {/fact}

// Example 13: Injection with indirect assignment
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13() {
    const app = express();
    app.get('/indirect-injection', async (req: Request, res: Response) => {
        const userInput = req.query.script as string;
        let scriptToExecute;
        
        if (userInput.length > 10) {
            scriptToExecute = userInput.substring(0, 100);
        } else {
            scriptToExecute = userInput;
        }
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(scriptToExecute);
        
        res.send(result);
        await browser.close();
    });
    app.listen(3012);
}
// {/fact}

// Example 14: Injection via multiple request parameters
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14() {
    const app = express();
    app.get('/multi-param-injection', async (req: Request, res: Response) => {
        const selector = req.query.selector as string;
        const action = req.query.action as string;
        
        const scriptToRun = `document.querySelector('${selector}').${action}()`;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(scriptToRun);
        
        res.json({ result });
        await browser.close();
    });
    app.listen(3013);
}
// {/fact}

// Example 15: Injection with eval inside evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15() {
    const app = express();
    app.get('/eval-in-evaluate', async (req: Request, res: Response) => {
        const userCode = req.query.code as string;
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ruleid: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(`eval("${userCode.replace(/"/g, '\\"')}")`);
        
        res.send(result);
        await browser.close();
    });
    app.listen(3014);
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Example 1: Using static code in page.evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1() {
    const app = express();
    app.get('/safe-evaluate', async (req: Request, res: Response) => {
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(() => {
            return document.title;
        });
        
        res.send(result);
        await browser.close();
    });
    app.listen(4000);
}
// {/fact}

// Example 2: Using static string in page.evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2() {
    const app = express();
    app.get('/safe-string-evaluate', async (req: Request, res: Response) => {
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate('document.querySelector("h1").innerText');
        
        res.send(result);
        await browser.close();
    });
    app.listen(4001);
}
// {/fact}

// Example 3: Passing sanitized parameters to evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3() {
    const app = express();
    app.get('/safe-params', async (req: Request, res: Response) => {
        const searchTerm = req.query.q as string;
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const count = await page.evaluate((term) => {
            return document.querySelectorAll(`a[href*="${term}"]`).length;
        }, searchTerm);
        
        res.send(`Found ${count} results`);
        await browser.close();
    });
    app.listen(4002);
}
// {/fact}

// Example 4: Safe use of page.$eval with static function
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4() {
    const app = express();
    app.get('/safe-dollar-eval', async (req: Request, res: Response) => {
        const selector = req.query.selector as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const text = await page.$eval(selector, (element) => element.textContent);
        
        res.send(text);
        await browser.close();
    });
    app.listen(4003);
}
// {/fact}

// Example 5: Safe use of page.$$eval with static function
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5() {
    const app = express();
    app.get('/safe-double-dollar-eval', async (req: Request, res: Response) => {
        const selector = req.query.selector as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const texts = await page.$$eval(selector, (elements) => 
            elements.map(el => el.textContent)
        );
        
        res.json({ texts });
        await browser.close();
    });
    app.listen(4004);
}
// {/fact}

// Example 6: Safe worker evaluation with static function
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6() {
    const app = express();
    app.get('/safe-worker-eval', async (req: Request, res: Response) => {
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        const worker = await page.workers()[0];
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await worker.evaluate(() => {
            return self.navigator.userAgent;
        });
        
        res.send(result);
        await browser.close();
    });
    app.listen(4005);
}
// {/fact}

// Example 7: Safe frame evaluation with static function
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7() {
    const app = express();
    app.get('/safe-frame-eval', async (req: Request, res: Response) => {
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        const frame = page.frames()[0];
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const content = await frame.evaluate(() => {
            return document.body.innerHTML;
        });
        
        res.send(content);
        await browser.close();
    });
    app.listen(4006);
}
// {/fact}

// Example 8: Using a whitelist for allowed scripts
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8() {
    const app = express();
    app.get('/whitelist-scripts', async (req: Request, res: Response) => {
        const scriptId = req.query.id as string;
        
        // Whitelist of allowed scripts
        const allowedScripts: {[key: string]: () => any} = {
            'getTitle': () => document.title,
            'getLinks': () => Array.from(document.querySelectorAll('a')).map(a => a.href),
            'getImages': () => Array.from(document.querySelectorAll('img')).map(img => img.src)
        };
        
        if (!Object.keys(allowedScripts).includes(scriptId)) {
            return res.status(400).send('Invalid script ID');
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(allowedScripts[scriptId]);
        
        res.json({ result });
        await browser.close();
    });
    app.listen(4007);
}
// {/fact}

// Example 9: Using predefined templates with safe parameter substitution
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9() {
    const app = express();
    app.get('/template-scripts', async (req: Request, res: Response) => {
        const elementId = req.query.id as string;
        // Validate input - only allow alphanumeric IDs
        if (!/^[a-zA-Z0-9-_]+$/.test(elementId)) {
            return res.status(400).send('Invalid element ID');
        }
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const text = await page.evaluate((id) => {
            const element = document.getElementById(id);
            return element ? element.textContent : null;
        }, elementId);
        
        res.send(text || 'Element not found');
        await browser.close();
    });
    app.listen(4008);
}
// {/fact}

// Example 10: Using a function reference instead of dynamic code
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10() {
    const app = express();
    app.get('/function-reference', async (req: Request, res: Response) => {
        const operation = req.query.op as string;
        
        // Define safe functions
        const getPageTitle = () => document.title;
        const getPageUrl = () => document.URL;
        const getMetaDescription = () => {
            const meta = document.querySelector('meta[name="description"]');
            return meta ? meta.getAttribute('content') : null;
        };
        
        let functionToExecute: () => any;
        
        switch (operation) {
            case 'title':
                functionToExecute = getPageTitle;
                break;
            case 'url':
                functionToExecute = getPageUrl;
                break;
            case 'description':
                functionToExecute = getMetaDescription;
                break;
            default:
                return res.status(400).send('Invalid operation');
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(functionToExecute);
        
        res.send(result);
        await browser.close();
    });
    app.listen(4009);
}
// {/fact}

// Example 11: Using a configuration object with safe parameters
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11() {
    const app = express();
    app.get('/config-based', async (req: Request, res: Response) => {
        const selector = req.query.selector as string;
        const attribute = req.query.attribute as string;
        
        // Validate inputs
        if (!/^[a-zA-Z0-9-_.\s]+$/.test(selector)) {
            return res.status(400).send('Invalid selector');
        }
        
        if (!/^[a-zA-Z0-9-_]+$/.test(attribute)) {
            return res.status(400).send('Invalid attribute');
        }
        
        const browser = await firefox.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const value = await page.evaluate(
            ({ sel, attr }) => {
                const element = document.querySelector(sel);
                return element ? element.getAttribute(attr) : null;
            },
            { sel: selector, attr: attribute }
        );
        
        res.send(value || 'Attribute not found');
        await browser.close();
    });
    app.listen(4010);
}
// {/fact}

// Example 12: Using a safe JSON-based configuration
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12() {
    const app = express();
    app.post('/json-config', async (req: Request, res: Response) => {
        const config = req.body;
        
        // Validate configuration
        if (!config.selector || typeof config.selector !== 'string' || 
            !config.properties || !Array.isArray(config.properties)) {
            return res.status(400).send('Invalid configuration');
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const data = await page.evaluate(
            (conf) => {
                const element = document.querySelector(conf.selector);
                if (!element) return null;
                
                const result: {[key: string]: any} = {};
                for (const prop of conf.properties) {
                    if (prop in element) {
                        result[prop] = (element as any)[prop];
                    }
                }
                return result;
            },
            config
        );
        
        res.json({ data });
        await browser.close();
    });
    app.listen(4011);
}
// {/fact}

// Example 13: Using a safe factory function pattern
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13() {
    const app = express();
    app.get('/factory-pattern', async (req: Request, res: Response) => {
        const elementType = req.query.type as string;
        
        // Factory function to create safe evaluation functions
        const createEvaluator = (type: string) => {
            switch (type) {
                case 'links':
                    return () => Array.from(document.querySelectorAll('a')).map(a => a.href);
                case 'images':
                    return () => Array.from(document.querySelectorAll('img')).map(img => img.src);
                case 'headings':
                    return () => Array.from(document.querySelectorAll('h1, h2, h3')).map(h => h.textContent);
                default:
                    return () => document.title;
            }
        };
        
        const browser = await webkit.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const result = await page.evaluate(createEvaluator(elementType));
        
        res.json({ result });
        await browser.close();
    });
    app.listen(4012);
}
// {/fact}

// Example 14: Using a safe builder pattern
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14() {
    const app = express();
    app.get('/builder-pattern', async (req: Request, res: Response) => {
        const selector = req.query.selector as string;
        const property = req.query.property as string;
        
        // Validate inputs
        if (!/^[a-zA-Z0-9-_.\s]+$/.test(selector)) {
            return res.status(400).send('Invalid selector');
        }
        
        if (!/^[a-zA-Z0-9-_]+$/.test(property)) {
            return res.status(400).send('Invalid property');
        }
        
        // Builder function to create safe evaluation
        const buildEvaluationFunction = (sel: string, prop: string) => {
            return (s: string, p: string) => {
                const element = document.querySelector(s);
                return element ? (element as any)[p] : null;
            };
        };
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto('https://example.com');
        
        // ok: playwright-evaluate-code-injection-ts-rule
        const value = await page.evaluate(buildEvaluationFunction(selector, property), selector, property);
        
        res.send(value || 'Property not found');
        await browser.close();
    });
    app.listen(4013);
}
// {/fact}

// Example 15: Using safe evaluation with proper error handling
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15() {
    const app = express();
    app.get('/safe-with-error-handling', async (req: Request, res: Response) => {
        const elementId = req.query.id as string;
        
        // Validate input
        if (!/^[a-zA-Z0-9-_]+$/.test(elementId)) {
            return res.status(400).send('Invalid element ID');
        }
        
        try {
            const browser = await firefox.launch();
            const page = await browser.newPage();
            await page.goto('https://example.com');
            
            // ok: playwright-evaluate-code-injection-ts-rule
            const result = await page.evaluate((id) => {
                try {
                    const element = document.getElementById(id);
                    if (!element) {
                        return { success: false, error: 'Element not found' };
                    }
                    return { 
                        success: true, 
                        data: {
                            tagName: element.tagName,
                            className: element.className,
                            textContent: element.textContent
                        }
                    };
                } catch (error) {
                    return { success: false, error: String(error) };
                }
            }, elementId);
            
            if (result.success) {
                res.json(result.data);
            } else {
                res.status(404).json({ error: result.error });
            }
            
            await browser.close();
        } catch (error) {
            res.status(500).json({ error: 'Server error' });
        }
    });
    app.listen(4014);
}
// {/fact}