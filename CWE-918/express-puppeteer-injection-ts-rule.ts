import express from 'express';
import puppeteer from 'puppeteer';
import { sanitizeUrl } from '@braintree/sanitize-url';
import validator from 'validator';
import * as crypto from 'crypto';

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Direct use of query parameter in page.goto
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1(req: express.Request, res: express.Response) {
    const url = req.query.url as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ruleid: express-puppeteer-injection-ts-rule
        await page.goto(url);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 2: Using POST body data in page.goto
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2(req: express.Request, res: express.Response) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ruleid: express-puppeteer-injection-ts-rule
        await page.goto(req.body.targetUrl);
        const screenshot = await page.screenshot();
        res.contentType('image/png');
        res.send(screenshot);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 3: Using request header in page.goto with string concatenation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3(req: express.Request, res: express.Response) {
    const userAgent = req.headers['user-agent'] as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ruleid: express-puppeteer-injection-ts-rule
        await page.goto('https://useragentinfo.com/check?ua=' + userAgent);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 4: Using request parameter in page.setContent
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4(req: express.Request, res: express.Response) {
    const htmlContent = req.query.html as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ruleid: express-puppeteer-injection-ts-rule
        await page.setContent(htmlContent);
        const pdf = await page.pdf();
        res.contentType('application/pdf');
        res.send(pdf);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 5: Using cookie value in page.goto
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5(req: express.Request, res: express.Response) {
    const targetSite = req.cookies.targetSite;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ruleid: express-puppeteer-injection-ts-rule
        await page.goto(targetSite);
        const title = await page.title();
        res.send({ title });
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 6: Using request parameter in page.evaluate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6(req: express.Request, res: express.Response) {
    const jsCode = req.query.code as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        const result = await page.evaluate(jsCode);
        res.json({ result });
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 7: Using request parameter in page.evaluateHandle
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7(req: express.Request, res: express.Response) {
    const selector = req.query.selector as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        const jsHandle = await page.evaluateHandle(`document.querySelector("${selector}")`);
        const properties = await jsHandle.getProperties();
        const result: Record<string, any> = {};
        for (const [key, value] of properties) {
            result[key] = await value.jsonValue();
        }
        res.json(result);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 8: Using request parameter in page.addScriptTag
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8(req: express.Request, res: express.Response) {
    const scriptUrl = req.query.script as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        await page.addScriptTag({ url: scriptUrl });
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 9: Using request parameter in page.click
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9(req: express.Request, res: express.Response) {
    const elementSelector = req.query.element as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        await page.click(elementSelector);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 10: Using request parameter in page.type
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10(req: express.Request, res: express.Response) {
    const selector = req.query.selector as string;
    const text = req.query.text as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        await page.type(selector, text);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 11: Using request parameter in browser.createIncognitoBrowserContext
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11(req: express.Request, res: express.Response) {
    const userProxyServer = req.query.proxy as string;
    const browser = await puppeteer.launch({
        // ruleid: express-puppeteer-injection-ts-rule
        args: [`--proxy-server=${userProxyServer}`]
    });
    
    try {
        const page = await browser.newPage();
        await page.goto('https://example.com');
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 12: Using request parameter in page.pdf with path option
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12(req: express.Request, res: express.Response) {
    const filePath = req.query.path as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        await page.pdf({ path: filePath });
        res.send('PDF created');
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 13: Using request parameter in page.screenshot with path option
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13(req: express.Request, res: express.Response) {
    const outputPath = req.query.output as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        await page.screenshot({ path: outputPath });
        res.send('Screenshot saved');
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 14: Using request parameter in page.waitForSelector
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14(req: express.Request, res: express.Response) {
    const selector = req.query.wait as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        await page.waitForSelector(selector);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 15: Using request parameter in page.$eval
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15(req: express.Request, res: express.Response) {
    const selector = req.query.selector as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ruleid: express-puppeteer-injection-ts-rule
        const text = await page.$eval(selector, (element) => element.textContent);
        res.send({ text });
    } finally {
        await browser.close();
    }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Example 1: Using hardcoded URL in page.goto
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1(req: express.Request, res: express.Response) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ok: express-puppeteer-injection-ts-rule
        await page.goto('https://example.com');
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 2: Validating URL with validator before using in page.goto
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2(req: express.Request, res: express.Response) {
    const url = req.query.url as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ok: express-puppeteer-injection-ts-rule
        if (validator.isURL(url, { protocols: ['http', 'https'], require_protocol: true })) {
            await page.goto(url);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('Invalid URL');
        }
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 3: Using URL whitelist for page.goto
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3(req: express.Request, res: express.Response) {
    const url = req.query.url as string;
    const allowedDomains = ['example.com', 'trusted-site.com', 'safe-domain.org'];
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ok: express-puppeteer-injection-ts-rule
        const urlObj = new URL(url);
        if (allowedDomains.includes(urlObj.hostname)) {
            await page.goto(url);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(403).send('Domain not allowed');
        }
    } catch (error) {
        res.status(400).send('Invalid URL');
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 4: Using sanitizeUrl library for page.goto
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4(req: express.Request, res: express.Response) {
    const userUrl = req.query.url as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ok: express-puppeteer-injection-ts-rule
        const sanitizedUrl = sanitizeUrl(userUrl);
        if (sanitizedUrl !== 'about:blank') {
            await page.goto(sanitizedUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('Invalid URL');
        }
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 5: Using URL constructor to validate and normalize URL
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5(req: express.Request, res: express.Response) {
    const userUrl = req.query.url as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ok: express-puppeteer-injection-ts-rule
        const url = new URL(userUrl);
        if (url.protocol === 'http:' || url.protocol === 'https:') {
            await page.goto(url.toString());
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('Invalid URL protocol');
        }
    } catch (error) {
        res.status(400).send('Invalid URL');
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 6: Using a predefined list of URLs
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6(req: express.Request, res: express.Response) {
    const urlId = req.query.id as string;
    const urlMap: Record<string, string> = {
        'google': 'https://www.google.com',
        'bing': 'https://www.bing.com',
        'yahoo': 'https://www.yahoo.com'
    };
    
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ok: express-puppeteer-injection-ts-rule
        const targetUrl = urlMap[urlId] || 'https://example.com';
        await page.goto(targetUrl);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 7: Using environment variables for URLs
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7(req: express.Request, res: express.Response) {
    const urlType = req.query.type as string;
    let targetUrl: string;
    
    // ok: express-puppeteer-injection-ts-rule
    switch (urlType) {
        case 'api':
            targetUrl = process.env.API_URL || 'https://api.example.com';
            break;
        case 'docs':
            targetUrl = process.env.DOCS_URL || 'https://docs.example.com';
            break;
        default:
            targetUrl = process.env.DEFAULT_URL || 'https://example.com';
    }
    
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto(targetUrl);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 8: Using regex pattern matching for URL validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8(req: express.Request, res: express.Response) {
    const userUrl = req.query.url as string;
    const urlPattern = /^https:\/\/(www\.)?example\.com\/[a-zA-Z0-9\/_-]+$/;
    
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        // ok: express-puppeteer-injection-ts-rule
        if (urlPattern.test(userUrl)) {
            await page.goto(userUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('URL not allowed');
        }
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 9: Using a safe selector from a predefined list
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9(req: express.Request, res: express.Response) {
    const selectorId = req.query.selector as string;
    const allowedSelectors: Record<string, string> = {
        'title': 'h1',
        'paragraph': 'p.main',
        'button': 'button.submit',
        'link': 'a.primary'
    };
    
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ok: express-puppeteer-injection-ts-rule
        const selector = allowedSelectors[selectorId] || 'body';
        await page.click(selector);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 10: Using a hash map for safe script URLs
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10(req: express.Request, res: express.Response) {
    const scriptId = req.query.script as string;
    const scriptMap: Record<string, string> = {
        'jquery': 'https://code.jquery.com/jquery-3.6.0.min.js',
        'bootstrap': 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
        'vue': 'https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js'
    };
    
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ok: express-puppeteer-injection-ts-rule
        const scriptUrl = scriptMap[scriptId];
        if (scriptUrl) {
            await page.addScriptTag({ url: scriptUrl });
        }
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 11: Using a function to validate and transform user input for page.type
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11(req: express.Request, res: express.Response) {
    const inputText = req.query.text as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ok: express-puppeteer-injection-ts-rule
        const sanitizedText = inputText ? inputText.replace(/[<>'"&]/g, '') : '';
        await page.type('#search-input', sanitizedText);
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 12: Using a fixed path for PDF output
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12(req: express.Request, res: express.Response) {
    const userId = req.query.userId as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ok: express-puppeteer-injection-ts-rule
        const timestamp = Date.now();
        const safeUserId = userId ? userId.replace(/[^a-zA-Z0-9]/g, '') : 'anonymous';
        const filename = `./reports/${safeUserId}_${timestamp}.pdf`;
        await page.pdf({ path: filename });
        res.download(filename);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 13: Using a safe evaluateHandle with no user input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13(req: express.Request, res: express.Response) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ok: express-puppeteer-injection-ts-rule
        const jsHandle = await page.evaluateHandle(() => {
            return {
                title: document.title,
                metaTags: Array.from(document.querySelectorAll('meta')).map(m => ({
                    name: m.getAttribute('name'),
                    content: m.getAttribute('content')
                }))
            };
        });
        const result = await jsHandle.jsonValue();
        res.json(result);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 14: Using a safe waitForSelector with no user input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14(req: express.Request, res: express.Response) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ok: express-puppeteer-injection-ts-rule
        await page.waitForSelector('#content', { timeout: 5000 });
        const content = await page.content();
        res.send(content);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Example 15: Using crypto to generate a safe filename for screenshot
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15(req: express.Request, res: express.Response) {
    const userIdentifier = req.query.id as string;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto('https://example.com');
        // ok: express-puppeteer-injection-ts-rule
        const hash = crypto.createHash('sha256').update(userIdentifier || 'anonymous').digest('hex');
        const filename = `./screenshots/${hash}.png`;
        await page.screenshot({ path: filename });
        res.sendFile(filename);
    } finally {
        await browser.close();
    }
}
// {/fact}

// Create Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/screenshot', bad_case_1);
app.post('/render', bad_case_2);
// ... other routes would be defined here

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});