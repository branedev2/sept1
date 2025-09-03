import { chromium, firefox, webkit, Browser, BrowserContext, Page } from 'playwright';
import express from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';

// TRUE POSITIVES (Vulnerable Code)

// Case 1: Direct user input to goto method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const app = express();
    app.get('/navigate', async (req, res) => {
        const userUrl = req.query.url as string;
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(userUrl);
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(3000);
}
// {/fact}

// Case 2: User input with minimal transformation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/screenshot', async (req, res) => {
        const targetUrl = req.query.target as string;
        const formattedUrl = targetUrl.trim();
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(formattedUrl);
        const screenshot = await page.screenshot();
        res.contentType('image/png');
        res.send(screenshot);
    });
    
    app.listen(3001);
}
// {/fact}

// Case 3: User input in POST request
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3() {
    const browser = await firefox.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.use(express.json());
    
    app.post('/fetch-content', async (req, res) => {
        const { url } = req.body;
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(url);
        const title = await page.title();
        res.json({ title });
    });
    
    app.listen(3002);
}
// {/fact}

// Case 4: User input from headers
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4() {
    const browser = await webkit.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const app = express();
    app.get('/proxy', async (req, res) => {
        const referer = req.headers.referer as string;
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(referer);
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(3003);
}
// {/fact}

// Case 5: User input with string concatenation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/visit', async (req, res) => {
        const domain = req.query.domain as string;
        const url = "https://" + domain;
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(url);
        const title = await page.title();
        res.send(`Title: ${title}`);
    });
    
    app.listen(3004);
}
// {/fact}

// Case 6: User input with template literals
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/navigate', async (req, res) => {
        const path = req.query.path as string;
        const baseUrl = "https://example.com";
        const fullUrl = `${baseUrl}/${path}`;
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(fullUrl);
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(3005);
}
// {/fact}

// Case 7: User input through cookies
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.use(express.json());
    
    app.get('/cookie-nav', async (req, res) => {
        const cookies = req.headers.cookie;
        const urlCookie = cookies?.split(';')
            .find(c => c.trim().startsWith('target_url='))
            ?.split('=')[1];
        
        if (urlCookie) {
            // ruleid: playwright-goto-injection-ts-rule
            await page.goto(decodeURIComponent(urlCookie));
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('No target URL provided');
        }
    });
    
    app.listen(3006);
}
// {/fact}

// Case 8: User input with conditional logic
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/conditional-nav', async (req, res) => {
        const url = req.query.url as string;
        let targetUrl = 'https://example.com';
        
        if (url && url.length > 0) {
            targetUrl = url;
        }
        
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(targetUrl);
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(3007);
}
// {/fact}

// Case 9: User input through multiple parameters
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/complex-nav', async (req, res) => {
        const protocol = (req.query.protocol as string) || 'https';
        const domain = req.query.domain as string;
        const path = req.query.path as string;
        
        const url = `${protocol}://${domain}/${path}`;
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(url);
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(3008);
}
// {/fact}

// Case 10: User input through JSON body
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10() {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const app = express();
    app.use(express.json());
    
    app.post('/json-nav', async (req, res) => {
        const { navigationTarget } = req.body;
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(navigationTarget);
        const title = await page.title();
        res.json({ pageTitle: title });
    });
    
    app.listen(3009);
}
// {/fact}

// Case 11: User input with error handling
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/safe-nav', async (req, res) => {
        const userUrl = req.query.url as string;
        
        try {
            // ruleid: playwright-goto-injection-ts-rule
            await page.goto(userUrl);
            const content = await page.content();
            res.send(content);
        } catch (error) {
            res.status(500).send('Navigation failed');
        }
    });
    
    app.listen(3010);
}
// {/fact}

// Case 12: User input with URL object
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/url-object', async (req, res) => {
        const userInput = req.query.url as string;
        const urlObj = new URL(userInput);
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(urlObj.toString());
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(3011);
}
// {/fact}

// Case 13: User input with async/await pattern
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/async-nav', async (req, res) => {
        const fetchUrl = async () => {
            return req.query.url as string;
        };
        
        const url = await fetchUrl();
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(url);
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(3012);
}
// {/fact}

// Case 14: User input with object destructuring
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/destructure', async (req, res) => {
        const { url } = req.query;
        // ruleid: playwright-goto-injection-ts-rule
        await page.goto(url as string);
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(3013);
}
// {/fact}

// Case 15: User input with array operations
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/array-nav', async (req, res) => {
        const urls = (req.query.urls as string).split(',');
        for (const url of urls) {
            // ruleid: playwright-goto-injection-ts-rule
            await page.goto(url);
            // Process each page
        }
        res.send('Navigation complete');
    });
    
    app.listen(3014);
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Case 1: Hardcoded URL
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/safe-nav', async (req, res) => {
        // ok: playwright-goto-injection-ts-rule
        await page.goto('https://example.com');
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(4000);
}
// {/fact}

// Case 2: URL from environment variable
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/env-nav', async (req, res) => {
        const safeUrl = process.env.SAFE_URL || 'https://example.com';
        // ok: playwright-goto-injection-ts-rule
        await page.goto(safeUrl);
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(4001);
}
// {/fact}

// Case 3: Whitelist validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/whitelist', async (req, res) => {
        const userUrl = req.query.url as string;
        const allowedDomains = ['example.com', 'trusted-site.org', 'safe-domain.net'];
        
        try {
            const urlObj = new URL(userUrl);
            if (allowedDomains.includes(urlObj.hostname)) {
                // ok: playwright-goto-injection-ts-rule
                await page.goto(userUrl);
                const content = await page.content();
                res.send(content);
            } else {
                res.status(403).send('Domain not allowed');
            }
        } catch (error) {
            res.status(400).send('Invalid URL');
        }
    });
    
    app.listen(4002);
}
// {/fact}

// Case 4: URL pattern validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/pattern-check', async (req, res) => {
        const userUrl = req.query.url as string;
        
        // Ensure URL starts with https://example.com/
        const urlPattern = /^https:\/\/example\.com\//;
        if (urlPattern.test(userUrl)) {
            // ok: playwright-goto-injection-ts-rule
            await page.goto(userUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(403).send('URL not allowed');
        }
    });
    
    app.listen(4003);
}
// {/fact}

// Case 5: URL construction with validated parts
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/safe-construction', async (req, res) => {
        const path = req.query.path as string;
        
        // Validate path contains only allowed characters
        if (/^[a-zA-Z0-9\/_-]+$/.test(path)) {
            const safeUrl = `https://example.com/${path}`;
            // ok: playwright-goto-injection-ts-rule
            await page.goto(safeUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('Invalid path');
        }
    });
    
    app.listen(4004);
}
// {/fact}

// Case 6: URL from configuration
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const config = {
        allowedUrls: {
            dashboard: 'https://example.com/dashboard',
            profile: 'https://example.com/profile',
            settings: 'https://example.com/settings'
        }
    };
    
    const app = express();
    app.get('/config-nav', async (req, res) => {
        const page = req.query.page as string;
        
        if (page && page in config.allowedUrls) {
            const safeUrl = config.allowedUrls[page as keyof typeof config.allowedUrls];
            // ok: playwright-goto-injection-ts-rule
            await page.goto(safeUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('Invalid page');
        }
    });
    
    app.listen(4005);
}
// {/fact}

// Case 7: URL with hostname validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/hostname-check', async (req, res) => {
        const userUrl = req.query.url as string;
        
        try {
            const urlObj = new URL(userUrl);
            
            // Ensure hostname is example.com
            if (urlObj.hostname === 'example.com') {
                // ok: playwright-goto-injection-ts-rule
                await page.goto(userUrl);
                const content = await page.content();
                res.send(content);
            } else {
                res.status(403).send('Domain not allowed');
            }
        } catch (error) {
            res.status(400).send('Invalid URL');
        }
    });
    
    app.listen(4006);
}
// {/fact}

// Case 8: URL with protocol validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/protocol-check', async (req, res) => {
        const userUrl = req.query.url as string;
        
        try {
            const urlObj = new URL(userUrl);
            
            // Ensure protocol is https
            if (urlObj.protocol === 'https:') {
                // Check domain is trusted
                if (urlObj.hostname === 'example.com') {
                    // ok: playwright-goto-injection-ts-rule
                    await page.goto(userUrl);
                    const content = await page.content();
                    res.send(content);
                } else {
                    res.status(403).send('Domain not allowed');
                }
            } else {
                res.status(403).send('Protocol not allowed');
            }
        } catch (error) {
            res.status(400).send('Invalid URL');
        }
    });
    
    app.listen(4007);
}
// {/fact}

// Case 9: URL with path mapping
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/path-mapping', async (req, res) => {
        const pathKey = req.query.path as string;
        
        const pathMap: Record<string, string> = {
            'home': '/home',
            'about': '/about',
            'contact': '/contact',
            'products': '/products'
        };
        
        if (pathKey && pathKey in pathMap) {
            const safePath = pathMap[pathKey];
            const safeUrl = `https://example.com${safePath}`;
            // ok: playwright-goto-injection-ts-rule
            await page.goto(safeUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('Invalid path key');
        }
    });
    
    app.listen(4008);
}
// {/fact}

// Case 10: URL with ID parameter validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/id-validation', async (req, res) => {
        const productId = req.query.id as string;
        
        // Ensure ID is numeric
        if (/^\d+$/.test(productId)) {
            const safeUrl = `https://example.com/products/${productId}`;
            // ok: playwright-goto-injection-ts-rule
            await page.goto(safeUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('Invalid product ID');
        }
    });
    
    app.listen(4009);
}
// {/fact}

// Case 11: URL with domain suffix validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/domain-suffix', async (req, res) => {
        const subdomain = req.query.subdomain as string;
        
        // Validate subdomain format
        if (/^[a-z0-9-]+$/.test(subdomain)) {
            const safeUrl = `https://${subdomain}.example.com`;
            // ok: playwright-goto-injection-ts-rule
            await page.goto(safeUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(400).send('Invalid subdomain');
        }
    });
    
    app.listen(4010);
}
// {/fact}

// Case 12: URL with query parameter construction
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/query-params', async (req, res) => {
        const searchTerm = req.query.q as string;
        const category = req.query.category as string;
        
        // Base URL is hardcoded
        const baseUrl = 'https://example.com/search';
        const url = new URL(baseUrl);
        
        // Add validated parameters
        if (searchTerm) {
            url.searchParams.append('q', searchTerm);
        }
        
        if (category && ['books', 'electronics', 'clothing'].includes(category)) {
            url.searchParams.append('category', category);
        }
        
        // ok: playwright-goto-injection-ts-rule
        await page.goto(url.toString());
        const content = await page.content();
        res.send(content);
    });
    
    app.listen(4011);
}
// {/fact}

// Case 13: URL with database lookup
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    // Mock database of allowed URLs
    const urlDatabase = {
        '1': 'https://example.com/page1',
        '2': 'https://example.com/page2',
        '3': 'https://example.com/page3'
    };
    
    const app = express();
    app.get('/db-lookup', async (req, res) => {
        const urlId = req.query.id as string;
        
        // Look up URL in database
        if (urlId && urlId in urlDatabase) {
            const safeUrl = urlDatabase[urlId as keyof typeof urlDatabase];
            // ok: playwright-goto-injection-ts-rule
            await page.goto(safeUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(404).send('URL not found');
        }
    });
    
    app.listen(4012);
}
// {/fact}

// Case 14: URL with hash validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    // Mock hash verification system
    const verifiedUrls: Record<string, string> = {
        'abc123': 'https://example.com/verified/page1',
        'def456': 'https://example.com/verified/page2',
        'ghi789': 'https://example.com/verified/page3'
    };
    
    const app = express();
    app.get('/hash-verification', async (req, res) => {
        const urlHash = req.query.hash as string;
        
        if (urlHash && urlHash in verifiedUrls) {
            const safeUrl = verifiedUrls[urlHash];
            // ok: playwright-goto-injection-ts-rule
            await page.goto(safeUrl);
            const content = await page.content();
            res.send(content);
        } else {
            res.status(403).send('URL not verified');
        }
    });
    
    app.listen(4013);
}
// {/fact}

// Case 15: URL with comprehensive validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15() {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const app = express();
    app.get('/comprehensive', async (req, res) => {
        const userUrl = req.query.url as string;
        
        try {
            // Parse URL
            const urlObj = new URL(userUrl);
            
            // Check protocol
            if (urlObj.protocol !== 'https:') {
                return res.status(403).send('Only HTTPS allowed');
            }
            
            // Check domain against whitelist
            const allowedDomains = ['example.com', 'trusted-site.org'];
            if (!allowedDomains.includes(urlObj.hostname)) {
                return res.status(403).send('Domain not allowed');
            }
            
            // Check path for dangerous patterns
            if (urlObj.pathname.includes('../') || urlObj.pathname.includes('..\\')) {
                return res.status(403).send('Invalid path');
            }
            
            // Validate path format
            if (!/^\/[a-zA-Z0-9\/_-]*$/.test(urlObj.pathname)) {
                return res.status(403).send('Invalid path format');
            }
            
            // URL passed all checks
            // ok: playwright-goto-injection-ts-rule
            await page.goto(userUrl);
            const content = await page.content();
            res.send(content);
        } catch (error) {
            res.status(400).send('Invalid URL');
        }
    });
    
    app.listen(4014);
}
// {/fact}