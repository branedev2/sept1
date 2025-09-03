const express = require('express');
const puppeteer = require('puppeteer');
const url = require('url');
const validator = require('validator');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// Bad Case 1: Direct use of query parameter in puppeteer.goto
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const userUrl = req.query.url;
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(userUrl);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Error fetching the page');
    }
}
// {/fact}

// Bad Case 2: Using POST body parameter without validation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const targetUrl = req.body.target;
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(targetUrl);
        const screenshot = await page.screenshot();
        await browser.close();
        res.type('image/png').send(screenshot);
    } catch (error) {
        await browser.close();
        res.status(500).send('Screenshot failed');
    }
}
// {/fact}

// Bad Case 3: Using request header without validation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const urlToVisit = req.headers['x-target-url'];
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(urlToVisit);
        const title = await page.title();
        await browser.close();
        res.json({ title });
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to fetch page title' });
    }
}
// {/fact}

// Bad Case 4: Using URL path parameter without validation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const targetSite = req.params.site;
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(`https://${targetSite}`);
        const metrics = await page.metrics();
        await browser.close();
        res.json(metrics);
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to get metrics' });
    }
}
// {/fact}

// Bad Case 5: Using cookie value without validation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const targetUrl = req.cookies.savedUrl;
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(targetUrl);
        const links = await page.$$eval('a', links => links.map(link => link.href));
        await browser.close();
        res.json({ links });
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to extract links' });
    }
}
// {/fact}

// Bad Case 6: Concatenating user input with base URL
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const path = req.query.path;
    const baseUrl = "https://example.com/";
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(baseUrl + path);
        const html = await page.content();
        await browser.close();
        res.send(html);
    } catch (error) {
        await browser.close();
        res.status(500).send('Error fetching content');
    }
}
// {/fact}

// Bad Case 7: Using template literals with user input
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const subdomain = req.query.subdomain;
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(`https://${subdomain}.example.com`);
        const cookies = await page.cookies();
        await browser.close();
        res.json(cookies);
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to get cookies' });
    }
}
// {/fact}

// Bad Case 8: Using page.setContent with user input
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const userUrl = req.query.url;
    
    try {
        await page.setContent('<html><body>Loading...</body></html>');
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(userUrl);
        const performance = await page.evaluate(() => JSON.stringify(window.performance));
        await browser.close();
        res.json(JSON.parse(performance));
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Performance measurement failed' });
    }
}
// {/fact}

// Bad Case 9: Using minimal input processing that doesn't validate URL
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    let userUrl = req.query.url;
    
    // This doesn't validate the URL, just ensures it has http/https
    if (!userUrl.startsWith('http')) {
        userUrl = 'https://' + userUrl;
    }
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(userUrl);
        const dimensions = await page.evaluate(() => {
            return {
                width: document.documentElement.clientWidth,
                height: document.documentElement.clientHeight
            };
        });
        await browser.close();
        res.json(dimensions);
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to get page dimensions' });
    }
}
// {/fact}

// Bad Case 10: Using page.evaluate with user input URL
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const targetUrl = req.query.url;
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(targetUrl);
        const result = await page.evaluate(() => {
            return document.title;
        });
        await browser.close();
        res.send(result);
    } catch (error) {
        await browser.close();
        res.status(500).send('Evaluation failed');
    }
}
// {/fact}

// Bad Case 11: Using user input in navigation after initial page load
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const nextUrl = req.query.next;
    
    try {
        await page.goto('https://example.com');
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(nextUrl);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Navigation failed');
    }
}
// {/fact}

// Bad Case 12: Using multiple user inputs to construct URL
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const protocol = req.query.protocol || 'https';
    const domain = req.query.domain;
    const path = req.query.path || '';
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(`${protocol}://${domain}/${path}`);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Failed to load page');
    }
}
// {/fact}

// Bad Case 13: Using page.setContent with iframe src from user input
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const iframeSrc = req.query.src;
    
    try {
        await page.setContent(`<html><body><iframe src="${iframeSrc}"></iframe></body></html>`);
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(iframeSrc);
        const screenshot = await page.screenshot();
        await browser.close();
        res.type('image/png').send(screenshot);
    } catch (error) {
        await browser.close();
        res.status(500).send('Failed to load iframe');
    }
}
// {/fact}

// Bad Case 14: Using URL from JSON body
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const { targetUrl } = req.body;
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(targetUrl);
        const metrics = await page.metrics();
        await browser.close();
        res.json(metrics);
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to get metrics' });
    }
}
// {/fact}

// Bad Case 15: Using URL from nested JSON body
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const { options } = req.body;
    const targetUrl = options && options.url;
    
    try {
        // ruleid: javascript-express-puppeteer-injection
        await page.goto(targetUrl);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Failed to load page');
    }
}
// {/fact}

// True Negative Examples (Secure Code)

// Good Case 1: Validating URL with allowlist
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const userUrl = req.query.url;
    
    const allowedDomains = ['example.com', 'trusted-site.com'];
    
    try {
        const parsedUrl = new URL(userUrl);
        const isAllowed = allowedDomains.some(domain => parsedUrl.hostname === domain || 
                                                       parsedUrl.hostname.endsWith(`.${domain}`));
        
        if (!isAllowed) {
            await browser.close();
            return res.status(403).send('URL not allowed');
        }
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(userUrl);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Error fetching the page');
    }
}
// {/fact}

// Good Case 2: Using URL validation library
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const targetUrl = req.body.target;
    
    try {
        if (!validator.isURL(targetUrl, { 
            protocols: ['http', 'https'],
            require_protocol: true,
            host_whitelist: ['example.com', 'trusted-site.com']
        })) {
            await browser.close();
            return res.status(400).send('Invalid URL');
        }
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(targetUrl);
        const screenshot = await page.screenshot();
        await browser.close();
        res.type('image/png').send(screenshot);
    } catch (error) {
        await browser.close();
        res.status(500).send('Screenshot failed');
    }
}
// {/fact}

// Good Case 3: Using URL pattern matching
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const urlToVisit = req.headers['x-target-url'];
    
    try {
        // Validate URL format and domain
        const urlPattern = /^https:\/\/(www\.)?example\.com\/[a-zA-Z0-9\/_-]*$/;
        if (!urlPattern.test(urlToVisit)) {
            await browser.close();
            return res.status(403).send('URL not allowed');
        }
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(urlToVisit);
        const title = await page.title();
        await browser.close();
        res.json({ title });
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to fetch page title' });
    }
}
// {/fact}

// Good Case 4: Using predefined URL templates
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const productId = req.params.productId;
    
    // Only allow numeric product IDs
    if (!/^\d+$/.test(productId)) {
        await browser.close();
        return res.status(400).send('Invalid product ID');
    }
    
    try {
        const productUrl = `https://example.com/products/${productId}`;
        // ok: javascript-express-puppeteer-injection
        await page.goto(productUrl);
        const productData = await page.evaluate(() => {
            // Extract product information from the page
            return {
                name: document.querySelector('.product-name').textContent,
                price: document.querySelector('.product-price').textContent
            };
        });
        await browser.close();
        res.json(productData);
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to fetch product data' });
    }
}
// {/fact}

// Good Case 5: Using URL constructor for validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const userInput = req.query.url;
    
    try {
        // Validate URL and ensure it's from allowed domain
        const parsedUrl = new URL(userInput);
        if (parsedUrl.hostname !== 'example.com') {
            await browser.close();
            return res.status(403).send('Only example.com URLs are allowed');
        }
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(parsedUrl.href);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Error processing URL');
    }
}
// {/fact}

// Good Case 6: Using hardcoded URLs only
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const pageId = req.query.id;
    
    // Map of allowed page IDs to their URLs
    const pageMap = {
        'home': 'https://example.com/',
        'about': 'https://example.com/about',
        'contact': 'https://example.com/contact'
    };
    
    if (!pageMap[pageId]) {
        await browser.close();
        return res.status(404).send('Page not found');
    }
    
    try {
        // ok: javascript-express-puppeteer-injection
        await page.goto(pageMap[pageId]);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Error fetching page');
    }
}
// {/fact}

// Good Case 7: Using URL validation with protocol and domain restrictions
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const userUrl = req.query.url;
    
    try {
        // Validate URL
        const parsedUrl = new URL(userUrl);
        
        // Ensure HTTPS protocol
        if (parsedUrl.protocol !== 'https:') {
            await browser.close();
            return res.status(403).send('Only HTTPS URLs are allowed');
        }
        
        // Check domain against allowlist
        const allowedDomains = ['example.com', 'example.org'];
        if (!allowedDomains.includes(parsedUrl.hostname)) {
            await browser.close();
            return res.status(403).send('Domain not allowed');
        }
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(userUrl);
        const screenshot = await page.screenshot();
        await browser.close();
        res.type('image/png').send(screenshot);
    } catch (error) {
        await browser.close();
        res.status(500).send('Error processing URL');
    }
}
// {/fact}

// Good Case 8: Using path-only navigation with base URL
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const path = req.query.path;
    
    // Validate path format
    if (!/^[a-zA-Z0-9\/_-]+$/.test(path)) {
        await browser.close();
        return res.status(400).send('Invalid path format');
    }
    
    try {
        // Set base URL first
        await page.goto('https://example.com');
        
        // Navigate to path within the same origin
        // ok: javascript-express-puppeteer-injection
        await page.evaluate((validPath) => {
            window.location.pathname = validPath;
        }, path);
        
        await page.waitForNavigation();
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Navigation failed');
    }
}
// {/fact}

// Good Case 9: Using a URL builder with validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const category = req.query.category;
    const page_num = req.query.page;
    
    // Validate inputs
    if (!/^[a-zA-Z0-9-]+$/.test(category) || !/^\d+$/.test(page_num)) {
        await browser.close();
        return res.status(400).send('Invalid parameters');
    }
    
    try {
        const baseUrl = 'https://example.com';
        const safeUrl = new URL(`/products/${category}`, baseUrl);
        safeUrl.searchParams.append('page', page_num);
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(safeUrl.toString());
        const productList = await page.$$eval('.product', products => 
            products.map(p => ({
                name: p.querySelector('.name').textContent,
                price: p.querySelector('.price').textContent
            }))
        );
        await browser.close();
        res.json(productList);
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to fetch products' });
    }
}
// {/fact}

// Good Case 10: Using environment-specific URLs
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const pageKey = req.query.page;
    
    // Define allowed pages
    const allowedPages = ['home', 'about', 'contact', 'products'];
    
    if (!allowedPages.includes(pageKey)) {
        await browser.close();
        return res.status(400).send('Invalid page requested');
    }
    
    try {
        // Get URL from environment or configuration
        const baseUrl = process.env.APP_URL || 'https://example.com';
        const targetUrl = `${baseUrl}/${pageKey}`;
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(targetUrl);
        const title = await page.title();
        await browser.close();
        res.json({ page: pageKey, title });
    } catch (error) {
        await browser.close();
        res.status(500).json({ error: 'Failed to load page' });
    }
}
// {/fact}

// Good Case 11: Using URL validation with custom function
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const userUrl = req.query.url;
    
    // Custom URL validation function
    function isValidUrl(urlString) {
        try {
            const parsedUrl = new URL(urlString);
            return (
                (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') &&
                (parsedUrl.hostname === 'example.com' || parsedUrl.hostname.endsWith('.example.com'))
            );
        } catch {
            return false;
        }
    }
    
    if (!isValidUrl(userUrl)) {
        await browser.close();
        return res.status(403).send('URL not allowed');
    }
    
    try {
        // ok: javascript-express-puppeteer-injection
        await page.goto(userUrl);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Failed to load page');
    }
}
// {/fact}

// Good Case 12: Using ID-based navigation with lookup
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const articleId = req.params.id;
    
    // Validate ID format
    if (!/^\d+$/.test(articleId)) {
        await browser.close();
        return res.status(400).send('Invalid article ID');
    }
    
    // Database or API lookup would happen here in a real app
    const articleUrls = {
        '1': 'https://example.com/articles/introduction',
        '2': 'https://example.com/articles/advanced-topics',
        '3': 'https://example.com/articles/conclusion'
    };
    
    const articleUrl = articleUrls[articleId];
    if (!articleUrl) {
        await browser.close();
        return res.status(404).send('Article not found');
    }
    
    try {
        // ok: javascript-express-puppeteer-injection
        await page.goto(articleUrl);
        const articleContent = await page.$eval('.article-body', el => el.textContent);
        await browser.close();
        res.send(articleContent);
    } catch (error) {
        await browser.close();
        res.status(500).send('Failed to fetch article');
    }
}
// {/fact}

// Good Case 13: Using domain validation with URL constructor
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const userUrl = req.query.url;
    
    try {
        const url = new URL(userUrl);
        
        // Validate domain and protocol
        if (url.hostname !== 'api.example.com' || url.protocol !== 'https:') {
            await browser.close();
            return res.status(403).send('Only https://api.example.com URLs are allowed');
        }
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(url.href);
        const apiResponse = await page.$eval('pre', el => el.textContent);
        const jsonResponse = JSON.parse(apiResponse);
        await browser.close();
        res.json(jsonResponse);
    } catch (error) {
        await browser.close();
        res.status(500).send('Failed to fetch API data');
    }
}
// {/fact}

// Good Case 14: Using a configuration-based URL with parameters
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const productId = req.query.id;
    
    // Validate product ID
    if (!/^\d+$/.test(productId)) {
        await browser.close();
        return res.status(400).send('Invalid product ID');
    }
    
    try {
        // Use configuration for base URL
        const config = {
            productApiUrl: 'https://api.example.com/products/'
        };
        
        const productUrl = `${config.productApiUrl}${productId}`;
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(productUrl);
        const productData = await page.$eval('body', el => el.textContent);
        await browser.close();
        res.send(productData);
    } catch (error) {
        await browser.close();
        res.status(500).send('Failed to fetch product data');
    }
}
// {/fact}

// Good Case 15: Using URL validation with path restrictions
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15(req, res) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const userUrl = req.query.url;
    
    try {
        const url = new URL(userUrl);
        
        // Validate domain
        if (url.hostname !== 'docs.example.com') {
            await browser.close();
            return res.status(403).send('Only docs.example.com URLs are allowed');
        }
        
        // Validate path starts with /public/
        if (!url.pathname.startsWith('/public/')) {
            await browser.close();
            return res.status(403).send('Only /public/ paths are allowed');
        }
        
        // ok: javascript-express-puppeteer-injection
        await page.goto(url.href);
        const content = await page.content();
        await browser.close();
        res.send(content);
    } catch (error) {
        await browser.close();
        res.status(500).send('Failed to fetch documentation');
    }
}
// {/fact}

// Export routes for Express
module.exports = {
    bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
    bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
    bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
    good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
    good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
    good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};