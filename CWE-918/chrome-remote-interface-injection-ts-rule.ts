// Filename: chrome_remote_interface_test_cases.ts

import * as http from 'http';
import * as url from 'url';
import * as CDP from 'chrome-remote-interface';
import * as express from 'express';
import { Request, Response } from 'express';
import { sanitizeUrl } from '@braintree/sanitize-url';
import { validate } from 'class-validator';
import { IsUrl } from 'class-validator';

// True Positive Examples (Vulnerable Code)

// Example 1: Using user input directly in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1(req: Request, res: Response) {
    const targetUrl = req.query.url as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 2: Using POST data in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2(req: Request, res: Response) {
    const targetUrl = req.body.url;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 3: Using header data in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3(req: Request, res: Response) {
    const targetUrl = req.headers['x-target-url'] as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 4: Using cookie data in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4(req: Request, res: Response) {
    const targetUrl = req.cookies.targetUrl;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 5: Using user input in Page.setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5(req: Request, res: Response) {
    const htmlContent = req.body.content;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: htmlContent 
        });
        
        await client.close();
        res.send('Content set successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 6: Using query parameter in Page.setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6(req: Request, res: Response) {
    const htmlContent = req.query.html as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: htmlContent 
        });
        
        await client.close();
        res.send('Content set successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 7: Using user input in Page.printToPDF
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7(req: Request, res: Response) {
    const targetUrl = req.query.url as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({ 
            url: targetUrl,
            printBackground: true 
        });
        
        await client.close();
        res.send('PDF generated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 8: Using indirect user input in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8(req: Request, res: Response) {
    const baseUrl = req.query.baseUrl as string;
    const path = req.query.path as string;
    const targetUrl = baseUrl + '/' + path;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 9: Using user input with string concatenation in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9(req: Request, res: Response) {
    const domain = req.query.domain as string;
    const targetUrl = 'https://' + domain + '/index.html';
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 10: Using user input with template literals in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10(req: Request, res: Response) {
    const domain = req.query.domain as string;
    const path = req.query.path as string;
    const targetUrl = `https://${domain}/${path}`;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 11: Using user input with minimal processing in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11(req: Request, res: Response) {
    let targetUrl = req.query.url as string;
    if (!targetUrl.startsWith('http')) {
        targetUrl = 'https://' + targetUrl;
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 12: Using user input in Page.setDocumentContent with string manipulation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12(req: Request, res: Response) {
    const title = req.query.title as string;
    const content = req.query.content as string;
    const htmlContent = `<html><head><title>${title}</title></head><body>${content}</body></html>`;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: htmlContent 
        });
        
        await client.close();
        res.send('Content set successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 13: Using user input in Page.printToPDF with object spread
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13(req: Request, res: Response) {
    const options = {
        url: req.query.url as string,
        printBackground: true,
        landscape: req.query.landscape === 'true'
    };
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF(options);
        
        await client.close();
        res.send('PDF generated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 14: Using user input in Page.navigate with conditional logic
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14(req: Request, res: Response) {
    let targetUrl: string;
    
    if (req.query.type === 'direct') {
        targetUrl = req.query.url as string;
    } else {
        targetUrl = 'https://example.com/search?q=' + req.query.query;
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 15: Using user input in Page.navigate with array processing
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15(req: Request, res: Response) {
    const segments = req.query.segments as string[];
    const targetUrl = 'https://' + segments.join('/');
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using hardcoded URL in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1(req: Request, res: Response) {
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: 'https://example.com' });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 2: Using URL validation before Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2(req: Request, res: Response) {
    const targetUrl = req.query.url as string;
    
    // Validate URL against an allowlist
    const allowedDomains = ['example.com', 'trusted-site.org', 'safe-domain.net'];
    
    try {
        const parsedUrl = new URL(targetUrl);
        const isAllowed = allowedDomains.some(domain => parsedUrl.hostname === domain || 
                                              parsedUrl.hostname.endsWith('.' + domain));
        
        if (!isAllowed) {
            return res.status(403).send('URL not allowed');
        }
        
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 3: Using URL sanitization before Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3(req: Request, res: Response) {
    const unsafeUrl = req.query.url as string;
    
    // Sanitize URL
    const safeUrl = sanitizeUrl(unsafeUrl);
    
    // Additional validation
    if (!safeUrl.startsWith('https://')) {
        return res.status(403).send('Only HTTPS URLs are allowed');
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: safeUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 4: Using URL validation with regex before Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4(req: Request, res: Response) {
    const targetUrl = req.query.url as string;
    
    // Validate URL with regex
    const urlRegex = /^https:\/\/(www\.)?example\.com\/[a-zA-Z0-9\/_-]+$/;
    
    if (!urlRegex.test(targetUrl)) {
        return res.status(403).send('Invalid URL format or domain');
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 5: Using class-validator for URL validation before Page.navigate
class NavigationRequest {
    @IsUrl({
        protocols: ['https'],
        require_protocol: true,
        require_valid_protocol: true,
        host_whitelist: ['example.com', 'trusted-site.org']
    })
    url: string;
}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5(req: Request, res: Response) {
    const navigationRequest = new NavigationRequest();
    navigationRequest.url = req.query.url as string;
    
    const errors = await validate(navigationRequest);
    if (errors.length > 0) {
        return res.status(400).send('Invalid URL: ' + errors.toString());
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: navigationRequest.url });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 6: Using URL constructor for validation before Page.setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6(req: Request, res: Response) {
    const targetUrl = req.query.url as string;
    
    try {
        // Validate URL format
        const url = new URL(targetUrl);
        
        // Only allow specific domains
        if (url.hostname !== 'example.com' && !url.hostname.endsWith('.example.com')) {
            return res.status(403).send('Domain not allowed');
        }
        
        const client = await CDP();
        const { Page, Network } = client;
        await Page.enable();
        await Network.enable();
        
        // Fetch content from validated URL
        const response = await fetch(url.toString());
        const htmlContent = await response.text();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: htmlContent 
        });
        
        await client.close();
        res.send('Content set successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 7: Using HTML sanitization before Page.setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7(req: Request, res: Response) {
    const htmlContent = req.body.content;
    
    // Sanitize HTML content (simplified example)
    const sanitizedHtml = htmlContent
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/on\w+="[^"]*"/gi, '')
        .replace(/on\w+='[^']*'/gi, '');
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: sanitizedHtml 
        });
        
        await client.close();
        res.send('Content set successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 8: Using predefined templates for Page.setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8(req: Request, res: Response) {
    const userName = req.query.name as string;
    const userAge = req.query.age as string;
    
    // Use predefined template with user data inserted safely
    const templates = {
        userProfile: `<html><head><title>User Profile</title></head><body>
            <h1>User Profile</h1>
            <p>Name: ${userName ? userName.replace(/[<>]/g, '') : ''}</p>
            <p>Age: ${userAge ? parseInt(userAge, 10) : ''}</p>
        </body></html>`
    };
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: templates.userProfile 
        });
        
        await client.close();
        res.send('Content set successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 9: Using URL validation before Page.printToPDF
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9(req: Request, res: Response) {
    const targetUrl = req.query.url as string;
    
    try {
        // Validate URL
        const url = new URL(targetUrl);
        
        // Check protocol
        if (url.protocol !== 'https:') {
            return res.status(403).send('Only HTTPS URLs are allowed');
        }
        
        // Check domain
        const allowedDomains = ['example.com', 'docs.example.com'];
        if (!allowedDomains.includes(url.hostname)) {
            return res.status(403).send('Domain not allowed');
        }
        
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({ 
            url: url.toString(),
            printBackground: true 
        });
        
        await client.close();
        res.send('PDF generated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 10: Using environment variables for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10(req: Request, res: Response) {
    // Use environment variable instead of user input
    const targetUrl = process.env.TARGET_URL;
    
    if (!targetUrl) {
        return res.status(500).send('Target URL not configured');
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 11: Using configuration file for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11(req: Request, res: Response) {
    // In a real app, this would be loaded from a config file
    const config = {
        allowedUrls: {
            documentation: 'https://docs.example.com',
            homepage: 'https://www.example.com',
            dashboard: 'https://dashboard.example.com'
        }
    };
    
    const urlType = req.query.type as string;
    const targetUrl = config.allowedUrls[urlType];
    
    if (!targetUrl) {
        return res.status(400).send('Invalid URL type');
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 12: Using URL builder with validation for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12(req: Request, res: Response) {
    const productId = req.query.productId as string;
    
    // Validate productId format
    if (!/^[a-zA-Z0-9-_]{1,50}$/.test(productId)) {
        return res.status(400).send('Invalid product ID format');
    }
    
    // Build URL with validated components
    const baseUrl = 'https://products.example.com';
    const targetUrl = `${baseUrl}/product/${encodeURIComponent(productId)}`;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 13: Using database lookup for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13(req: Request, res: Response) {
    const pageId = req.query.pageId as string;
    
    // Simulate database lookup (in a real app, this would query a database)
    const getPageUrlFromDatabase = (id: string): string | null => {
        const pages = {
            'home': 'https://example.com',
            'about': 'https://example.com/about',
            'contact': 'https://example.com/contact'
        };
        return pages[id] || null;
    };
    
    const targetUrl = getPageUrlFromDatabase(pageId);
    
    if (!targetUrl) {
        return res.status(404).send('Page not found');
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 14: Using strict type checking for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14(req: Request, res: Response) {
    // Define allowed URLs as an enum for type safety
    enum AllowedUrl {
        HOME = 'https://example.com',
        ABOUT = 'https://example.com/about',
        CONTACT = 'https://example.com/contact'
    }
    
    const pageType = req.query.page as string;
    let targetUrl: AllowedUrl;
    
    switch (pageType) {
        case 'home':
            targetUrl = AllowedUrl.HOME;
            break;
        case 'about':
            targetUrl = AllowedUrl.ABOUT;
            break;
        case 'contact':
            targetUrl = AllowedUrl.CONTACT;
            break;
        default:
            return res.status(400).send('Invalid page type');
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 15: Using URL validation with custom function for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15(req: Request, res: Response) {
    const targetUrl = req.query.url as string;
    
    // Custom URL validation function
    const isUrlSafe = (url: string): boolean => {
        try {
            const parsedUrl = new URL(url);
            
            // Check protocol
            if (parsedUrl.protocol !== 'https:') {
                return false;
            }
            
            // Check domain
            const safeDomains = ['example.com', 'trusted-domain.org'];
            const isDomainSafe = safeDomains.some(domain => 
                parsedUrl.hostname === domain || 
                parsedUrl.hostname.endsWith('.' + domain)
            );
            
            if (!isDomainSafe) {
                return false;
            }
            
            // Check path
            if (parsedUrl.pathname.includes('../') || parsedUrl.pathname.includes('..\\')) {
                return false;
            }
            
            return true;
        } catch {
            return false;
        }
    };
    
    if (!isUrlSafe(targetUrl)) {
        return res.status(403).send('URL not allowed');
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        await client.close();
        res.send('Page navigated successfully');
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Start the server
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Define routes
app.get('/navigate', bad_case_1);
app.post('/navigate-post', bad_case_2);
app.get('/navigate-header', bad_case_3);
app.get('/navigate-cookie', bad_case_4);
app.post('/set-content', bad_case_5);
app.get('/set-content-query', bad_case_6);
app.get('/print-pdf', bad_case_7);
app.get('/navigate-combined', bad_case_8);
app.get('/navigate-concat', bad_case_9);
app.get('/navigate-template', bad_case_10);
app.get('/navigate-processed', bad_case_11);
app.get('/set-content-manipulated', bad_case_12);
app.get('/print-pdf-spread', bad_case_13);
app.get('/navigate-conditional', bad_case_14);
app.get('/navigate-array', bad_case_15);

app.get('/safe-navigate', good_case_1);
app.get('/safe-navigate-allowlist', good_case_2);
app.get('/safe-navigate-sanitize', good_case_3);
app.get('/safe-navigate-regex', good_case_4);
app.get('/safe-navigate-validator', good_case_5);
app.get('/safe-set-content-url', good_case_6);
app.post('/safe-set-content-sanitize', good_case_7);
app.get('/safe-set-content-template', good_case_8);
app.get('/safe-print-pdf', good_case_9);
app.get('/safe-navigate-env', good_case_10);
app.get('/safe-navigate-config', good_case_11);
app.get('/safe-navigate-builder', good_case_12);
app.get('/safe-navigate-db', good_case_13);
app.get('/safe-navigate-enum', good_case_14);
app.get('/safe-navigate-custom', good_case_15);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});