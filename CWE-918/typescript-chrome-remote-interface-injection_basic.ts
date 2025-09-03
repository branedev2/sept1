import * as CDP from 'chrome-remote-interface';
import * as http from 'http';
import * as express from 'express';
import * as url from 'url';
import * as fs from 'fs';
import { Request, Response } from 'express';

// TRUE POSITIVES - Vulnerable code examples

// Example 1: Using user input directly in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1(req: Request, res: Response) {
    const userUrl = req.query.url as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: userUrl });
        
        const result = await Page.captureScreenshot();
        res.send(`<img src="data:image/png;base64,${result.data}">`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 2: Using user input in setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2(req: Request, res: Response) {
    const userContent = req.body.content;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: userContent 
        });
        
        res.send('Content set');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 3: Using user input in printToPDF
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3(req: Request, res: Response) {
    const userMarginTop = req.query.marginTop as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({ 
            marginTop: userMarginTop 
        });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 4: Using multiple user inputs in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4(req: Request, res: Response) {
    const protocol = req.query.protocol as string;
    const domain = req.query.domain as string;
    const path = req.query.path as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        const fullUrl = `${protocol}://${domain}/${path}`;
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: fullUrl });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 5: Using user input from headers in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5(req: Request, res: Response) {
    const referer = req.headers.referer as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: referer });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 6: Using user input from cookies in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6(req: Request, res: Response) {
    const lastVisited = req.cookies.lastVisited;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: lastVisited });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 7: Using user input with string concatenation in setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7(req: Request, res: Response) {
    const userName = req.query.name as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        const html = `<html><body><h1>Hello, ${userName}</h1></body></html>`;
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: html 
        });
        
        res.send('Content set');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 8: Using user input in printToPDF with template literals
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8(req: Request, res: Response) {
    const userScale = req.query.scale as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({ 
            scale: Number(userScale) 
        });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 9: Using user input in Page.navigate with conditional logic
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9(req: Request, res: Response) {
    let targetUrl = 'https://example.com';
    
    if (req.query.customUrl) {
        targetUrl = req.query.customUrl as string;
    }
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 10: Using user input in setDocumentContent with JSON parsing
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10(req: Request, res: Response) {
    const userData = JSON.parse(req.body.userData);
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: `<pre>${JSON.stringify(userData, null, 2)}</pre>` 
        });
        
        res.send('Content set');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 11: Using user input in printToPDF with multiple parameters
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11(req: Request, res: Response) {
    const format = req.query.format as string;
    const landscape = req.query.landscape === 'true';
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({ 
            format: format,
            landscape: landscape
        });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 12: Using user input in Page.navigate with URL object
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12(req: Request, res: Response) {
    const userPath = req.query.path as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        const urlObj = new URL(userPath, 'https://example.com');
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: urlObj.toString() });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 13: Using user input in setDocumentContent with template
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13(req: Request, res: Response) {
    const userTitle = req.query.title as string;
    const userContent = req.body.content;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        const template = `
            <html>
                <head><title>${userTitle}</title></head>
                <body>${userContent}</body>
            </html>
        `;
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: template 
        });
        
        res.send('Content set');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 14: Using user input in printToPDF with object spread
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14(req: Request, res: Response) {
    const userOptions = {
        scale: req.query.scale ? Number(req.query.scale) : 1,
        landscape: req.query.landscape === 'true',
        pageRanges: req.query.pageRanges as string
    };
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({
            ...userOptions
        });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 15: Using user input in Page.navigate with array join
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15(req: Request, res: Response) {
    const segments = [
        req.query.protocol || 'https',
        '://',
        req.query.domain || 'example.com',
        '/',
        req.query.path || ''
    ];
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ruleid: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: segments.join('') });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// TRUE NEGATIVES - Safe code examples

// Example 1: Using hardcoded URL in Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1(req: Request, res: Response) {
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: 'https://example.com' });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 2: Using hardcoded content in setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2(req: Request, res: Response) {
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: '<html><body><h1>Hello, World!</h1></body></html>' 
        });
        
        res.send('Content set');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 3: Using hardcoded parameters in printToPDF
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3(req: Request, res: Response) {
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        // ok: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({ 
            format: 'A4',
            landscape: false,
            marginTop: 0.4
        });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 4: Validating URL in Page.navigate with allowlist
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4(req: Request, res: Response) {
    const userUrl = req.query.url as string;
    const allowedDomains = ['example.com', 'trusted-site.com', 'safe-domain.org'];
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // Validate URL against allowlist
        const urlObj = new URL(userUrl);
        if (!allowedDomains.includes(urlObj.hostname)) {
            throw new Error('Domain not allowed');
        }
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: userUrl });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error: Invalid or disallowed URL');
    }
}
// {/fact}

// Example 5: Sanitizing HTML content for setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5(req: Request, res: Response) {
    const userContent = req.body.content;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // Sanitize HTML content
        const sanitizedContent = sanitizeHtml(userContent, {
            allowedTags: ['h1', 'h2', 'p', 'b', 'i', 'em', 'strong'],
            allowedAttributes: {}
        });
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: sanitizedContent 
        });
        
        res.send('Content set');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Helper function for sanitizing HTML
function sanitizeHtml(html: string, options: any): string {
    // This is a simplified sanitizer for demonstration
    // In real code, use a proper HTML sanitizer library
    const { allowedTags } = options;
    let sanitized = html;
    
    // Strip all tags except allowed ones
    const tagPattern = /<\/?([a-z][a-z0-9]*)\b[^>]*>/gi;
    sanitized = sanitized.replace(tagPattern, (match, tag) => {
        return allowedTags.includes(tag.toLowerCase()) ? match : '';
    });
    
    return sanitized;
}

// Example 6: Validating printToPDF parameters
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6(req: Request, res: Response) {
    const userScale = req.query.scale ? Number(req.query.scale) : 1;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        // Validate scale parameter
        const scale = Math.min(Math.max(0.1, userScale), 2.0); // Limit between 0.1 and 2.0
        
        // ok: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({ 
            scale: scale 
        });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 7: Using URL validation library for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7(req: Request, res: Response) {
    const userUrl = req.query.url as string;
    
    try {
        // Validate URL format and safety
        if (!isValidUrl(userUrl)) {
            throw new Error('Invalid URL format');
        }
        
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: userUrl });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error: Invalid URL');
    }
}
// {/fact}

// Helper function for URL validation
function isValidUrl(urlString: string): boolean {
    try {
        const url = new URL(urlString);
        // Check for allowed protocols
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (err) {
        return false;
    }
}

// Example 8: Using template with safe interpolation for setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8(req: Request, res: Response) {
    const userName = req.query.name as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // Escape HTML special characters
        const escapedName = escapeHtml(userName);
        const html = `<html><body><h1>Hello, ${escapedName}</h1></body></html>`;
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: html 
        });
        
        res.send('Content set');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Helper function for HTML escaping
function escapeHtml(unsafe: string): string {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Example 9: Using configuration object for printToPDF
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9(req: Request, res: Response) {
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        const pdfConfig = {
            format: 'A4',
            landscape: false,
            printBackground: true,
            marginTop: 0.4,
            marginBottom: 0.4,
            marginLeft: 0.4,
            marginRight: 0.4
        };
        
        // ok: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF(pdfConfig);
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 10: Using URL builder pattern for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10(req: Request, res: Response) {
    const productId = req.query.productId as string;
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // Build URL safely
        const baseUrl = 'https://example.com/products/';
        const urlBuilder = new URLBuilder(baseUrl);
        urlBuilder.addPathSegment(encodeURIComponent(productId));
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: urlBuilder.toString() });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Helper class for URL building
class URLBuilder {
    private url: URL;
    
    constructor(baseUrl: string) {
        this.url = new URL(baseUrl);
    }
    
    addPathSegment(segment: string): URLBuilder {
        this.url.pathname = this.url.pathname.replace(/\/$/, '') + '/' + segment;
        return this;
    }
    
    addQueryParam(key: string, value: string): URLBuilder {
        this.url.searchParams.append(key, value);
        return this;
    }
    
    toString(): string {
        return this.url.toString();
    }
}

// Example 11: Using environment variables for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11(req: Request, res: Response) {
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        // Get URL from environment variable
        const targetUrl = process.env.TARGET_URL || 'https://example.com';
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 12: Using content from file for setDocumentContent
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12(req: Request, res: Response) {
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'about:blank' });
        
        // Read HTML from a trusted file
        const htmlContent = fs.readFileSync('./templates/welcome.html', 'utf8');
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.setDocumentContent({ 
            frameId: '1', 
            html: htmlContent 
        });
        
        res.send('Content set');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 13: Using validated parameters for printToPDF
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13(req: Request, res: Response) {
    const format = req.query.format as string;
    const validFormats = ['A4', 'A3', 'Letter', 'Legal'];
    
    try {
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        // Validate format parameter
        const safeFormat = validFormats.includes(format) ? format : 'A4';
        
        // ok: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF({ 
            format: safeFormat
        });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Example 14: Using URL composition with validation for Page.navigate
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14(req: Request, res: Response) {
    const productId = req.query.id as string;
    
    try {
        // Validate product ID format
        if (!/^\d+$/.test(productId)) {
            throw new Error('Invalid product ID');
        }
        
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        
        const targetUrl = `https://example.com/products/${productId}`;
        
        // ok: chrome-remote-interface-injection-ts-rule
        await Page.navigate({ url: targetUrl });
        
        res.send('Navigation successful');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error: ' + err.message);
    }
}
// {/fact}

// Example 15: Using configuration from database for printToPDF
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15(req: Request, res: Response) {
    const configId = req.query.configId as string;
    
    try {
        // Get configuration from database (simulated)
        const pdfConfig = await getPdfConfigFromDatabase(configId);
        
        const client = await CDP();
        const { Page } = client;
        await Page.enable();
        await Page.navigate({ url: 'https://example.com' });
        
        // ok: chrome-remote-interface-injection-ts-rule
        const pdf = await Page.printToPDF(pdfConfig);
        
        res.setHeader('Content-Type', 'application/pdf');
        res.send(Buffer.from(pdf.data, 'base64'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error');
    }
}
// {/fact}

// Helper function to simulate getting config from database
async function getPdfConfigFromDatabase(configId: string): Promise<any> {
    // In a real application, this would fetch from a database
    const configs: {[key: string]: any} = {
        'default': {
            format: 'A4',
            landscape: false,
            printBackground: true
        },
        'brochure': {
            format: 'A3',
            landscape: true,
            printBackground: true
        }
    };
    
    return configs[configId] || configs['default'];
}