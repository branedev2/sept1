import { chromium, Page, Browser } from 'playwright';
import express from 'express';
import { Request, Response } from 'express';
import * as http from 'http';
import * as https from 'https';
import * as url from 'url';
import * as fs from 'fs';
import * as path from 'path';
import { sanitizeHtml } from 'sanitize-html';
import { JSDOM } from 'jsdom';
import DOMPurify from 'dompurify';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1() {
    const app = express();
    
    app.get('/screenshot', async (req: Request, res: Response) => {
        const userHtml = req.query.html as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(userHtml);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2() {
    const app = express();
    
    app.post('/render', async (req: Request, res: Response) => {
        const userTemplate = req.body.template;
        
        const browser = await chromium.launch();
        const context = await browser.newContext();
        const page = await context.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`<div>${userTemplate}</div>`);
        
        const content = await page.content();
        await browser.close();
        
        res.send(content);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3() {
    const app = express();
    
    app.get('/preview', async (req: Request, res: Response) => {
        const headerContent = req.headers['x-custom-template'] as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(headerContent);
        
        const pdf = await page.pdf();
        await browser.close();
        
        res.contentType('application/pdf');
        res.send(pdf);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4() {
    const app = express();
    
    app.get('/generate-report', async (req: Request, res: Response) => {
        const reportTemplate = req.query.template as string;
        const userName = req.query.user as string;
        
        const htmlContent = `
            <html>
                <head><title>Report for ${userName}</title></head>
                <body>${reportTemplate}</body>
            </html>
        `;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(htmlContent);
        
        const reportContent = await page.content();
        await browser.close();
        
        res.send(reportContent);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5() {
    const app = express();
    
    app.post('/email-preview', async (req: Request, res: Response) => {
        const emailBody = req.body.emailContent;
        const recipient = req.body.recipient;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div style="border: 1px solid #ccc; padding: 20px;">
                <h2>Email Preview to: ${recipient}</h2>
                <div>${emailBody}</div>
            </div>
        `);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6() {
    const app = express();
    
    app.get('/render-markdown', async (req: Request, res: Response) => {
        const markdownContent = req.query.markdown as string;
        
        // Simple markdown to HTML conversion (insecure for demonstration)
        const htmlContent = markdownContent
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/\n/g, '<br>');
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(htmlContent);
        
        const renderedContent = await page.content();
        await browser.close();
        
        res.send(renderedContent);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7() {
    const app = express();
    
    app.post('/process-form', async (req: Request, res: Response) => {
        const formData = req.body;
        let formHtml = '<h2>Form Submission Preview</h2><dl>';
        
        for (const [key, value] of Object.entries(formData)) {
            formHtml += `<dt>${key}</dt><dd>${value}</dd>`;
        }
        
        formHtml += '</dl>';
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(formHtml);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8() {
    const app = express();
    
    app.get('/dynamic-page', async (req: Request, res: Response) => {
        const pageTitle = req.query.title as string;
        const pageContent = req.query.content as string;
        const pageFooter = req.query.footer as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <html>
                <head><title>${pageTitle}</title></head>
                <body>
                    <header><h1>${pageTitle}</h1></header>
                    <main>${pageContent}</main>
                    <footer>${pageFooter}</footer>
                </body>
            </html>
        `);
        
        const renderedPage = await page.content();
        await browser.close();
        
        res.send(renderedPage);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9() {
    const app = express();
    
    app.get('/iframe-preview', async (req: Request, res: Response) => {
        const iframeSrc = req.query.src as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <html>
                <body>
                    <h2>External Content Preview</h2>
                    <iframe src="${iframeSrc}" width="800" height="600"></iframe>
                </body>
            </html>
        `);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10() {
    const app = express();
    
    app.post('/custom-widget', async (req: Request, res: Response) => {
        const widgetType = req.body.type;
        const widgetData = req.body.data;
        
        let widgetHtml = '';
        if (widgetType === 'chart') {
            widgetHtml = `<div class="chart">${widgetData}</div>`;
        } else if (widgetType === 'table') {
            widgetHtml = `<div class="table">${widgetData}</div>`;
        } else {
            widgetHtml = `<div class="generic">${widgetData}</div>`;
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(widgetHtml);
        
        const renderedWidget = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(renderedWidget);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11() {
    const app = express();
    
    app.get('/user-profile', async (req: Request, res: Response) => {
        const userId = req.query.id as string;
        const userName = req.query.name as string;
        const userBio = req.query.bio as string;
        
        // Fetch user data from database (simulated)
        const userData = {
            id: userId,
            name: userName,
            bio: userBio
        };
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="profile">
                <h1>${userData.name}</h1>
                <p>${userData.bio}</p>
                <small>User ID: ${userData.id}</small>
            </div>
        `);
        
        const profileHtml = await page.content();
        await browser.close();
        
        res.send(profileHtml);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12() {
    const app = express();
    
    app.get('/comment-preview', async (req: Request, res: Response) => {
        const commentText = req.query.text as string;
        const userName = req.query.user as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        const timestamp = new Date().toISOString();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="comment">
                <div class="comment-header">
                    <span class="user">${userName}</span>
                    <span class="date">${timestamp}</span>
                </div>
                <div class="comment-body">${commentText}</div>
            </div>
        `);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13() {
    const app = express();
    
    app.post('/product-card', async (req: Request, res: Response) => {
        const productName = req.body.name;
        const productDesc = req.body.description;
        const productPrice = req.body.price;
        const productImage = req.body.image;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="product-card">
                <img src="${productImage}" alt="${productName}">
                <h3>${productName}</h3>
                <p>${productDesc}</p>
                <div class="price">$${productPrice}</div>
                <button>Add to Cart</button>
            </div>
        `);
        
        const cardImage = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(cardImage);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14() {
    const app = express();
    
    app.get('/social-share', async (req: Request, res: Response) => {
        const pageUrl = req.query.url as string;
        const pageTitle = req.query.title as string;
        const pageDesc = req.query.description as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="social-share-preview">
                <h2>Share Preview</h2>
                <div class="preview-card">
                    <h3>${pageTitle}</h3>
                    <p>${pageDesc}</p>
                    <a href="${pageUrl}">${pageUrl}</a>
                </div>
                <div class="share-buttons">
                    <button>Facebook</button>
                    <button>Twitter</button>
                    <button>LinkedIn</button>
                </div>
            </div>
        `);
        
        const previewImage = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(previewImage);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15() {
    const app = express();
    
    app.get('/event-ticket', async (req: Request, res: Response) => {
        const eventName = req.query.event as string;
        const attendeeName = req.query.attendee as string;
        const eventDate = req.query.date as string;
        const ticketId = req.query.id as string;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ruleid: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="ticket">
                <h1>${eventName}</h1>
                <div class="ticket-details">
                    <p>Attendee: ${attendeeName}</p>
                    <p>Date: ${eventDate}</p>
                    <p>Ticket ID: ${ticketId}</p>
                </div>
                <div class="qr-code">
                    <!-- QR code would be generated here -->
                </div>
            </div>
        `);
        
        const ticketImage = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(ticketImage);
    });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1() {
    const app = express();
    
    app.get('/screenshot', async (req: Request, res: Response) => {
        const userHtml = req.query.html as string;
        
        // Sanitize the HTML to prevent SSRF
        const sanitizedHtml = sanitizeHtml(userHtml, {
            allowedTags: ['h1', 'h2', 'p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li'],
            allowedAttributes: {
                'a': ['href']
            },
            allowedIframeHostnames: []
        });
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(sanitizedHtml);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2() {
    const app = express();
    
    app.post('/render', async (req: Request, res: Response) => {
        const userTemplate = req.body.template;
        
        // Use DOMPurify to sanitize HTML
        const window = new JSDOM('').window;
        const purify = DOMPurify(window);
        const sanitizedTemplate = purify.sanitize(userTemplate);
        
        const browser = await chromium.launch();
        const context = await browser.newContext();
        const page = await context.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`<div>${sanitizedTemplate}</div>`);
        
        const content = await page.content();
        await browser.close();
        
        res.send(content);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3() {
    const app = express();
    
    app.get('/preview', async (req: Request, res: Response) => {
        // Use predefined templates instead of user input
        const templateId = req.query.templateId as string;
        let templateContent = '';
        
        // Only allow selection from predefined templates
        const templates = {
            'invoice': '<div class="invoice">Invoice Template</div>',
            'report': '<div class="report">Report Template</div>',
            'letter': '<div class="letter">Letter Template</div>'
        };
        
        if (templateId in templates) {
            templateContent = templates[templateId as keyof typeof templates];
        } else {
            templateContent = '<div>Default template</div>';
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(templateContent);
        
        const pdf = await page.pdf();
        await browser.close();
        
        res.contentType('application/pdf');
        res.send(pdf);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4() {
    const app = express();
    
    app.get('/generate-report', async (req: Request, res: Response) => {
        const userName = req.query.user as string;
        
        // Escape HTML special characters to prevent injection
        const escapeHtml = (unsafe: string): string => {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        };
        
        const safeUserName = escapeHtml(userName);
        
        // Use a safe, predefined template
        const htmlContent = `
            <html>
                <head><title>Report for ${safeUserName}</title></head>
                <body>
                    <h1>Report for ${safeUserName}</h1>
                    <p>This is a safe, predefined report template.</p>
                </body>
            </html>
        `;
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(htmlContent);
        
        const reportContent = await page.content();
        await browser.close();
        
        res.send(reportContent);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5() {
    const app = express();
    
    app.post('/email-preview', async (req: Request, res: Response) => {
        const emailBody = req.body.emailContent;
        const recipient = req.body.recipient;
        
        // Sanitize inputs
        const sanitizedEmailBody = sanitizeHtml(emailBody);
        const sanitizedRecipient = sanitizeHtml(recipient);
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div style="border: 1px solid #ccc; padding: 20px;">
                <h2>Email Preview to: ${sanitizedRecipient}</h2>
                <div>${sanitizedEmailBody}</div>
            </div>
        `);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6() {
    const app = express();
    
    app.get('/render-markdown', async (req: Request, res: Response) => {
        const markdownContent = req.query.markdown as string;
        
        // Use a proper markdown library that handles sanitization
        // This is a simplified example - in practice, use a real markdown library
        const convertMarkdownSafely = (markdown: string): string => {
            // First sanitize to remove any HTML
            const sanitized = sanitizeHtml(markdown, { allowedTags: [] });
            
            // Then convert markdown to HTML safely
            return sanitized
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                .replace(/\n/g, '<br>');
        };
        
        const safeHtml = convertMarkdownSafely(markdownContent);
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(safeHtml);
        
        const renderedContent = await page.content();
        await browser.close();
        
        res.send(renderedContent);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7() {
    const app = express();
    
    app.post('/process-form', async (req: Request, res: Response) => {
        const formData = req.body;
        let formHtml = '<h2>Form Submission Preview</h2><dl>';
        
        // Sanitize each form field
        for (const [key, value] of Object.entries(formData)) {
            const safeKey = sanitizeHtml(key);
            const safeValue = sanitizeHtml(value as string);
            formHtml += `<dt>${safeKey}</dt><dd>${safeValue}</dd>`;
        }
        
        formHtml += '</dl>';
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(formHtml);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8() {
    const app = express();
    
    app.get('/dynamic-page', async (req: Request, res: Response) => {
        // Validate inputs against a whitelist of allowed values
        const allowedTitles = ['Welcome', 'About Us', 'Contact', 'Products'];
        const allowedFooters = ['Copyright 2023', 'Terms of Service', 'Privacy Policy'];
        
        let pageTitle = req.query.title as string;
        const pageContent = sanitizeHtml(req.query.content as string);
        let pageFooter = req.query.footer as string;
        
        // Ensure title is from allowed list
        if (!allowedTitles.includes(pageTitle)) {
            pageTitle = 'Default Title';
        }
        
        // Ensure footer is from allowed list
        if (!allowedFooters.includes(pageFooter)) {
            pageFooter = 'Copyright 2023';
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <html>
                <head><title>${pageTitle}</title></head>
                <body>
                    <header><h1>${pageTitle}</h1></header>
                    <main>${pageContent}</main>
                    <footer>${pageFooter}</footer>
                </body>
            </html>
        `);
        
        const renderedPage = await page.content();
        await browser.close();
        
        res.send(renderedPage);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9() {
    const app = express();
    
    app.get('/iframe-preview', async (req: Request, res: Response) => {
        const iframeSrc = req.query.src as string;
        
        // Validate URL against whitelist
        const allowedDomains = ['trusted-domain.com', 'safe-site.org', 'company-cdn.net'];
        
        let isSafeUrl = false;
        try {
            const urlObj = new URL(iframeSrc);
            isSafeUrl = allowedDomains.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain));
        } catch (e) {
            isSafeUrl = false;
        }
        
        const safeIframeSrc = isSafeUrl ? iframeSrc : 'about:blank';
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <html>
                <body>
                    <h2>External Content Preview</h2>
                    <iframe src="${safeIframeSrc}" width="800" height="600"></iframe>
                </body>
            </html>
        `);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10() {
    const app = express();
    
    app.post('/custom-widget', async (req: Request, res: Response) => {
        const widgetType = req.body.type;
        const widgetData = req.body.data;
        
        // Validate widget type against allowed types
        const allowedWidgetTypes = ['chart', 'table', 'generic'];
        const safeWidgetType = allowedWidgetTypes.includes(widgetType) ? widgetType : 'generic';
        
        // Sanitize widget data
        const safeWidgetData = sanitizeHtml(widgetData);
        
        let widgetHtml = '';
        if (safeWidgetType === 'chart') {
            widgetHtml = `<div class="chart">${safeWidgetData}</div>`;
        } else if (safeWidgetType === 'table') {
            widgetHtml = `<div class="table">${safeWidgetData}</div>`;
        } else {
            widgetHtml = `<div class="generic">${safeWidgetData}</div>`;
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(widgetHtml);
        
        const renderedWidget = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(renderedWidget);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11() {
    const app = express();
    
    app.get('/user-profile', async (req: Request, res: Response) => {
        const userId = req.query.id as string;
        const userName = req.query.name as string;
        const userBio = req.query.bio as string;
        
        // Sanitize user data
        const safeUserId = sanitizeHtml(userId);
        const safeUserName = sanitizeHtml(userName);
        const safeUserBio = sanitizeHtml(userBio);
        
        // Fetch user data from database (simulated)
        const userData = {
            id: safeUserId,
            name: safeUserName,
            bio: safeUserBio
        };
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="profile">
                <h1>${userData.name}</h1>
                <p>${userData.bio}</p>
                <small>User ID: ${userData.id}</small>
            </div>
        `);
        
        const profileHtml = await page.content();
        await browser.close();
        
        res.send(profileHtml);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12() {
    const app = express();
    
    app.get('/comment-preview', async (req: Request, res: Response) => {
        const commentText = req.query.text as string;
        const userName = req.query.user as string;
        
        // Sanitize inputs
        const safeCommentText = sanitizeHtml(commentText);
        const safeUserName = sanitizeHtml(userName);
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        const timestamp = new Date().toISOString();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="comment">
                <div class="comment-header">
                    <span class="user">${safeUserName}</span>
                    <span class="date">${timestamp}</span>
                </div>
                <div class="comment-body">${safeCommentText}</div>
            </div>
        `);
        
        const screenshot = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(screenshot);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13() {
    const app = express();
    
    app.post('/product-card', async (req: Request, res: Response) => {
        const productName = req.body.name;
        const productDesc = req.body.description;
        const productPrice = req.body.price;
        const productImage = req.body.image;
        
        // Sanitize inputs
        const safeProductName = sanitizeHtml(productName);
        const safeProductDesc = sanitizeHtml(productDesc);
        
        // Validate price is a number
        const safeProductPrice = typeof productPrice === 'number' ? 
            productPrice.toFixed(2) : '0.00';
        
        // Validate image URL against whitelist
        const allowedImageDomains = ['company-cdn.net', 'trusted-images.com'];
        let safeProductImage = '/default-product.jpg';
        
        try {
            const imageUrl = new URL(productImage);
            const isAllowedDomain = allowedImageDomains.some(
                domain => imageUrl.hostname === domain || 
                imageUrl.hostname.endsWith('.' + domain)
            );
            
            if (isAllowedDomain) {
                safeProductImage = productImage;
            }
        } catch (e) {
            // Invalid URL, use default
        }
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="product-card">
                <img src="${safeProductImage}" alt="${safeProductName}">
                <h3>${safeProductName}</h3>
                <p>${safeProductDesc}</p>
                <div class="price">$${safeProductPrice}</div>
                <button>Add to Cart</button>
            </div>
        `);
        
        const cardImage = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(cardImage);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14() {
    const app = express();
    
    app.get('/social-share', async (req: Request, res: Response) => {
        const pageUrl = req.query.url as string;
        const pageTitle = req.query.title as string;
        const pageDesc = req.query.description as string;
        
        // Validate URL
        let safePageUrl = '#';
        try {
            const urlObj = new URL(pageUrl);
            // Only allow HTTP and HTTPS URLs
            if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
                safePageUrl = pageUrl;
            }
        } catch (e) {
            // Invalid URL, use default
        }
        
        // Sanitize text content
        const safePageTitle = sanitizeHtml(pageTitle);
        const safePageDesc = sanitizeHtml(pageDesc);
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="social-share-preview">
                <h2>Share Preview</h2>
                <div class="preview-card">
                    <h3>${safePageTitle}</h3>
                    <p>${safePageDesc}</p>
                    <a href="${safePageUrl}">${safePageUrl}</a>
                </div>
                <div class="share-buttons">
                    <button>Facebook</button>
                    <button>Twitter</button>
                    <button>LinkedIn</button>
                </div>
            </div>
        `);
        
        const previewImage = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(previewImage);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15() {
    const app = express();
    
    app.get('/event-ticket', async (req: Request, res: Response) => {
        const eventName = req.query.event as string;
        const attendeeName = req.query.attendee as string;
        const eventDate = req.query.date as string;
        const ticketId = req.query.id as string;
        
        // Sanitize all inputs
        const safeEventName = sanitizeHtml(eventName);
        const safeAttendeeName = sanitizeHtml(attendeeName);
        const safeEventDate = sanitizeHtml(eventDate);
        
        // Validate ticket ID format (assuming it should be alphanumeric)
        const ticketIdPattern = /^[A-Za-z0-9-]+$/;
        const safeTicketId = ticketIdPattern.test(ticketId) ? ticketId : 'INVALID';
        
        const browser = await chromium.launch();
        const page = await browser.newPage();
        
        // ok: playwright-setcontent-injection-ts-rule
        await page.setContent(`
            <div class="ticket">
                <h1>${safeEventName}</h1>
                <div class="ticket-details">
                    <p>Attendee: ${safeAttendeeName}</p>
                    <p>Date: ${safeEventDate}</p>
                    <p>Ticket ID: ${safeTicketId}</p>
                </div>
                <div class="qr-code">
                    <!-- QR code would be generated here -->
                </div>
            </div>
        `);
        
        const ticketImage = await page.screenshot();
        await browser.close();
        
        res.contentType('image/png');
        res.send(ticketImage);
    });
}
// {/fact}