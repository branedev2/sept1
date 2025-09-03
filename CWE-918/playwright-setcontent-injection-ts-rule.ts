import { Page, Browser, BrowserContext } from 'playwright';
import express from 'express';
import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import { URL } from 'url';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1(req: express.Request, res: express.Response) {
    const browser = await require('playwright').chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    const userInput = req.query.content as string;
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(userInput);
    
    await browser.close();
    res.send('Content set');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2(req: express.Request, res: express.Response) {
    const { chromium } = require('playwright');
    const browser = await chromium.launch();
    const page = await browser.newPage();
    const userTemplate = req.body.template;
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(`<div>${userTemplate}</div>`);
    
    const screenshot = await page.screenshot();
    await browser.close();
    res.send(screenshot);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.firefox.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const headerContent = req.headers['x-custom-content'] as string;
    let processedContent = '';
    
    if (headerContent) {
        processedContent = headerContent.replace(/script/gi, '');
    }
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(processedContent);
    
    await browser.close();
    res.send('Done');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4(req: express.Request, res: express.Response) {
    const { webkit } = require('playwright');
    const browser = await webkit.launch();
    const page = await browser.newPage();
    
    const userContent = req.cookies.content;
    let htmlContent = '';
    
    switch (req.query.type) {
        case 'article':
            htmlContent = `<article>${userContent}</article>`;
            break;
        case 'section':
            htmlContent = `<section>${userContent}</section>`;
            break;
        default:
            htmlContent = `<div>${userContent}</div>`;
    }
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(htmlContent);
    
    await browser.close();
    res.send('Content processed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.chromium.launch();
    const page = await browser.newPage();
    
    const contentParts = [];
    if (req.query.header) contentParts.push(`<header>${req.query.header}</header>`);
    if (req.query.body) contentParts.push(`<main>${req.query.body}</main>`);
    if (req.query.footer) contentParts.push(`<footer>${req.query.footer}</footer>`);
    
    const fullContent = contentParts.join('');
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(fullContent);
    
    await browser.close();
    res.send('Page rendered');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6(req: express.Request, res: express.Response) {
    const { chromium } = require('playwright');
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    let userInput = '';
    for (const key in req.query) {
        userInput += `<p>${key}: ${req.query[key]}</p>`;
    }
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(`<div class="container">${userInput}</div>`);
    
    await browser.close();
    res.send('Query parameters displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.firefox.launch();
    const page = await browser.newPage();
    
    const userId = req.params.id;
    const userData = await fetchUserData(userId);
    const userGeneratedContent = userData.content; // Content from database that was originally from user input
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(userGeneratedContent);
    
    await browser.close();
    res.send('User content displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8(req: express.Request, res: express.Response) {
    const { webkit } = require('playwright');
    const browser = await webkit.launch();
    const page = await browser.newPage();
    
    const referer = req.headers.referer as string;
    const contentWithReferer = `<html><body>You came from: ${referer}</body></html>`;
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(contentWithReferer);
    
    await browser.close();
    res.send('Referer displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const userAgent = req.headers['user-agent'] as string;
    let template = '';
    
    if (userAgent.includes('Mobile')) {
        template = req.body.mobileTemplate;
    } else {
        template = req.body.desktopTemplate;
    }
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(template);
    
    await browser.close();
    res.send('Template rendered based on device');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10(req: express.Request, res: express.Response) {
    const { chromium } = require('playwright');
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const contentType = req.query.type as string || 'text';
    const userContent = req.body.content;
    
    let formattedContent = '';
    if (contentType === 'html') {
        formattedContent = userContent;
    } else if (contentType === 'markdown') {
        formattedContent = convertMarkdownToHtml(userContent);
    } else {
        formattedContent = `<pre>${userContent}</pre>`;
    }
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(formattedContent);
    
    await browser.close();
    res.send('Content formatted and displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.firefox.launch();
    const page = await browser.newPage();
    
    const language = req.query.lang as string || 'en';
    const translations = {
        en: req.body.english,
        es: req.body.spanish,
        fr: req.body.french
    };
    
    const content = translations[language] || translations.en;
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(`<div lang="${language}">${content}</div>`);
    
    await browser.close();
    res.send('Localized content displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12(req: express.Request, res: express.Response) {
    const { webkit } = require('playwright');
    const browser = await webkit.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const theme = req.cookies.theme || 'light';
    const userHtml = req.body.html;
    
    const styledContent = `
        <html>
            <head>
                <style>
                    body { background-color: ${theme === 'dark' ? '#333' : '#fff'}; }
                </style>
            </head>
            <body>
                ${userHtml}
            </body>
        </html>
    `;
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(styledContent);
    
    await browser.close();
    res.send('Themed content displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.chromium.launch();
    const page = await browser.newPage();
    
    const searchQuery = req.query.q as string;
    const searchResults = await performSearch(searchQuery);
    
    let resultsHtml = '<ul>';
    for (const result of searchResults) {
        resultsHtml += `<li>${result.title} - ${result.description}</li>`;
    }
    resultsHtml += '</ul>';
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(`
        <html>
            <body>
                <h1>Search Results for: ${searchQuery}</h1>
                ${resultsHtml}
            </body>
        </html>
    `);
    
    await browser.close();
    res.send('Search results displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14(req: express.Request, res: express.Response) {
    const { chromium } = require('playwright');
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const commentAuthor = req.body.author;
    const commentText = req.body.comment;
    const timestamp = new Date().toISOString();
    
    const commentHtml = `
        <div class="comment">
            <h3>${commentAuthor}</h3>
            <p>${commentText}</p>
            <small>${timestamp}</small>
        </div>
    `;
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(commentHtml);
    
    await browser.close();
    res.send('Comment preview generated');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.firefox.launch();
    const page = await browser.newPage();
    
    const profileData = {
        name: req.body.name,
        bio: req.body.bio,
        avatar: req.body.avatar
    };
    
    const profileHtml = `
        <div class="profile">
            <img src="${profileData.avatar}" alt="Profile picture">
            <h2>${profileData.name}</h2>
            <p>${profileData.bio}</p>
        </div>
    `;
    
    // ruleid: playwright-setcontent-injection-ts-rule
    await page.setContent(profileHtml);
    
    await browser.close();
    res.send('Profile preview generated');
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1(req: express.Request, res: express.Response) {
    const browser = await require('playwright').chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent('<h1>Static content</h1><p>This is safe</p>');
    
    await browser.close();
    res.send('Content set safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2(req: express.Request, res: express.Response) {
    const { chromium } = require('playwright');
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    const safeTemplates = {
        article: '<article><h1>Article Title</h1><p>Content here</p></article>',
        section: '<section><h2>Section Title</h2><p>Section content</p></section>'
    };
    
    const templateType = req.query.type as string;
    const template = safeTemplates[templateType] || safeTemplates.article;
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(template);
    
    await browser.close();
    res.send('Safe template used');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.firefox.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const userInput = req.query.content as string;
    const sanitizedContent = sanitizeHtml(userInput, {
        allowedTags: ['b', 'i', 'em', 'strong', 'p'],
        allowedAttributes: {}
    });
    
    const safeHtml = `<div class="user-content">${sanitizedContent}</div>`;
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(safeHtml);
    
    await browser.close();
    res.send('Content sanitized and set');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4(req: express.Request, res: express.Response) {
    const { webkit } = require('playwright');
    const browser = await webkit.launch();
    const page = await browser.newPage();
    
    const allowedValues = ['product', 'service', 'about'];
    const pageType = req.query.type as string;
    
    let htmlContent = '<div>Default content</div>';
    
    if (allowedValues.includes(pageType)) {
        htmlContent = getStaticTemplate(pageType);
    }
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(htmlContent);
    
    await browser.close();
    res.send('Safe template selected');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.chromium.launch();
    const page = await browser.newPage();
    
    const userId = req.params.id;
    // Validate userId is numeric
    if (!/^\d+$/.test(userId)) {
        res.status(400).send('Invalid user ID');
        return;
    }
    
    const userData = await fetchUserData(parseInt(userId, 10));
    const escapedName = escapeHtml(userData.name);
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(`<h1>User Profile: ${escapedName}</h1>`);
    
    await browser.close();
    res.send('User profile displayed safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6(req: express.Request, res: express.Response) {
    const { chromium } = require('playwright');
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Using a predefined template with placeholders
    const template = `
        <html>
            <head><title>Product Page</title></head>
            <body>
                <h1>{{productName}}</h1>
                <p>{{productDescription}}</p>
                <p>Price: ${{productPrice}}</p>
            </body>
        </html>
    `;
    
    // Replace placeholders with sanitized data
    const productName = escapeHtml(req.query.name as string);
    const productDescription = escapeHtml(req.query.description as string);
    const productPrice = parseFloat(req.query.price as string).toFixed(2);
    
    const safeContent = template
        .replace('{{productName}}', productName)
        .replace('{{productDescription}}', productDescription)
        .replace('{{productPrice}}', productPrice);
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(safeContent);
    
    await browser.close();
    res.send('Product page rendered safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.firefox.launch();
    const page = await browser.newPage();
    
    const allowedThemes = ['light', 'dark', 'blue', 'green'];
    const theme = allowedThemes.includes(req.query.theme as string) 
        ? req.query.theme 
        : 'light';
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(`
        <html>
            <head>
                <link rel="stylesheet" href="/themes/${theme}.css">
            </head>
            <body>
                <h1>Welcome to our site</h1>
                <p>This is a safe page with theme: ${theme}</p>
            </body>
        </html>
    `);
    
    await browser.close();
    res.send('Themed page rendered safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8(req: express.Request, res: express.Response) {
    const { webkit } = require('playwright');
    const browser = await webkit.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const contentId = req.query.id as string;
    // Validate contentId is alphanumeric
    if (!/^[a-zA-Z0-9-]+$/.test(contentId)) {
        res.status(400).send('Invalid content ID');
        return;
    }
    
    // Load predefined content from a safe source
    const safeContent = await loadContentFromDatabase(contentId);
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(safeContent);
    
    await browser.close();
    res.send('Content loaded safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.chromium.launch();
    const page = await browser.newPage();
    
    // Using a template engine with auto-escaping
    const templateData = {
        title: req.query.title,
        message: req.query.message,
        username: req.query.username
    };
    
    const safeHtml = renderTemplate('welcome', templateData);
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(safeHtml);
    
    await browser.close();
    res.send('Template rendered safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10(req: express.Request, res: express.Response) {
    const { chromium } = require('playwright');
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Using DOMPurify to sanitize HTML
    const userHtml = req.body.html;
    const sanitizedHtml = DOMPurify.sanitize(userHtml, {
        ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a'],
        ALLOWED_ATTR: ['href']
    });
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(`
        <html>
            <head><title>Sanitized Content</title></head>
            <body>
                <div class="safe-content">${sanitizedHtml}</div>
            </body>
        </html>
    `);
    
    await browser.close();
    res.send('Content sanitized and displayed safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.firefox.launch();
    const page = await browser.newPage();
    
    // Using a whitelist of allowed values
    const allowedPages = {
        home: '<h1>Home Page</h1><p>Welcome to our site!</p>',
        about: '<h1>About Us</h1><p>Learn more about our company.</p>',
        contact: '<h1>Contact Us</h1><p>Get in touch with our team.</p>'
    };
    
    const pageKey = req.query.page as string;
    const content = allowedPages[pageKey] || allowedPages.home;
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(content);
    
    await browser.close();
    res.send('Safe page content displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12(req: express.Request, res: express.Response) {
    const { webkit } = require('playwright');
    const browser = await webkit.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Using a safe HTML builder
    const htmlBuilder = new SafeHtmlBuilder();
    htmlBuilder.addHeading('Search Results', 1);
    
    const searchQuery = req.query.q as string;
    htmlBuilder.addParagraph(`You searched for: ${htmlBuilder.escapeText(searchQuery)}`);
    
    const results = await performSearch(searchQuery);
    htmlBuilder.startList();
    for (const result of results) {
        htmlBuilder.addListItem(`${htmlBuilder.escapeText(result.title)}`);
    }
    htmlBuilder.endList();
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(htmlBuilder.getHtml());
    
    await browser.close();
    res.send('Search results displayed safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.chromium.launch();
    const page = await browser.newPage();
    
    // Using constant HTML with dynamic data inserted safely
    const username = escapeHtml(req.query.username as string);
    const loginTime = new Date().toLocaleString();
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(`
        <html>
            <body>
                <div class="welcome-message">
                    <h1>Welcome, ${username}!</h1>
                    <p>You logged in at: ${loginTime}</p>
                    <p>Thank you for using our service.</p>
                </div>
            </body>
        </html>
    `);
    
    await browser.close();
    res.send('Welcome page displayed safely');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14(req: express.Request, res: express.Response) {
    const { chromium } = require('playwright');
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Using a content security policy
    const safeContent = `
        <html>
            <head>
                <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
                <title>Secure Page</title>
            </head>
            <body>
                <h1>Secure Content</h1>
                <p>This page has a strict CSP.</p>
            </body>
        </html>
    `;
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(safeContent);
    
    await browser.close();
    res.send('Secure page with CSP displayed');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15(req: express.Request, res: express.Response) {
    const playwright = require('playwright');
    const browser = await playwright.firefox.launch();
    const page = await browser.newPage();
    
    // Using a safe iframe approach
    const userContent = req.body.content;
    
    // ok: playwright-setcontent-injection-ts-rule
    await page.setContent(`
        <html>
            <head>
                <title>Sandboxed Content</title>
            </head>
            <body>
                <h1>User Content (Sandboxed)</h1>
                <iframe sandbox="allow-scripts" srcdoc="<html><body><div id='content'></div></body></html>"></iframe>
                <script>
                    // The content would be inserted client-side in a controlled manner
                    // This is just a placeholder for the concept
                </script>
            </body>
        </html>
    `);
    
    await browser.close();
    res.send('Content displayed in sandboxed iframe');
}
// {/fact}

// Helper functions to make the examples work
function escapeHtml(unsafe: string): string {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function sanitizeHtml(input: string, options: any): string {
    // Simplified sanitizer for example purposes
    return input.replace(/<(?!\/?(b|i|em|strong|p)\b)[^>]+>/gi, '');
}

function getStaticTemplate(templateName: string): string {
    const templates = {
        product: '<h1>Product Page</h1><p>Product details go here</p>',
        service: '<h1>Service Page</h1><p>Service details go here</p>',
        about: '<h1>About Us</h1><p>Company information goes here</p>'
    };
    return templates[templateName];
}

async function fetchUserData(userId: number | string): Promise<any> {
    // Simulated database fetch
    return { name: 'John Doe', content: '<p>User profile content</p>' };
}

async function loadContentFromDatabase(contentId: string): Promise<string> {
    // Simulated database content fetch
    return '<h1>Database Content</h1><p>This content is from a trusted source</p>';
}

function renderTemplate(templateName: string, data: any): string {
    // Simulated template rendering with auto-escaping
    if (templateName === 'welcome') {
        return `<h1>${escapeHtml(data.title)}</h1><p>${escapeHtml(data.message)}</p>`;
    }
    return '<p>Default template</p>';
}

async function performSearch(query: string): Promise<any[]> {
    // Simulated search function
    return [
        { title: 'Result 1', description: 'Description 1' },
        { title: 'Result 2', description: 'Description 2' }
    ];
}

class SafeHtmlBuilder {
    private html: string = '';
    
    addHeading(text: string, level: number): void {
        const safeLevel = Math.min(Math.max(level, 1), 6);
        this.html += `<h${safeLevel}>${this.escapeText(text)}</h${safeLevel}>`;
    }
    
    addParagraph(text: string): void {
        this.html += `<p>${text}</p>`;
    }
    
    startList(): void {
        this.html += '<ul>';
    }
    
    addListItem(text: string): void {
        this.html += `<li>${text}</li>`;
    }
    
    endList(): void {
        this.html += '</ul>';
    }
    
    escapeText(text: string): string {
        return escapeHtml(text);
    }
    
    getHtml(): string {
        return `<html><body>${this.html}</body></html>`;
    }
}

// Mock DOMPurify for example purposes
const DOMPurify = {
    sanitize: (html: string, options: any): string => {
        // Simplified sanitizer for example purposes
        return html.replace(/<(?!\/?(p|b|i|em|strong|a)\b)[^>]+>/gi, '');
    }
};