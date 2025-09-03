// File: insecure_createnodesfrommarkup_test_cases.ts

import express from 'express';
import * as http from 'http';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import axios from 'axios';

// Set up JSDOM for DOM manipulation in Node.js environment
const { window } = new JSDOM('<!DOCTYPE html>');
const document = window.document;

// Mock implementation of createNodesFromMarkup for testing purposes
function createNodesFromMarkup(markup: string, root: HTMLElement): Node[] {
    const template = document.createElement('template');
    template.innerHTML = markup;
    const fragment = template.content;
    return Array.from(fragment.childNodes);
}

// Mock implementation of createNodes for testing purposes
function createNodes(markup: string): Node[] {
    const template = document.createElement('template');
    template.innerHTML = markup;
    return Array.from(template.content.childNodes);
}

// Mock implementation of generateNodes for testing purposes
function generateNodes(markup: string): Node[] {
    const div = document.createElement('div');
    div.innerHTML = markup;
    return Array.from(div.childNodes);
}

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/render', (req, res) => {
        const userInput = req.query.content as string;
        const container = document.createElement('div');
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const nodes = createNodesFromMarkup(userInput, container);
        
        container.append(...nodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/comment', express.json(), (req, res) => {
        const commentText = req.body.comment;
        const commentSection = document.getElementById('comments');
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const commentNodes = createNodes(commentText);
        
        if (commentSection) {
            commentSection.append(...commentNodes);
        }
        res.send({ success: true });
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/profile', (req, res) => {
        const username = req.query.username as string;
        const bioMarkup = `<div class="bio">${username}</div>`;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const bioNodes = generateNodes(bioMarkup);
        
        const container = document.createElement('div');
        container.append(...bioNodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    http.createServer((req, res) => {
        if (req.url?.includes('/search')) {
            const url = new URL(req.url, `http://${req.headers.host}`);
            const searchTerm = url.searchParams.get('q') || '';
            const resultMarkup = `<div>Search results for: ${searchTerm}</div>`;
            
            // ruleid: insecure-createnodesfrommarkup-ts-rule
            const nodes = createNodesFromMarkup(resultMarkup, document.body);
            
            // Send response
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`<html><body>${document.body.innerHTML}</body></html>`);
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/article', (req, res) => {
        const articleId = req.query.id as string;
        const articleTitle = req.query.title as string;
        
        const headerMarkup = `<h1>${articleTitle}</h1>`;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const headerNodes = createNodes(headerMarkup);
        
        const container = document.createElement('div');
        container.append(...headerNodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/message', (req, res) => {
        const message = req.headers['x-message'] as string;
        const container = document.createElement('div');
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const nodes = generateNodes(`<p>${message}</p>`);
        
        container.append(...nodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.post('/feedback', express.urlencoded({ extended: true }), (req, res) => {
        const feedback = req.body.feedback;
        const userName = req.body.name;
        
        const feedbackMarkup = `<div class="feedback"><p>From: ${userName}</p><p>${feedback}</p></div>`;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const nodes = createNodesFromMarkup(feedbackMarkup, document.body);
        
        res.send('Feedback submitted');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/product', (req, res) => {
        const productName = req.query.name as string;
        const productDesc = req.query.description as string;
        
        let productMarkup = `<div class="product">
            <h2>${productName}</h2>
            <p>${productDesc}</p>
        </div>`;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const productNodes = createNodes(productMarkup);
        
        const container = document.createElement('div');
        container.append(...productNodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/notification', (req, res) => {
        const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.trim().split('=');
            acc[key] = value;
            return acc;
        }, {} as Record<string, string>) || {};
        
        const userTheme = cookies['theme'] || 'light';
        const notificationMarkup = `<div class="notification ${userTheme}">${req.query.message}</div>`;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const nodes = generateNodes(notificationMarkup);
        
        const container = document.createElement('div');
        container.append(...nodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.post('/review', express.json(), async (req, res) => {
        try {
            const { productId, reviewText, rating } = req.body;
            
            // Fetch product name from API
            const response = await axios.get(`https://api.example.com/products/${productId}`);
            const productName = response.data.name;
            
            const reviewMarkup = `
                <div class="review">
                    <h3>Review for ${productName}</h3>
                    <div class="rating">${'★'.repeat(rating)}</div>
                    <p>${reviewText}</p>
                </div>
            `;
            
            // ruleid: insecure-createnodesfrommarkup-ts-rule
            const reviewNodes = createNodesFromMarkup(reviewMarkup, document.body);
            
            res.send('Review submitted');
        } catch (error) {
            res.status(500).send('Error submitting review');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/embed', (req, res) => {
        const embedCode = req.query.code as string;
        const container = document.createElement('div');
        
        if (embedCode) {
            // ruleid: insecure-createnodesfrommarkup-ts-rule
            const nodes = createNodes(embedCode);
            container.append(...nodes);
        }
        
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/template', (req, res) => {
        const templateId = req.query.id as string;
        const templateData = req.query.data as string;
        
        // Simple template engine
        let template = `<div>Default Template</div>`;
        if (templateId === '1') {
            template = `<div class="template-1">${templateData}</div>`;
        } else if (templateId === '2') {
            template = `<div class="template-2">${templateData}</div>`;
        }
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const nodes = generateNodes(template);
        
        const container = document.createElement('div');
        container.append(...nodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/widget', (req, res) => {
        const widgetType = req.query.type as string;
        const widgetContent = req.query.content as string;
        
        let widgetMarkup = '';
        switch (widgetType) {
            case 'info':
                widgetMarkup = `<div class="info-widget">${widgetContent}</div>`;
                break;
            case 'alert':
                widgetMarkup = `<div class="alert-widget">${widgetContent}</div>`;
                break;
            default:
                widgetMarkup = `<div class="default-widget">${widgetContent}</div>`;
        }
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const widgetNodes = createNodesFromMarkup(widgetMarkup, document.body);
        
        const container = document.createElement('div');
        container.append(...widgetNodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/user-profile', (req, res) => {
        const referer = req.headers.referer || '';
        const userAgent = req.headers['user-agent'] || '';
        
        const debugInfo = `
            <div class="debug-info">
                <p>Referer: ${referer}</p>
                <p>User Agent: ${userAgent}</p>
            </div>
        `;
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const debugNodes = createNodes(debugInfo);
        
        const container = document.createElement('div');
        container.append(...debugNodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/dynamic-content', (req, res) => {
        const contentId = req.query.id as string;
        const contentParams = new URLSearchParams(req.query.params as string);
        
        let dynamicContent = `<div class="dynamic-content" data-id="${contentId}">`;
        for (const [key, value] of contentParams.entries()) {
            dynamicContent += `<span data-param="${key}">${value}</span>`;
        }
        dynamicContent += '</div>';
        
        // ruleid: insecure-createnodesfrommarkup-ts-rule
        const contentNodes = generateNodes(dynamicContent);
        
        const container = document.createElement('div');
        container.append(...contentNodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/render', (req, res) => {
        const userInput = req.query.content as string;
        const container = document.createElement('div');
        
        // Sanitize user input before using it
        const sanitizedInput = DOMPurify.sanitize(userInput);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const nodes = createNodesFromMarkup(sanitizedInput, container);
        
        container.append(...nodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/comment', express.json(), (req, res) => {
        const commentText = req.body.comment;
        const commentSection = document.getElementById('comments');
        
        // Create text node instead of parsing HTML
        const textNode = document.createTextNode(commentText);
        const paragraph = document.createElement('p');
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        paragraph.appendChild(textNode);
        
        if (commentSection) {
            commentSection.appendChild(paragraph);
        }
        res.send({ success: true });
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/profile', (req, res) => {
        const username = req.query.username as string;
        
        // Create elements safely without parsing HTML
        const bioDiv = document.createElement('div');
        bioDiv.className = 'bio';
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const textNode = document.createTextNode(username);
        bioDiv.appendChild(textNode);
        
        const container = document.createElement('div');
        container.appendChild(bioDiv);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    http.createServer((req, res) => {
        if (req.url?.includes('/search')) {
            const url = new URL(req.url, `http://${req.headers.host}`);
            const searchTerm = url.searchParams.get('q') || '';
            
            // Create elements safely
            const div = document.createElement('div');
            const text = document.createTextNode(`Search results for: ${searchTerm}`);
            
            // ok: insecure-createnodesfrommarkup-ts-rule
            div.appendChild(text);
            document.body.appendChild(div);
            
            // Send response
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`<html><body>${document.body.innerHTML}</body></html>`);
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/article', (req, res) => {
        const articleId = req.query.id as string;
        const articleTitle = req.query.title as string;
        
        // Create elements safely
        const h1 = document.createElement('h1');
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        h1.textContent = articleTitle;
        
        const container = document.createElement('div');
        container.appendChild(h1);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.get('/message', (req, res) => {
        const message = req.headers['x-message'] as string;
        
        // Sanitize input
        const sanitizedMessage = DOMPurify.sanitize(message);
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        const nodes = generateNodes(`<p>${sanitizedMessage}</p>`);
        
        const container = document.createElement('div');
        container.append(...nodes);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.post('/feedback', express.urlencoded({ extended: true }), (req, res) => {
        const feedback = req.body.feedback;
        const userName = req.body.name;
        
        // Create elements safely
        const feedbackDiv = document.createElement('div');
        feedbackDiv.className = 'feedback';
        
        const fromP = document.createElement('p');
        fromP.textContent = `From: ${userName}`;
        
        const contentP = document.createElement('p');
        contentP.textContent = feedback;
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        feedbackDiv.appendChild(fromP);
        feedbackDiv.appendChild(contentP);
        
        document.body.appendChild(feedbackDiv);
        res.send('Feedback submitted');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/product', (req, res) => {
        const productName = req.query.name as string;
        const productDesc = req.query.description as string;
        
        // Create elements safely
        const productDiv = document.createElement('div');
        productDiv.className = 'product';
        
        const h2 = document.createElement('h2');
        h2.textContent = productName;
        
        const p = document.createElement('p');
        p.textContent = productDesc;
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        productDiv.appendChild(h2);
        productDiv.appendChild(p);
        
        const container = document.createElement('div');
        container.appendChild(productDiv);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.get('/notification', (req, res) => {
        const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.trim().split('=');
            acc[key] = value;
            return acc;
        }, {} as Record<string, string>) || {};
        
        const userTheme = cookies['theme'] || 'light';
        const message = req.query.message as string;
        
        // Create elements safely
        const notificationDiv = document.createElement('div');
        notificationDiv.className = `notification ${userTheme}`;
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        notificationDiv.textContent = message;
        
        const container = document.createElement('div');
        container.appendChild(notificationDiv);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.post('/review', express.json(), async (req, res) => {
        try {
            const { productId, reviewText, rating } = req.body;
            
            // Fetch product name from API
            const response = await axios.get(`https://api.example.com/products/${productId}`);
            const productName = response.data.name;
            
            // Create elements safely
            const reviewDiv = document.createElement('div');
            reviewDiv.className = 'review';
            
            const h3 = document.createElement('h3');
            h3.textContent = `Review for ${productName}`;
            
            const ratingDiv = document.createElement('div');
            ratingDiv.className = 'rating';
            ratingDiv.textContent = '★'.repeat(rating);
            
            const p = document.createElement('p');
            p.textContent = reviewText;
            
            // ok: insecure-createnodesfrommarkup-ts-rule
            reviewDiv.appendChild(h3);
            reviewDiv.appendChild(ratingDiv);
            reviewDiv.appendChild(p);
            
            document.body.appendChild(reviewDiv);
            res.send('Review submitted');
        } catch (error) {
            res.status(500).send('Error submitting review');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/embed', (req, res) => {
        const embedCode = req.query.code as string;
        const container = document.createElement('div');
        
        if (embedCode) {
            // Sanitize the embed code
            const sanitizedCode = DOMPurify.sanitize(embedCode, {
                ALLOWED_TAGS: ['iframe'],
                ALLOWED_ATTR: ['src', 'width', 'height', 'frameborder']
            });
            
            // ok: insecure-createnodesfrommarkup-ts-rule
            const nodes = createNodes(sanitizedCode);
            container.append(...nodes);
        }
        
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/template', (req, res) => {
        const templateId = req.query.id as string;
        const templateData = req.query.data as string;
        
        // Create elements safely
        const container = document.createElement('div');
        
        if (templateId === '1') {
            container.className = 'template-1';
        } else if (templateId === '2') {
            container.className = 'template-2';
        }
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        container.textContent = templateData;
        
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/widget', (req, res) => {
        const widgetType = req.query.type as string;
        const widgetContent = req.query.content as string;
        
        // Create elements safely
        const widgetDiv = document.createElement('div');
        
        switch (widgetType) {
            case 'info':
                widgetDiv.className = 'info-widget';
                break;
            case 'alert':
                widgetDiv.className = 'alert-widget';
                break;
            default:
                widgetDiv.className = 'default-widget';
        }
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        widgetDiv.textContent = widgetContent;
        
        const container = document.createElement('div');
        container.appendChild(widgetDiv);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/user-profile', (req, res) => {
        const referer = req.headers.referer || '';
        const userAgent = req.headers['user-agent'] || '';
        
        // Create elements safely
        const debugDiv = document.createElement('div');
        debugDiv.className = 'debug-info';
        
        const refererP = document.createElement('p');
        refererP.textContent = `Referer: ${referer}`;
        
        const uaP = document.createElement('p');
        uaP.textContent = `User Agent: ${userAgent}`;
        
        // ok: insecure-createnodesfrommarkup-ts-rule
        debugDiv.appendChild(refererP);
        debugDiv.appendChild(uaP);
        
        const container = document.createElement('div');
        container.appendChild(debugDiv);
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.get('/dynamic-content', (req, res) => {
        const contentId = req.query.id as string;
        const contentParams = new URLSearchParams(req.query.params as string);
        
        // Create elements safely
        const dynamicDiv = document.createElement('div');
        dynamicDiv.className = 'dynamic-content';
        dynamicDiv.setAttribute('data-id', contentId);
        
        for (const [key, value] of contentParams.entries()) {
            const span = document.createElement('span');
            span.setAttribute('data-param', key);
            
            // ok: insecure-createnodesfrommarkup-ts-rule
            span.textContent = value;
            
            dynamicDiv.appendChild(span);
        }
        
        const container = document.createElement('div');
        container.appendChild(dynamicDiv);
        res.send(container.outerHTML);
    });
}
// {/fact}