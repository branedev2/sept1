// File: typescript-unsafe-serialize-test-cases.ts
import express from 'express';
import { Request, Response } from 'express';
import * as serialize from 'serialize-javascript';
import * as safeSerialize from 'safe-serialize';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { sanitizeHtml } from 'sanitize-html';

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/user', (req: Request, res: Response) => {
        const userData = {
            name: req.query.name,
            id: req.query.id
        };
        
        // ruleid: typescript-unsafe-serialize
        res.send(`<script>var user = ${JSON.stringify(userData)};</script>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/profile', (req: Request, res: Response) => {
        const profileData = req.body;
        
        // ruleid: typescript-unsafe-serialize
        const serializedData = `window.PROFILE_DATA = ${JSON.stringify(profileData)};`;
        res.send(`<html><head><script>${serializedData}</script></head><body>Profile updated</body></html>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/config', (req: Request, res: Response) => {
        const userConfig = {
            theme: req.query.theme,
            language: req.query.language
        };
        
        // ruleid: typescript-unsafe-serialize
        const html = `
            <!DOCTYPE html>
            <html>
                <head>
                    <script>
                        const config = ${JSON.stringify(userConfig)};
                    </script>
                </head>
                <body>Configuration page</body>
            </html>
        `;
        res.send(html);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchTerm = req.query.q;
        const searchResults = [`Result for ${searchTerm}`];
        
        // ruleid: typescript-unsafe-serialize
        res.send(`
            <div id="results"></div>
            <script>
                document.getElementById('results').innerHTML = 'Results for: ' + ${JSON.stringify(searchTerm)};
                const results = ${JSON.stringify(searchResults)};
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/api/data', (req: Request, res: Response) => {
        const userInput = req.query.data;
        
        // ruleid: typescript-unsafe-serialize
        res.setHeader('Content-Type', 'text/html');
        res.send(`
            <script>
                const receivedData = ${JSON.stringify(userInput)};
                console.log(receivedData);
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.post('/comments', (req: Request, res: Response) => {
        const comments = [
            { author: req.body.name, text: req.body.comment }
        ];
        
        // ruleid: typescript-unsafe-serialize
        const pageContent = `
            <html>
                <body>
                    <div id="comments"></div>
                    <script>
                        const comments = ${JSON.stringify(comments)};
                        // Render comments
                    </script>
                </body>
            </html>
        `;
        res.send(pageContent);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/product/:id', (req: Request, res: Response) => {
        const productData = {
            id: req.params.id,
            name: req.query.name,
            description: req.query.description
        };
        
        // ruleid: typescript-unsafe-serialize
        const html = `
            <div id="product-info"></div>
            <script>
                const product = ${JSON.stringify(productData)};
                document.getElementById('product-info').textContent = product.name;
            </script>
        `;
        res.send(html);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/analytics', (req: Request, res: Response) => {
        const userAgent = req.headers['user-agent'];
        const referrer = req.headers.referer;
        const analyticsData = { userAgent, referrer };
        
        // ruleid: typescript-unsafe-serialize
        res.send(`
            <script>
                const analytics = ${JSON.stringify(analyticsData)};
                // Send analytics data
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.post('/feedback', (req: Request, res: Response) => {
        const feedback = {
            rating: req.body.rating,
            comment: req.body.comment
        };
        
        // ruleid: typescript-unsafe-serialize
        const responseHtml = `
            <html>
                <body>
                    <h1>Thank you for your feedback!</h1>
                    <script>
                        const submittedFeedback = ${JSON.stringify(feedback)};
                        alert('Feedback submitted: ' + submittedFeedback.rating + ' stars');
                    </script>
                </body>
            </html>
        `;
        res.send(responseHtml);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/settings', (req: Request, res: Response) => {
        const cookieValue = req.cookies.preferences;
        
        // ruleid: typescript-unsafe-serialize
        res.send(`
            <script>
                const userPreferences = ${JSON.stringify(cookieValue)};
                // Apply user preferences
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/error', (req: Request, res: Response) => {
        const errorMessage = req.query.message;
        
        // ruleid: typescript-unsafe-serialize
        const errorPage = `
            <html>
                <body>
                    <h1>An error occurred</h1>
                    <script>
                        const error = ${JSON.stringify(errorMessage)};
                        document.write('<div class="error">' + error + '</div>');
                    </script>
                </body>
            </html>
        `;
        res.status(500).send(errorPage);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/widget', (req: Request, res: Response) => {
        const widgetConfig = {
            color: req.query.color,
            size: req.query.size,
            text: req.query.text
        };
        
        // ruleid: typescript-unsafe-serialize
        res.send(`
            <div id="widget"></div>
            <script>
                const config = ${JSON.stringify(widgetConfig)};
                document.getElementById('widget').innerHTML = 
                    '<div style="color:' + config.color + '">' + config.text + '</div>';
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/chart', (req: Request, res: Response) => {
        const labels = req.query.labels?.toString().split(',') || [];
        const data = req.query.data?.toString().split(',').map(Number) || [];
        const chartData = { labels, data };
        
        // ruleid: typescript-unsafe-serialize
        res.send(`
            <canvas id="chart"></canvas>
            <script>
                const chartData = ${JSON.stringify(chartData)};
                // Initialize chart with data
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/localization', (req: Request, res: Response) => {
        const lang = req.query.lang || 'en';
        const translations = {
            greeting: req.query.greeting || 'Hello'
        };
        
        // ruleid: typescript-unsafe-serialize
        const html = `
            <html lang="${lang}">
                <head>
                    <script>
                        window.translations = ${JSON.stringify(translations)};
                    </script>
                </head>
                <body>
                    <h1 id="greeting"></h1>
                    <script>
                        document.getElementById('greeting').textContent = window.translations.greeting;
                    </script>
                </body>
            </html>
        `;
        res.send(html);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/redirect', (req: Request, res: Response) => {
        const redirectUrl = req.query.url;
        const redirectData = { url: redirectUrl, timeout: 3000 };
        
        // ruleid: typescript-unsafe-serialize
        res.send(`
            <html>
                <body>
                    <p>Redirecting you shortly...</p>
                    <script>
                        const redirectInfo = ${JSON.stringify(redirectData)};
                        setTimeout(() => {
                            window.location.href = redirectInfo.url;
                        }, redirectInfo.timeout);
                    </script>
                </body>
            </html>
        `);
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/user', (req: Request, res: Response) => {
        const userData = {
            name: req.query.name,
            id: req.query.id
        };
        
        // ok: typescript-unsafe-serialize
        res.send(`<script>var user = ${serialize(userData)};</script>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/profile', (req: Request, res: Response) => {
        const profileData = req.body;
        
        // ok: typescript-unsafe-serialize
        const window = new JSDOM('').window;
        const purify = DOMPurify(window);
        const sanitizedData = purify.sanitize(JSON.stringify(profileData));
        const serializedData = `window.PROFILE_DATA = ${sanitizedData};`;
        res.send(`<html><head><script>${serializedData}</script></head><body>Profile updated</body></html>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/config', (req: Request, res: Response) => {
        const userConfig = {
            theme: req.query.theme,
            language: req.query.language
        };
        
        // ok: typescript-unsafe-serialize
        const html = `
            <!DOCTYPE html>
            <html>
                <head>
                    <script>
                        const config = ${serialize(userConfig, { isJSON: true })};
                    </script>
                </head>
                <body>Configuration page</body>
            </html>
        `;
        res.send(html);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchTerm = req.query.q;
        const searchResults = [`Result for ${searchTerm}`];
        
        // ok: typescript-unsafe-serialize
        const safeSearchTerm = sanitizeHtml(searchTerm as string);
        const safeResults = searchResults.map(r => sanitizeHtml(r));
        
        res.send(`
            <div id="results"></div>
            <script>
                document.getElementById('results').textContent = 'Results for: ' + ${JSON.stringify(safeSearchTerm)};
                const results = ${JSON.stringify(safeResults)};
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/api/data', (req: Request, res: Response) => {
        const userInput = req.query.data;
        
        // ok: typescript-unsafe-serialize
        res.setHeader('Content-Type', 'text/html');
        res.send(`
            <script>
                const receivedData = ${serialize(userInput)};
                console.log(receivedData);
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.post('/comments', (req: Request, res: Response) => {
        const comments = [
            { author: req.body.name, text: req.body.comment }
        ];
        
        // ok: typescript-unsafe-serialize
        const window = new JSDOM('').window;
        const purify = DOMPurify(window);
        const safeComments = purify.sanitize(JSON.stringify(comments));
        
        const pageContent = `
            <html>
                <body>
                    <div id="comments"></div>
                    <script>
                        const comments = JSON.parse('${safeComments}');
                        // Render comments
                    </script>
                </body>
            </html>
        `;
        res.send(pageContent);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.get('/product/:id', (req: Request, res: Response) => {
        const productData = {
            id: req.params.id,
            name: req.query.name,
            description: req.query.description
        };
        
        // ok: typescript-unsafe-serialize
        const html = `
            <div id="product-info"></div>
            <script>
                const product = ${serialize(productData)};
                document.getElementById('product-info').textContent = product.name;
            </script>
        `;
        res.send(html);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/analytics', (req: Request, res: Response) => {
        const userAgent = req.headers['user-agent'];
        const referrer = req.headers.referer;
        const analyticsData = { userAgent, referrer };
        
        // ok: typescript-unsafe-serialize
        res.send(`
            <script>
                const analytics = ${serialize(analyticsData, { isJSON: true })};
                // Send analytics data
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.post('/feedback', (req: Request, res: Response) => {
        const feedback = {
            rating: parseInt(req.body.rating as string),
            comment: sanitizeHtml(req.body.comment as string)
        };
        
        // ok: typescript-unsafe-serialize
        const responseHtml = `
            <html>
                <body>
                    <h1>Thank you for your feedback!</h1>
                    <script>
                        const submittedFeedback = ${serialize(feedback)};
                        alert('Feedback submitted: ' + submittedFeedback.rating + ' stars');
                    </script>
                </body>
            </html>
        `;
        res.send(responseHtml);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/settings', (req: Request, res: Response) => {
        const cookieValue = req.cookies.preferences;
        
        // ok: typescript-unsafe-serialize
        const window = new JSDOM('').window;
        const purify = DOMPurify(window);
        const sanitizedPreferences = purify.sanitize(JSON.stringify(cookieValue));
        
        res.send(`
            <script>
                const userPreferences = JSON.parse(${JSON.stringify(sanitizedPreferences)});
                // Apply user preferences
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/error', (req: Request, res: Response) => {
        const errorMessage = req.query.message;
        
        // ok: typescript-unsafe-serialize
        const safeErrorMessage = sanitizeHtml(errorMessage as string);
        
        const errorPage = `
            <html>
                <body>
                    <h1>An error occurred</h1>
                    <script>
                        const error = ${JSON.stringify(safeErrorMessage)};
                        const errorDiv = document.createElement('div');
                        errorDiv.className = 'error';
                        errorDiv.textContent = error;
                        document.body.appendChild(errorDiv);
                    </script>
                </body>
            </html>
        `;
        res.status(500).send(errorPage);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/widget', (req: Request, res: Response) => {
        const widgetConfig = {
            color: sanitizeHtml(req.query.color as string),
            size: sanitizeHtml(req.query.size as string),
            text: sanitizeHtml(req.query.text as string)
        };
        
        // ok: typescript-unsafe-serialize
        res.send(`
            <div id="widget"></div>
            <script>
                const config = ${serialize(widgetConfig)};
                const widgetElement = document.getElementById('widget');
                const widgetContent = document.createElement('div');
                widgetContent.style.color = config.color;
                widgetContent.textContent = config.text;
                widgetElement.appendChild(widgetContent);
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/chart', (req: Request, res: Response) => {
        const rawLabels = req.query.labels?.toString().split(',') || [];
        const rawData = req.query.data?.toString().split(',').map(Number) || [];
        
        // Sanitize inputs
        const labels = rawLabels.map(label => sanitizeHtml(label));
        const data = rawData.filter(num => !isNaN(num));
        
        const chartData = { labels, data };
        
        // ok: typescript-unsafe-serialize
        res.send(`
            <canvas id="chart"></canvas>
            <script>
                const chartData = ${serialize(chartData, { isJSON: true })};
                // Initialize chart with data
            </script>
        `);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/localization', (req: Request, res: Response) => {
        const lang = sanitizeHtml(req.query.lang as string) || 'en';
        const translations = {
            greeting: sanitizeHtml(req.query.greeting as string) || 'Hello'
        };
        
        // ok: typescript-unsafe-serialize
        const html = `
            <html lang="${lang}">
                <head>
                    <script>
                        window.translations = ${serialize(translations)};
                    </script>
                </head>
                <body>
                    <h1 id="greeting"></h1>
                    <script>
                        document.getElementById('greeting').textContent = window.translations.greeting;
                    </script>
                </body>
            </html>
        `;
        res.send(html);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.get('/redirect', (req: Request, res: Response) => {
        // Validate URL to prevent open redirect vulnerabilities
        const redirectUrl = req.query.url as string;
        const allowedDomains = ['example.com', 'trusted-site.org'];
        
        let validatedUrl = '';
        try {
            const urlObj = new URL(redirectUrl);
            if (allowedDomains.includes(urlObj.hostname)) {
                validatedUrl = redirectUrl;
            } else {
                validatedUrl = 'https://example.com';
            }
        } catch (e) {
            validatedUrl = 'https://example.com';
        }
        
        const redirectData = { url: validatedUrl, timeout: 3000 };
        
        // ok: typescript-unsafe-serialize
        res.send(`
            <html>
                <body>
                    <p>Redirecting you shortly...</p>
                    <script>
                        const redirectInfo = ${serialize(redirectData)};
                        setTimeout(() => {
                            window.location.href = redirectInfo.url;
                        }, redirectInfo.timeout);
                    </script>
                </body>
            </html>
        `);
    });
}
// {/fact}