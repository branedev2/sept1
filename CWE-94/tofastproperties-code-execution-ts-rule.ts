import * as util from 'util';
import * as http from 'http';
import * as url from 'url';
import * as express from 'express';
import { Request, Response } from 'express';

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userInput = parsedUrl.query.input as string;
        
        const obj = JSON.parse(userInput);
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(obj);
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Processing complete');
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/process', (req: Request, res: Response) => {
        const userObject = req.body.data;
        
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(userObject);
        
        res.send('Data processed');
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            try {
                const userData = JSON.parse(body);
                // ruleid: tofastproperties-code-execution-ts-rule
                util.toFastProperties(userData);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (e) {
                res.writeHead(400);
                res.end('Invalid input');
            }
        });
    });
    server.listen(8080);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/optimize', (req: Request, res: Response) => {
        const inputParam = req.query.config as string;
        const configObj = JSON.parse(inputParam);
        
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(configObj);
        
        res.json({ status: 'optimized' });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    http.createServer((req, res) => {
        if (req.headers['content-type'] === 'application/json') {
            let data = '';
            req.on('data', chunk => {
                data += chunk;
            });
            
            req.on('end', () => {
                const userConfig = JSON.parse(data);
                // ruleid: tofastproperties-code-execution-ts-rule
                util.toFastProperties(userConfig);
                res.end('Configuration applied');
            });
        }
    }).listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.post('/settings', (req: Request, res: Response) => {
        const settings = req.body.settings;
        const userPrefs = settings.preferences;
        
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(userPrefs);
        
        res.send('Settings updated');
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    const server = http.createServer((req, res) => {
        const cookies = req.headers.cookie?.split(';').reduce((obj, cookie) => {
            const parts = cookie.trim().split('=');
            obj[parts[0]] = parts[1];
            return obj;
        }, {} as Record<string, string>) || {};
        
        const userSettings = JSON.parse(cookies['user_settings'] || '{}');
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(userSettings);
        
        res.end('Cookie settings applied');
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.post('/api/config', (req: Request, res: Response) => {
        const headerData = req.headers['x-custom-data'] as string;
        if (headerData) {
            const parsedData = JSON.parse(Buffer.from(headerData, 'base64').toString());
            // ruleid: tofastproperties-code-execution-ts-rule
            util.toFastProperties(parsedData);
            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Missing header' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        if (parsedUrl.pathname === '/optimize') {
            const base64Input = parsedUrl.query.data as string;
            const decodedData = JSON.parse(Buffer.from(base64Input, 'base64').toString());
            
            // ruleid: tofastproperties-code-execution-ts-rule
            util.toFastProperties(decodedData);
            
            res.writeHead(200);
            res.end('Optimization complete');
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.put('/user/:id/preferences', (req: Request, res: Response) => {
        const userId = req.params.id;
        const userPreferences = req.body;
        
        // Some processing with userId
        console.log(`Updating preferences for user ${userId}`);
        
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(userPreferences);
        
        res.json({ updated: true });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/submit') {
            let formData = '';
            req.on('data', chunk => {
                formData += chunk.toString();
            });
            
            req.on('end', () => {
                const params = new URLSearchParams(formData);
                const jsonData = params.get('json_data') || '{}';
                const parsedData = JSON.parse(jsonData);
                
                // ruleid: tofastproperties-code-execution-ts-rule
                util.toFastProperties(parsedData);
                
                res.writeHead(200);
                res.end('Form processed');
            });
        }
    }).listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchParams = req.query;
        const searchOptions = {
            term: searchParams.q,
            filters: JSON.parse(searchParams.filters as string || '{}')
        };
        
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(searchOptions);
        
        res.send('Search executed');
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    const server = http.createServer((req, res) => {
        const authHeader = req.headers.authorization || '';
        if (authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            // Decode JWT payload (simplified)
            const payload = JSON.parse(
                Buffer.from(token.split('.')[1], 'base64').toString()
            );
            
            // ruleid: tofastproperties-code-execution-ts-rule
            util.toFastProperties(payload);
            
            res.writeHead(200);
            res.end('Token processed');
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.post('/import', (req: Request, res: Response) => {
        const fileContent = req.body.fileContent;
        try {
            const importedData = JSON.parse(fileContent);
            
            // ruleid: tofastproperties-code-execution-ts-rule
            util.toFastProperties(importedData);
            
            res.json({ success: true });
        } catch (e) {
            res.status(400).json({ error: 'Invalid file content' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.post('/webhook', (req: Request, res: Response) => {
        const eventData = req.body;
        const eventType = eventData.type;
        
        console.log(`Received webhook: ${eventType}`);
        
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(eventData);
        
        res.status(200).send('Webhook received');
    });
    
    app.listen(3000);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userInput = parsedUrl.query.input as string;
        
        // Validate and sanitize user input
        const safeObj = validateAndSanitizeObject(JSON.parse(userInput));
        
        // ok: tofastproperties-code-execution-ts-rule
        const staticObj = { prop1: 'static', prop2: 'value' };
        util.toFastProperties(staticObj);
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Processing complete');
    });
    server.listen(3000);
}
// {/fact}

function validateAndSanitizeObject(obj: any): any {
    // Implementation of validation and sanitization
    return { safe: true };
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/process', (req: Request, res: Response) => {
        const userObject = req.body.data;
        
        // Instead of passing user data directly, use a predefined object
        // ok: tofastproperties-code-execution-ts-rule
        const configObject = { 
            enableCache: true, 
            timeout: 5000, 
            retries: 3 
        };
        util.toFastProperties(configObject);
        
        res.send('Data processed');
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            try {
                const userData = JSON.parse(body);
                
                // Use the user data safely without passing to toFastProperties
                const response = { success: true, userId: userData.id };
                
                // ok: tofastproperties-code-execution-ts-rule
                const systemConfig = { 
                    cacheEnabled: true, 
                    logLevel: 'info' 
                };
                util.toFastProperties(systemConfig);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(response));
            } catch (e) {
                res.writeHead(400);
                res.end('Invalid input');
            }
        });
    });
    server.listen(8080);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/optimize', (req: Request, res: Response) => {
        const inputParam = req.query.config as string;
        
        // Instead of using user input directly, use a safe predefined object
        // ok: tofastproperties-code-execution-ts-rule
        const safeConfig = {
            useCache: true,
            optimizeRendering: true,
            debugMode: false
        };
        util.toFastProperties(safeConfig);
        
        res.json({ status: 'optimized' });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    http.createServer((req, res) => {
        if (req.headers['content-type'] === 'application/json') {
            let data = '';
            req.on('data', chunk => {
                data += chunk;
            });
            
            req.on('end', () => {
                const userConfig = JSON.parse(data);
                
                // Process user config safely without passing to toFastProperties
                processUserConfig(userConfig);
                
                // ok: tofastproperties-code-execution-ts-rule
                const appConfig = { version: '1.0.0', environment: 'production' };
                util.toFastProperties(appConfig);
                
                res.end('Configuration applied');
            });
        }
    }).listen(3000);
}
// {/fact}

function processUserConfig(config: any): void {
    // Safe processing of user config
    console.log('Processing user config:', config);
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.post('/settings', (req: Request, res: Response) => {
        const settings = req.body.settings;
        
        // Store user settings safely
        saveUserSettings(settings);
        
        // ok: tofastproperties-code-execution-ts-rule
        const defaultSettings = {
            theme: 'light',
            notifications: true,
            language: 'en'
        };
        util.toFastProperties(defaultSettings);
        
        res.send('Settings updated');
    });
    
    app.listen(3000);
}
// {/fact}

function saveUserSettings(settings: any): void {
    // Implementation of saving user settings
    console.log('Saving settings:', settings);
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    const server = http.createServer((req, res) => {
        const cookies = req.headers.cookie?.split(';').reduce((obj, cookie) => {
            const parts = cookie.trim().split('=');
            obj[parts[0]] = parts[1];
            return obj;
        }, {} as Record<string, string>) || {};
        
        // Process cookies safely without passing to toFastProperties
        processCookies(cookies);
        
        // ok: tofastproperties-code-execution-ts-rule
        const cookieDefaults = { 
            session: 'default', 
            preferences: 'default' 
        };
        util.toFastProperties(cookieDefaults);
        
        res.end('Cookie settings applied');
    });
    server.listen(3000);
}
// {/fact}

function processCookies(cookies: Record<string, string>): void {
    // Safe processing of cookies
    console.log('Processing cookies:', cookies);
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.post('/api/config', (req: Request, res: Response) => {
        const headerData = req.headers['x-custom-data'] as string;
        if (headerData) {
            const parsedData = JSON.parse(Buffer.from(headerData, 'base64').toString());
            
            // Use parsed data safely without passing to toFastProperties
            const result = processApiConfig(parsedData);
            
            // ok: tofastproperties-code-execution-ts-rule
            const apiDefaults = { 
                timeout: 30000, 
                retries: 3, 
                caching: true 
            };
            util.toFastProperties(apiDefaults);
            
            res.json({ success: true, result });
        } else {
            res.status(400).json({ error: 'Missing header' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

function processApiConfig(config: any): any {
    // Safe processing of API config
    return { processed: true, config };
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        if (parsedUrl.pathname === '/optimize') {
            const base64Input = parsedUrl.query.data as string;
            const decodedData = JSON.parse(Buffer.from(base64Input, 'base64').toString());
            
            // Use decoded data safely
            const result = processDecodedData(decodedData);
            
            // ok: tofastproperties-code-execution-ts-rule
            const optimizationConfig = { 
                level: 'high', 
                aggressive: true, 
                cacheResults: true 
            };
            util.toFastProperties(optimizationConfig);
            
            res.writeHead(200);
            res.end(JSON.stringify(result));
        }
    });
    server.listen(3000);
}
// {/fact}

function processDecodedData(data: any): any {
    // Safe processing of decoded data
    return { processed: true, data };
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.put('/user/:id/preferences', (req: Request, res: Response) => {
        const userId = req.params.id;
        const userPreferences = req.body;
        
        // Process user preferences safely
        updateUserPreferences(userId, userPreferences);
        
        // ok: tofastproperties-code-execution-ts-rule
        const systemPreferences = { 
            defaultTheme: 'light', 
            defaultLanguage: 'en', 
            notifications: true 
        };
        util.toFastProperties(systemPreferences);
        
        res.json({ updated: true });
    });
    
    app.listen(3000);
}
// {/fact}

function updateUserPreferences(userId: string, preferences: any): void {
    // Safe implementation of updating user preferences
    console.log(`Updating preferences for user ${userId}:`, preferences);
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/submit') {
            let formData = '';
            req.on('data', chunk => {
                formData += chunk.toString();
            });
            
            req.on('end', () => {
                const params = new URLSearchParams(formData);
                const jsonData = params.get('json_data') || '{}';
                const parsedData = JSON.parse(jsonData);
                
                // Process form data safely
                processFormData(parsedData);
                
                // ok: tofastproperties-code-execution-ts-rule
                const formConfig = { 
                    validateInput: true, 
                    sanitizeFields: true, 
                    logSubmissions: false 
                };
                util.toFastProperties(formConfig);
                
                res.writeHead(200);
                res.end('Form processed');
            });
        }
    }).listen(3000);
}
// {/fact}

function processFormData(data: any): void {
    // Safe processing of form data
    console.log('Processing form data:', data);
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchParams = req.query;
        
        // Process search parameters safely
        const results = executeSearch(searchParams);
        
        // ok: tofastproperties-code-execution-ts-rule
        const searchConfig = { 
            maxResults: 100, 
            sortByRelevance: true, 
            includeArchived: false 
        };
        util.toFastProperties(searchConfig);
        
        res.json(results);
    });
    
    app.listen(3000);
}
// {/fact}

function executeSearch(params: any): any[] {
    // Safe implementation of search
    return [{ result: 'Sample result' }];
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    const server = http.createServer((req, res) => {
        const authHeader = req.headers.authorization || '';
        if (authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            // Decode JWT payload (simplified)
            const payload = JSON.parse(
                Buffer.from(token.split('.')[1], 'base64').toString()
            );
            
            // Process token payload safely
            validateToken(payload);
            
            // ok: tofastproperties-code-execution-ts-rule
            const authConfig = { 
                issuer: 'auth-service', 
                expiryCheck: true, 
                refreshEnabled: true 
            };
            util.toFastProperties(authConfig);
            
            res.writeHead(200);
            res.end('Token processed');
        }
    });
    server.listen(3000);
}
// {/fact}

function validateToken(payload: any): boolean {
    // Safe implementation of token validation
    return true;
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.post('/import', (req: Request, res: Response) => {
        const fileContent = req.body.fileContent;
        try {
            const importedData = JSON.parse(fileContent);
            
            // Process imported data safely
            const result = processImportedData(importedData);
            
            // ok: tofastproperties-code-execution-ts-rule
            const importConfig = { 
                validateSchema: true, 
                allowOverwrite: false, 
                createBackup: true 
            };
            util.toFastProperties(importConfig);
            
            res.json({ success: true, result });
        } catch (e) {
            res.status(400).json({ error: 'Invalid file content' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

function processImportedData(data: any): any {
    // Safe processing of imported data
    return { processed: true, count: Object.keys(data).length };
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.post('/webhook', (req: Request, res: Response) => {
        const eventData = req.body;
        
        // Process webhook data safely
        handleWebhookEvent(eventData);
        
        // ok: tofastproperties-code-execution-ts-rule
        const webhookConfig = { 
            verifySignature: true, 
            logEvents: true, 
            retryFailed: true 
        };
        util.toFastProperties(webhookConfig);
        
        res.status(200).send('Webhook received');
    });
    
    app.listen(3000);
}
// {/fact}

function handleWebhookEvent(event: any): void {
    // Safe handling of webhook events
    console.log(`Processing webhook event: ${event.type}`);
}