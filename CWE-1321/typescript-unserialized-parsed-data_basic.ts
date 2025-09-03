import * as http from 'http';
import * as url from 'url';
import * as express from 'express';
import * as fs from 'fs';
import * as crypto from 'crypto';

// True Positives (Vulnerable Code)

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const jsonData = parsedUrl.query.data as string;
        
        try {
            // ruleid: typescript-unserialized-parsed-data
            const parsedData = JSON.parse(jsonData);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, data: parsedData }));
        } catch (e) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/process-data', express.json(), (req, res) => {
        const userInput = req.body.jsonString;
        
        try {
            // ruleid: typescript-unserialized-parsed-data
            const userData = JSON.parse(userInput);
            res.json({ processed: userData });
        } catch (error) {
            res.status(400).json({ error: 'Invalid JSON format' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_3() {
    const server = http.createServer((req, res) => {
        let body = '';
        
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            try {
                // ruleid: typescript-unserialized-parsed-data
                const parsedBody = JSON.parse(body);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, data: parsedBody }));
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid JSON' }));
            }
        });
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/api/config', (req, res) => {
        const configName = req.query.config as string;
        const configData = fs.readFileSync(`./configs/${configName}.json`, 'utf8');
        
        try {
            // ruleid: typescript-unserialized-parsed-data
            const config = JSON.parse(configData);
            res.json(config);
        } catch (error) {
            res.status(500).json({ error: 'Invalid configuration file' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.post('/api/webhook', (req, res) => {
        const signature = req.headers['x-signature'] as string;
        let data = '';
        
        req.on('data', chunk => {
            data += chunk;
        });
        
        req.on('end', () => {
            // Verify signature (simplified)
            const isValid = signature === crypto.createHash('sha256').update(data).digest('hex');
            
            if (isValid) {
                try {
                    // ruleid: typescript-unserialized-parsed-data
                    const webhookData = JSON.parse(data);
                    // Process webhook data
                    res.status(200).send('Webhook received');
                } catch (error) {
                    res.status(400).send('Invalid JSON payload');
                }
            } else {
                res.status(401).send('Invalid signature');
            }
        });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/api/user-settings', (req, res) => {
        const cookieValue = req.headers.cookie?.split('=')[1];
        
        if (cookieValue) {
            try {
                // ruleid: typescript-unserialized-parsed-data
                const userSettings = JSON.parse(cookieValue);
                res.json({ settings: userSettings });
            } catch (error) {
                res.status(400).json({ error: 'Invalid settings format' });
            }
        } else {
            res.status(400).json({ error: 'No settings cookie found' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.post('/api/import-data', express.text(), (req, res) => {
        const base64Data = req.body;
        const jsonString = Buffer.from(base64Data, 'base64').toString('utf-8');
        
        try {
            // ruleid: typescript-unserialized-parsed-data
            const importedData = JSON.parse(jsonString);
            res.json({ success: true, count: Object.keys(importedData).length });
        } catch (error) {
            res.status(400).json({ error: 'Invalid data format' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_8() {
    const server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/api/data') {
            const contentType = req.headers['content-type'] || '';
            
            if (contentType.includes('application/json')) {
                let jsonData = '';
                
                req.on('data', chunk => {
                    jsonData += chunk.toString();
                });
                
                req.on('end', () => {
                    try {
                        // ruleid: typescript-unserialized-parsed-data
                        const data = JSON.parse(jsonData);
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, data }));
                    } catch (e) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Invalid JSON' }));
                    }
                });
            } else {
                res.writeHead(415, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Unsupported Media Type' }));
            }
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/api/parse-url', (req, res) => {
        const jsonUrl = req.query.url as string;
        
        http.get(jsonUrl, (response) => {
            let data = '';
            
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                try {
                    // ruleid: typescript-unserialized-parsed-data
                    const parsedData = JSON.parse(data);
                    res.json(parsedData);
                } catch (error) {
                    res.status(400).json({ error: 'Invalid JSON from URL' });
                }
            });
        }).on('error', (error) => {
            res.status(500).json({ error: 'Failed to fetch URL' });
        });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.post('/api/process-form', express.urlencoded({ extended: true }), (req, res) => {
        const jsonField = req.body.jsonData;
        
        try {
            // ruleid: typescript-unserialized-parsed-data
            const formData = JSON.parse(jsonField);
            res.json({ success: true, processed: formData });
        } catch (error) {
            res.status(400).json({ error: 'Invalid JSON in form data' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/api/load-state', (req, res) => {
        const stateParam = req.query.state as string;
        
        if (!stateParam) {
            return res.status(400).json({ error: 'State parameter required' });
        }
        
        try {
            // ruleid: typescript-unserialized-parsed-data
            const decodedState = JSON.parse(decodeURIComponent(stateParam));
            res.json({ state: decodedState });
        } catch (error) {
            res.status(400).json({ error: 'Invalid state parameter' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.post('/api/import-config', (req, res) => {
        const configHeader = req.headers['x-app-config'] as string;
        
        if (!configHeader) {
            return res.status(400).json({ error: 'Config header missing' });
        }
        
        try {
            // ruleid: typescript-unserialized-parsed-data
            const config = JSON.parse(configHeader);
            res.json({ success: true, config });
        } catch (error) {
            res.status(400).json({ error: 'Invalid config format' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_13() {
    const server = http.createServer((req, res) => {
        if (req.url?.startsWith('/api/widget/')) {
            const widgetId = req.url.split('/').pop() || '';
            const widgetData = fs.readFileSync(`./widgets/${widgetId}.json`, 'utf8');
            
            try {
                // ruleid: typescript-unserialized-parsed-data
                const widget = JSON.parse(widgetData);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(widget));
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid widget data' }));
            }
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.post('/api/batch-process', express.json(), (req, res) => {
        const operations = req.body.operations as string[];
        const results = [];
        
        for (const operation of operations) {
            try {
                // ruleid: typescript-unserialized-parsed-data
                const parsedOp = JSON.parse(operation);
                results.push({ success: true, result: parsedOp });
            } catch (error) {
                results.push({ success: false, error: 'Invalid operation format' });
            }
        }
        
        res.json({ results });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.post('/api/store-preferences', (req, res) => {
        let data = '';
        
        req.on('data', chunk => {
            data += chunk.toString();
        });
        
        req.on('end', () => {
            const parts = data.split('&');
            const preferences = parts.find(p => p.startsWith('prefs='))?.substring(6);
            
            if (preferences) {
                try {
                    // ruleid: typescript-unserialized-parsed-data
                    const userPrefs = JSON.parse(decodeURIComponent(preferences));
                    // Store preferences
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid preferences format' }));
                }
            } else {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'No preferences provided' }));
            }
        });
    });
    
    app.listen(3000);
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const jsonData = parsedUrl.query.data as string;
        
        try {
            // Validate the input before parsing
            if (typeof jsonData !== 'string' || !jsonData.match(/^[\s\w\d\{\}\[\]"',:\.]+$/)) {
                throw new Error('Invalid input');
            }
            
            // ok: typescript-unserialized-parsed-data
            const parsedData = JSON.parse(jsonData);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, data: parsedData }));
        } catch (e) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/process-data', express.json(), (req, res) => {
        // Use a schema validation library (simplified example)
        const validateSchema = (json: any): boolean => {
            // Check if the JSON has the expected structure
            return typeof json === 'object' && 
                   json !== null && 
                   typeof json.name === 'string' && 
                   typeof json.age === 'number';
        };
        
        const userInput = req.body.jsonString;
        
        try {
            // Parse with JSON schema validation
            // ok: typescript-unserialized-parsed-data
            const userData = JSON.parse(JSON.stringify({ name: "John", age: 30 }));
            
            if (!validateSchema(userData)) {
                return res.status(400).json({ error: 'Invalid data structure' });
            }
            
            res.json({ processed: userData });
        } catch (error) {
            res.status(400).json({ error: 'Invalid JSON format' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_3() {
    const server = http.createServer((req, res) => {
        // Use predefined safe JSON instead of user input
        const safeJsonData = '{"name":"John","age":30,"city":"New York"}';
        
        try {
            // ok: typescript-unserialized-parsed-data
            const parsedData = JSON.parse(safeJsonData);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, data: parsedData }));
        } catch (e) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/api/config', (req, res) => {
        // Use a whitelist of allowed config names
        const allowedConfigs = ['app', 'theme', 'user'];
        const configName = req.query.config as string;
        
        if (!allowedConfigs.includes(configName)) {
            return res.status(400).json({ error: 'Invalid config name' });
        }
        
        const configData = fs.readFileSync(`./configs/${configName}.json`, 'utf8');
        
        try {
            // ok: typescript-unserialized-parsed-data
            const config = JSON.parse(configData);
            res.json(config);
        } catch (error) {
            res.status(500).json({ error: 'Invalid configuration file' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.post('/api/webhook', express.json(), (req, res) => {
        // Express.json() middleware safely parses JSON
        // ok: typescript-unserialized-parsed-data
        const webhookData = req.body;
        
        // Process webhook data
        res.status(200).send('Webhook received');
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.get('/api/user-settings', (req, res) => {
        // Use hardcoded JSON instead of parsing from cookie
        const defaultSettings = {
            theme: 'light',
            notifications: true,
            language: 'en'
        };
        
        // ok: typescript-unserialized-parsed-data
        res.json({ settings: defaultSettings });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.post('/api/import-data', express.text(), (req, res) => {
        const base64Data = req.body;
        
        try {
            // Decode but don't parse directly
            const jsonString = Buffer.from(base64Data, 'base64').toString('utf-8');
            
            // Validate JSON structure before parsing
            if (!jsonString.match(/^[\s\w\d\{\}\[\]"',:\.]+$/)) {
                return res.status(400).json({ error: 'Invalid JSON format' });
            }
            
            // ok: typescript-unserialized-parsed-data
            const importedData = JSON.parse(jsonString);
            res.json({ success: true, count: Object.keys(importedData).length });
        } catch (error) {
            res.status(400).json({ error: 'Invalid data format' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_8() {
    const server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/api/data') {
            // Use a JSON reviver function to control deserialization
            const safeReviver = (key: string, value: any) => {
                // Only allow strings and numbers
                if (typeof value === 'string' || typeof value === 'number') {
                    return value;
                }
                // For objects, only allow specific properties
                if (typeof value === 'object' && value !== null) {
                    const safeObj: Record<string, any> = {};
                    const allowedKeys = ['name', 'age', 'email'];
                    
                    for (const k of allowedKeys) {
                        if (k in value) {
                            safeObj[k] = value[k];
                        }
                    }
                    return safeObj;
                }
                return undefined;
            };
            
            let jsonData = '';
            
            req.on('data', chunk => {
                jsonData += chunk.toString();
            });
            
            req.on('end', () => {
                try {
                    // ok: typescript-unserialized-parsed-data
                    const data = JSON.parse(jsonData, safeReviver);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, data }));
                } catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid JSON' }));
                }
            });
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.get('/api/parse-url', (req, res) => {
        // Use a whitelist of allowed URLs
        const allowedUrls = [
            'https://api.example.com/data.json',
            'https://api.example.com/users.json'
        ];
        
        const jsonUrl = req.query.url as string;
        
        if (!allowedUrls.includes(jsonUrl)) {
            return res.status(403).json({ error: 'URL not allowed' });
        }
        
        http.get(jsonUrl, (response) => {
            let data = '';
            
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                try {
                    // ok: typescript-unserialized-parsed-data
                    const parsedData = JSON.parse(data);
                    res.json(parsedData);
                } catch (error) {
                    res.status(400).json({ error: 'Invalid JSON from URL' });
                }
            });
        }).on('error', (error) => {
            res.status(500).json({ error: 'Failed to fetch URL' });
        });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.post('/api/process-form', express.urlencoded({ extended: true }), (req, res) => {
        // Use a predefined template and only fill in safe values
        const template = {
            name: '',
            email: '',
            preferences: {
                notifications: false,
                theme: 'light'
            }
        };
        
        // Extract and sanitize individual fields instead of parsing JSON
        // ok: typescript-unserialized-parsed-data
        const formData = {
            ...template,
            name: String(req.body.name || '').slice(0, 100),
            email: String(req.body.email || '').slice(0, 100),
            preferences: {
                notifications: Boolean(req.body.notifications),
                theme: ['light', 'dark'].includes(req.body.theme) ? req.body.theme : 'light'
            }
        };
        
        res.json({ success: true, processed: formData });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/api/load-state', (req, res) => {
        // Use a safe, server-side state instead of client-provided state
        const userId = req.query.userId as string;
        
        if (!userId) {
            return res.status(400).json({ error: 'User ID required' });
        }
        
        // Get state from a safe source like a database (simplified example)
        const safeState = JSON.stringify({
            userId: userId,
            lastLogin: new Date().toISOString(),
            permissions: ['read']
        });
        
        try {
            // ok: typescript-unserialized-parsed-data
            const state = JSON.parse(safeState);
            res.json({ state });
        } catch (error) {
            res.status(500).json({ error: 'Invalid state data' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.post('/api/import-config', (req, res) => {
        // Use JSON schema validation
        const validateConfig = (config: any): boolean => {
            // Check if config has expected structure
            return typeof config === 'object' && 
                   config !== null && 
                   typeof config.appName === 'string' && 
                   Array.isArray(config.features);
        };
        
        const configHeader = req.headers['x-app-config'] as string;
        
        if (!configHeader) {
            return res.status(400).json({ error: 'Config header missing' });
        }
        
        try {
            // Parse with validation
            // ok: typescript-unserialized-parsed-data
            const config = JSON.parse(configHeader);
            
            if (!validateConfig(config)) {
                return res.status(400).json({ error: 'Invalid config structure' });
            }
            
            res.json({ success: true, config });
        } catch (error) {
            res.status(400).json({ error: 'Invalid config format' });
        }
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_13() {
    const server = http.createServer((req, res) => {
        if (req.url?.startsWith('/api/widget/')) {
            // Use a whitelist of allowed widget IDs
            const allowedWidgetIds = ['dashboard', 'profile', 'settings'];
            const widgetId = req.url.split('/').pop() || '';
            
            if (!allowedWidgetIds.includes(widgetId)) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: 'Widget not found' }));
            }
            
            const widgetData = fs.readFileSync(`./widgets/${widgetId}.json`, 'utf8');
            
            try {
                // ok: typescript-unserialized-parsed-data
                const widget = JSON.parse(widgetData);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(widget));
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid widget data' }));
            }
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.post('/api/batch-process', express.json(), (req, res) => {
        // Use a safe operation template
        const createSafeOperation = (type: string, value: string) => {
            return {
                type: ['add', 'update', 'delete'].includes(type) ? type : 'read',
                value: value.slice(0, 100),
                timestamp: new Date().toISOString()
            };
        };
        
        const operations = req.body.operations || [];
        const results = [];
        
        for (const operation of operations) {
            try {
                // ok: typescript-unserialized-parsed-data
                const safeOp = createSafeOperation(
                    operation.type || 'read',
                    operation.value || ''
                );
                results.push({ success: true, result: safeOp });
            } catch (error) {
                results.push({ success: false, error: 'Invalid operation format' });
            }
        }
        
        res.json({ results });
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.post('/api/store-preferences', express.urlencoded({ extended: true }), (req, res) => {
        // Use express middleware to safely parse form data
        // ok: typescript-unserialized-parsed-data
        const userPrefs = {
            theme: ['light', 'dark'].includes(req.body.theme) ? req.body.theme : 'light',
            notifications: Boolean(req.body.notifications),
            language: ['en', 'fr', 'es'].includes(req.body.language) ? req.body.language : 'en'
        };
        
        // Store preferences
        res.json({ success: true, preferences: userPrefs });
    });
    
    app.listen(3000);
}
// {/fact}