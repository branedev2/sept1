import * as http from 'http';
import * as url from 'url';
import * as querystring from 'querystring';
import * as yaml from 'js-yaml';
import * as serialize from 'node-serialize';
import * as express from 'express';
import { Request, Response } from 'express';

// True Positive Examples (Vulnerable Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userInput = parsedUrl.query.data as string;
        
        try {
            // ruleid: typescript-user-controlled-unserialized-data
            const deserializedData = serialize.unserialize(userInput);
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ result: deserializedData }));
        } catch (error) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Invalid input');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/process-yaml', (req: Request, res: Response) => {
        const userInput = req.body.yamlData;
        
        try {
            // ruleid: typescript-user-controlled-unserialized-data
            const parsedYaml = yaml.load(userInput);
            
            res.status(200).json({ result: parsedYaml });
        } catch (error) {
            res.status(400).send('Invalid YAML');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_3() {
    const server = http.createServer((req, res) => {
        let body = '';
        
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            const postData = querystring.parse(body);
            const serializedObject = postData.serialized as string;
            
            try {
                // ruleid: typescript-user-controlled-unserialized-data
                const obj = serialize.unserialize(serializedObject);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ processed: obj }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Error processing data');
            }
        });
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/config', (req: Request, res: Response) => {
        const configData = req.query.config as string;
        
        try {
            // ruleid: typescript-user-controlled-unserialized-data
            const config = yaml.load(configData);
            
            res.status(200).json({ config });
        } catch (error) {
            res.status(400).send('Invalid configuration');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_5() {
    const server = http.createServer((req, res) => {
        const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.trim().split('=');
            acc[key] = value;
            return acc;
        }, {} as Record<string, string>) || {};
        
        const userData = cookies.userState;
        
        if (userData) {
            try {
                // ruleid: typescript-user-controlled-unserialized-data
                const userState = serialize.unserialize(userData);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ user: userState }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Invalid user state');
            }
        } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('No user state found');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.post('/import-data', (req: Request, res: Response) => {
        const headerData = req.headers['x-custom-data'] as string;
        
        if (headerData) {
            try {
                // ruleid: typescript-user-controlled-unserialized-data
                const importedData = yaml.load(headerData);
                
                res.status(200).json({ imported: importedData });
            } catch (error) {
                res.status(400).send('Invalid import data');
            }
        } else {
            res.status(400).send('No import data provided');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_7() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const base64Input = parsedUrl.query.data as string;
        
        if (base64Input) {
            try {
                const decodedInput = Buffer.from(base64Input, 'base64').toString();
                // ruleid: typescript-user-controlled-unserialized-data
                const parsedData = serialize.unserialize(decodedInput);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ result: parsedData }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Invalid input');
            }
        } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('No data provided');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.post('/process-template', (req: Request, res: Response) => {
        const template = req.body.template;
        const variables = req.body.variables;
        
        try {
            // First parse the variables
            // ruleid: typescript-user-controlled-unserialized-data
            const parsedVars = yaml.load(variables);
            
            // Use the variables to process the template
            const processedTemplate = template.replace(/\{\{(\w+)\}\}/g, (match: string, key: string) => {
                return parsedVars[key] || match;
            });
            
            res.status(200).send(processedTemplate);
        } catch (error) {
            res.status(400).send('Invalid template or variables');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_9() {
    const server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/api/data') {
            let body = '';
            
            req.on('data', chunk => {
                body += chunk.toString();
            });
            
            req.on('end', () => {
                try {
                    const jsonData = JSON.parse(body);
                    const serializedPart = jsonData.serializedData;
                    
                    // ruleid: typescript-user-controlled-unserialized-data
                    const deserializedData = serialize.unserialize(serializedPart);
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, data: deserializedData }));
                } catch (error) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.end('Invalid data format');
                }
            });
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.put('/update-config', (req: Request, res: Response) => {
        const configSection = req.query.section as string;
        const configData = req.body.data;
        
        try {
            // ruleid: typescript-user-controlled-unserialized-data
            const parsedConfig = yaml.load(configData);
            
            // Update configuration
            const result = { section: configSection, config: parsedConfig };
            
            res.status(200).json(result);
        } catch (error) {
            res.status(400).send('Invalid configuration data');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_11() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        
        if (parsedUrl.pathname === '/api/settings') {
            const format = parsedUrl.query.format as string;
            const data = parsedUrl.query.data as string;
            
            if (format === 'yaml') {
                try {
                    // ruleid: typescript-user-controlled-unserialized-data
                    const settings = yaml.load(data);
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ settings }));
                } catch (error) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.end('Invalid settings data');
                }
            } else {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Unsupported format');
            }
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.post('/user-preferences', (req: Request, res: Response) => {
        const userId = req.query.id as string;
        const preferencesData = req.body.preferences;
        
        if (!userId || !preferencesData) {
            return res.status(400).send('Missing user ID or preferences data');
        }
        
        try {
            // ruleid: typescript-user-controlled-unserialized-data
            const preferences = serialize.unserialize(preferencesData);
            
            // Save preferences to user profile
            const result = { userId, preferences };
            
            res.status(200).json(result);
        } catch (error) {
            res.status(400).send('Invalid preferences data');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_13() {
    const server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url?.startsWith('/api/import')) {
            let body = '';
            
            req.on('data', chunk => {
                body += chunk.toString();
            });
            
            req.on('end', () => {
                const contentType = req.headers['content-type'] || '';
                
                if (contentType.includes('application/x-yaml')) {
                    try {
                        // ruleid: typescript-user-controlled-unserialized-data
                        const importedData = yaml.load(body);
                        
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, data: importedData }));
                    } catch (error) {
                        res.writeHead(400, { 'Content-Type': 'text/plain' });
                        res.end('Invalid YAML data');
                    }
                } else {
                    res.writeHead(415, { 'Content-Type': 'text/plain' });
                    res.end('Unsupported Media Type');
                }
            });
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.post('/batch-process', (req: Request, res: Response) => {
        const operations = req.body.operations || [];
        
        const results = operations.map((operation: any) => {
            if (operation.type === 'parse-yaml' && operation.data) {
                try {
                    // ruleid: typescript-user-controlled-unserialized-data
                    const parsedData = yaml.load(operation.data);
                    return { success: true, result: parsedData };
                } catch (error) {
                    return { success: false, error: 'Invalid YAML data' };
                }
            }
            
            return { success: false, error: 'Unsupported operation' };
        });
        
        res.status(200).json({ results });
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_15() {
    const server = http.createServer((req, res) => {
        if (req.method === 'GET' && req.url?.startsWith('/api/template')) {
            const parsedUrl = url.parse(req.url, true);
            const templateId = parsedUrl.query.id as string;
            const templateData = parsedUrl.query.data as string;
            
            if (!templateId || !templateData) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Missing template ID or data');
                return;
            }
            
            try {
                // ruleid: typescript-user-controlled-unserialized-data
                const parsedTemplate = yaml.load(templateData);
                
                // Process template
                const result = {
                    id: templateId,
                    template: parsedTemplate,
                    processed: true
                };
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Invalid template data');
            }
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userInput = parsedUrl.query.data as string;
        
        try {
            // Validate the input before deserializing
            if (!userInput || typeof userInput !== 'string' || !isValidSerializedData(userInput)) {
                throw new Error('Invalid input');
            }
            
            // ok: typescript-user-controlled-unserialized-data
            const deserializedData = JSON.parse(userInput); // Using JSON.parse instead of unserialize
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ result: deserializedData }));
        } catch (error) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Invalid input');
        }
    });
    
    server.listen(3000);
}
// {/fact}

function isValidSerializedData(data: string): boolean {
    // Implement validation logic
    try {
        const parsed = JSON.parse(data);
        return typeof parsed === 'object' && parsed !== null;
    } catch {
        return false;
    }
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/process-yaml', (req: Request, res: Response) => {
        const userInput = req.body.yamlData;
        
        try {
            // ok: typescript-user-controlled-unserialized-data
            const parsedYaml = yaml.load(userInput, { schema: yaml.JSON_SCHEMA }); // Using safe schema
            
            res.status(200).json({ result: parsedYaml });
        } catch (error) {
            res.status(400).send('Invalid YAML');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_3() {
    const server = http.createServer((req, res) => {
        let body = '';
        
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            const postData = querystring.parse(body);
            const serializedObject = postData.serialized as string;
            
            try {
                // Using a whitelist of allowed keys
                const allowedKeys = ['name', 'age', 'email'];
                
                // ok: typescript-user-controlled-unserialized-data
                const obj = JSON.parse(serializedObject);
                
                // Filter out any keys that are not in the whitelist
                const filteredObj = Object.keys(obj)
                    .filter(key => allowedKeys.includes(key))
                    .reduce((acc, key) => {
                        acc[key] = obj[key];
                        return acc;
                    }, {} as Record<string, any>);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ processed: filteredObj }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Error processing data');
            }
        });
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/config', (req: Request, res: Response) => {
        const configData = req.query.config as string;
        
        try {
            // ok: typescript-user-controlled-unserialized-data
            const config = yaml.safeLoad(configData); // Using safeLoad instead of load
            
            res.status(200).json({ config });
        } catch (error) {
            res.status(400).send('Invalid configuration');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_5() {
    const server = http.createServer((req, res) => {
        const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.trim().split('=');
            acc[key] = value;
            return acc;
        }, {} as Record<string, string>) || {};
        
        const userData = cookies.userState;
        
        if (userData) {
            try {
                // ok: typescript-user-controlled-unserialized-data
                const userState = JSON.parse(userData); // Using JSON.parse instead of unserialize
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ user: userState }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Invalid user state');
            }
        } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('No user state found');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.post('/import-data', (req: Request, res: Response) => {
        const headerData = req.headers['x-custom-data'] as string;
        
        if (headerData) {
            try {
                // ok: typescript-user-controlled-unserialized-data
                const importedData = yaml.safeLoad(headerData, { schema: yaml.JSON_SCHEMA }); // Using safeLoad with safe schema
                
                res.status(200).json({ imported: importedData });
            } catch (error) {
                res.status(400).send('Invalid import data');
            }
        } else {
            res.status(400).send('No import data provided');
        }
    });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_7() {
    // Using a predefined template instead of user input
    const predefinedTemplates = {
        'user': { name: '', email: '', age: 0 },
        'product': { name: '', price: 0, description: '' },
        'order': { id: '', items: [], total: 0 }
    };
    
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const templateName = parsedUrl.query.template as string;
        
        if (templateName && templateName in predefinedTemplates) {
            // ok: typescript-user-controlled-unserialized-data
            const template = JSON.parse(JSON.stringify(predefinedTemplates[templateName as keyof typeof predefinedTemplates]));
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ template }));
        } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Invalid template name');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.post('/process-template', (req: Request, res: Response) => {
        const template = req.body.template;
        const variables = req.body.variables;
        
        try {
            // Parse variables as JSON instead of YAML
            // ok: typescript-user-controlled-unserialized-data
            const parsedVars = JSON.parse(variables);
            
            // Validate the variables against a schema
            if (!isValidVariables(parsedVars)) {
                throw new Error('Invalid variables');
            }
            
            // Use the variables to process the template
            const processedTemplate = template.replace(/\{\{(\w+)\}\}/g, (match: string, key: string) => {
                return parsedVars[key] || match;
            });
            
            res.status(200).send(processedTemplate);
        } catch (error) {
            res.status(400).send('Invalid template or variables');
        }
    });
}
// {/fact}

function isValidVariables(vars: any): boolean {
    // Implement validation logic
    if (typeof vars !== 'object' || vars === null) {
        return false;
    }
    
    // Check that all values are strings or numbers
    return Object.values(vars).every(value => 
        typeof value === 'string' || 
        typeof value === 'number'
    );
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_9() {
    // Using a predefined set of serialized data
    const serializedDataStore = {
        'user1': '{"name":"John","age":30,"email":"john@example.com"}',
        'user2': '{"name":"Jane","age":25,"email":"jane@example.com"}',
        'user3': '{"name":"Bob","age":40,"email":"bob@example.com"}'
    };
    
    const server = http.createServer((req, res) => {
        if (req.method === 'GET' && req.url?.startsWith('/api/user/')) {
            const userId = req.url.substring('/api/user/'.length);
            
            if (userId in serializedDataStore) {
                // ok: typescript-user-controlled-unserialized-data
                const userData = JSON.parse(serializedDataStore[userId as keyof typeof serializedDataStore]);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(userData));
            } else {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('User not found');
            }
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.put('/update-config', (req: Request, res: Response) => {
        const configSection = req.query.section as string;
        const configData = req.body.data;
        
        // Validate the section name
        const allowedSections = ['general', 'user', 'system'];
        
        if (!allowedSections.includes(configSection)) {
            return res.status(400).send('Invalid configuration section');
        }
        
        try {
            // ok: typescript-user-controlled-unserialized-data
            const parsedConfig = yaml.safeLoad(configData, { schema: yaml.JSON_SCHEMA }); // Using safeLoad with safe schema
            
            // Validate the configuration structure
            if (!isValidConfig(parsedConfig, configSection)) {
                throw new Error('Invalid configuration structure');
            }
            
            // Update configuration
            const result = { section: configSection, config: parsedConfig };
            
            res.status(200).json(result);
        } catch (error) {
            res.status(400).send('Invalid configuration data');
        }
    });
}
// {/fact}

function isValidConfig(config: any, section: string): boolean {
    // Implement validation logic based on the section
    if (typeof config !== 'object' || config === null) {
        return false;
    }
    
    // Different validation rules for different sections
    switch (section) {
        case 'general':
            return 'name' in config && 'version' in config;
        case 'user':
            return 'permissions' in config && Array.isArray(config.permissions);
        case 'system':
            return 'maxConnections' in config && typeof config.maxConnections === 'number';
        default:
            return false;
    }
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_11() {
    const server = http.createServer((req, res) => {
        // Use a trusted source for data instead of user input
        const trustedData = '{"name":"System Config","version":"1.0","settings":{"debug":false,"logLevel":"info"}}';
        
        try {
            // ok: typescript-user-controlled-unserialized-data
            const config = JSON.parse(trustedData);
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ config }));
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Error processing configuration');
        }
    });
    
    server.listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.post('/user-preferences', (req: Request, res: Response) => {
        const userId = req.query.id as string;
        const preferencesData = req.body.preferences;
        
        if (!userId || !preferencesData) {
            return res.status(400).send('Missing user ID or preferences data');
        }
        
        try {
            // ok: typescript-user-controlled-unserialized-data
            const preferences = JSON.parse(preferencesData); // Using JSON.parse instead of unserialize
            
            // Validate the preferences
            const validatedPreferences = validateUserPreferences(preferences);
            
            // Save preferences to user profile
            const result = { userId, preferences: validatedPreferences };
            
            res.status(200).json(result);
        } catch (error) {
            res.status(400).send('Invalid preferences data');
        }
    });
}
// {/fact}

function validateUserPreferences(prefs: any): Record<string, any> {
    // Implement validation logic
    const allowedPreferences = ['theme', 'language', 'notifications', 'timezone'];
    const validatedPrefs: Record<string, any> = {};
    
    for (const key of allowedPreferences) {
        if (key in prefs) {
            validatedPrefs[key] = prefs[key];
        }
    }
    
    return validatedPrefs;
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_13() {
    const server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url?.startsWith('/api/import')) {
            let body = '';
            
            req.on('data', chunk => {
                body += chunk.toString();
            });
            
            req.on('end', () => {
                const contentType = req.headers['content-type'] || '';
                
                if (contentType.includes('application/json')) {
                    try {
                        // ok: typescript-user-controlled-unserialized-data
                        const importedData = JSON.parse(body); // Using JSON.parse instead of yaml.load
                        
                        // Validate the imported data
                        if (!isValidImportData(importedData)) {
                            throw new Error('Invalid import data structure');
                        }
                        
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, data: importedData }));
                    } catch (error) {
                        res.writeHead(400, { 'Content-Type': 'text/plain' });
                        res.end('Invalid import data');
                    }
                } else {
                    res.writeHead(415, { 'Content-Type': 'text/plain' });
                    res.end('Unsupported Media Type');
                }
            });
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
        }
    });
    
    server.listen(3000);
}
// {/fact}

function isValidImportData(data: any): boolean {
    // Implement validation logic
    return typeof data === 'object' && 
           data !== null && 
           'version' in data && 
           'items' in data && 
           Array.isArray(data.items);
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.post('/batch-process', (req: Request, res: Response) => {
        const operations = req.body.operations || [];
        
        const results = operations.map((operation: any) => {
            if (operation.type === 'parse-json' && operation.data) {
                try {
                    // ok: typescript-user-controlled-unserialized-data
                    const parsedData = JSON.parse(operation.data); // Using JSON.parse instead of yaml.load
                    
                    // Validate the parsed data
                    if (!isValidBatchData(parsedData)) {
                        throw new Error('Invalid data structure');
                    }
                    
                    return { success: true, result: parsedData };
                } catch (error) {
                    return { success: false, error: 'Invalid data' };
                }
            }
            
            return { success: false, error: 'Unsupported operation' };
        });
        
        res.status(200).json({ results });
    });
}
// {/fact}

function isValidBatchData(data: any): boolean {
    // Implement validation logic
    return typeof data === 'object' && data !== null;
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_15() {
    // Using a predefined set of templates
    const templates = {
        'simple': '{"title":"Simple Template","fields":["name","email"]}',
        'advanced': '{"title":"Advanced Template","fields":["name","email","address","phone"],"options":{"required":["name","email"]}}'
    };
    
    const server = http.createServer((req, res) => {
        if (req.method === 'GET' && req.url?.startsWith('/api/template')) {
            const parsedUrl = url.parse(req.url, true);
            const templateId = parsedUrl.query.id as string;
            
            if (!templateId || !(templateId in templates)) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Invalid or missing template ID');
                return;
            }
            
            try {
                // ok: typescript-user-controlled-unserialized-data
                const parsedTemplate = JSON.parse(templates[templateId as keyof typeof templates]);
                
                // Process template
                const result = {
                    id: templateId,
                    template: parsedTemplate,
                    processed: true
                };
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Error processing template');
            }
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
        }
    });
    
    server.listen(3000);
}
// {/fact}