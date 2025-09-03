import * as http from 'http';
import * as url from 'url';
import * as express from 'express';
import { Request, Response } from 'express';

// True Positive Examples (Vulnerable Code)

// Example 1: Basic dynamic method call with tainted data from query parameter
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const methodName = parsedUrl.query.method as string;
        
        const obj = {
            getPublicData: () => "Public data",
            getPrivateData: () => "SENSITIVE DATA: API Keys, passwords, etc.",
            executeCommand: (cmd: string) => `Executed: ${cmd}`
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(obj[methodName]());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 2: Dynamic method call with tainted data from POST body
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    app.use(express.json());
    
    app.post('/api/execute', (req: Request, res: Response) => {
        const methodName = req.body.method;
        
        const dataProcessor = {
            formatData: () => "Formatted data",
            getRawData: () => "Raw sensitive data",
            executeQuery: (q: string) => `Query result: ${q}`
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(dataProcessor[methodName]());
    });
}
// {/fact}

// Example 3: Dynamic method with parameters from request headers
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_3() {
    const server = http.createServer((req, res) => {
        const methodName = req.headers['x-method-name'] as string;
        const param = req.headers['x-param'] as string;
        
        const utils = {
            echo: (text: string) => text,
            log: (text: string) => `Logged: ${text}`,
            execute: (cmd: string) => `Executed: ${cmd}`
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(utils[methodName](param));
    });
    
    server.listen(3000);
}
// {/fact}

// Example 4: Dynamic method from cookie
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    app.use(express.json());
    
    app.get('/api/data', (req: Request, res: Response) => {
        const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.trim().split('=');
            acc[key] = value;
            return acc;
        }, {} as Record<string, string>) || {};
        
        const methodName = cookies['method'];
        
        const dataService = {
            getPublicData: () => "Public data",
            getAdminData: () => "Admin only data",
            executeAdminCommand: (cmd: string) => `Admin command: ${cmd}`
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(dataService[methodName]());
    });
}
// {/fact}

// Example 5: Dynamic method with tainted data through URL path parameter
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/api/:method', (req: Request, res: Response) => {
        const methodName = req.params.method;
        
        const apiMethods = {
            getUsers: () => JSON.stringify(["user1", "user2"]),
            getSecrets: () => JSON.stringify({"key": "secret_value"}),
            runCommand: (cmd: string) => `Result: ${cmd}`
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(apiMethods[methodName]());
    });
}
// {/fact}

// Example 6: Dynamic method with tainted data through multiple request parameters
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_6() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const category = parsedUrl.query.category as string;
        const action = parsedUrl.query.action as string;
        
        const methodName = `${category}_${action}`;
        
        const handlers = {
            user_get: () => "User data",
            user_delete: () => "User deleted",
            admin_get: () => "Admin data",
            admin_execute: (cmd: string) => `Executed: ${cmd}`
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(handlers[methodName]());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 7: Dynamic method with tainted data through request body JSON
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    app.use(express.json());
    
    app.post('/api/process', (req: Request, res: Response) => {
        const requestData = req.body;
        const methodName = requestData.operation;
        const param = requestData.parameter;
        
        const operations = {
            calculate: (formula: string) => `Result: ${eval(formula)}`,
            format: (text: string) => `Formatted: ${text}`,
            query: (sql: string) => `Query executed: ${sql}`
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(operations[methodName](param));
    });
}
// {/fact}

// Example 8: Dynamic method with tainted data through URL fragment
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_8() {
    const server = http.createServer((req, res) => {
        const fullUrl = req.url || '';
        const fragment = fullUrl.split('#')[1] || '';
        const methodName = fragment.split('=')[1] || 'default';
        
        const actions = {
            default: () => "Default action",
            getData: () => "Some data",
            getSecretData: () => "Secret data that should not be accessible"
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(actions[methodName]());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 9: Dynamic method with tainted data through referer header
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/api/data', (req: Request, res: Response) => {
        const referer = req.headers.referer || '';
        const methodName = new URL(referer).searchParams.get('method') || 'default';
        
        const dataProviders = {
            default: () => "Default data",
            public: () => "Public data",
            private: () => "Private data",
            admin: () => "Admin data"
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(dataProviders[methodName]());
    });
}
// {/fact}

// Example 10: Dynamic method with tainted data through user-agent
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_10() {
    const server = http.createServer((req, res) => {
        const userAgent = req.headers['user-agent'] || '';
        // Extract method from user-agent string (e.g., "Mozilla/5.0 (METHOD:getData)")
        const match = userAgent.match(/\(METHOD:([^)]+)\)/);
        const methodName = match ? match[1] : 'default';
        
        const handlers = {
            default: () => "Default response",
            getData: () => "Regular data",
            getSystemInfo: () => "System information: " + JSON.stringify(process.env)
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(handlers[methodName]());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 11: Dynamic method with tainted data through query parameter with processing
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/api/execute', (req: Request, res: Response) => {
        let methodName = req.query.method as string;
        // Some processing that doesn't validate the method
        methodName = methodName.toLowerCase().trim();
        
        const commands = {
            ping: () => "Pong!",
            time: () => new Date().toString(),
            env: () => JSON.stringify(process.env)
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(commands[methodName]());
    });
}
// {/fact}

// Example 12: Dynamic method with tainted data through base64 encoded parameter
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_12() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const encodedMethod = parsedUrl.query.cmd as string;
        
        // Decode the base64 encoded method name
        const methodName = Buffer.from(encodedMethod, 'base64').toString('utf-8');
        
        const actions = {
            echo: (text: string) => text,
            reverse: (text: string) => text.split('').reverse().join(''),
            execute: (cmd: string) => require('child_process').execSync(cmd).toString()
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(actions[methodName]("Hello world"));
    });
    
    server.listen(3000);
}
// {/fact}

// Example 13: Dynamic method with tainted data through multiple levels of processing
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    app.use(express.json());
    
    app.post('/api/complex', (req: Request, res: Response) => {
        const data = req.body;
        let methodName = '';
        
        if (data.type === 'direct') {
            methodName = data.method;
        } else if (data.type === 'encoded') {
            methodName = Buffer.from(data.method, 'base64').toString('utf-8');
        } else {
            methodName = 'default';
        }
        
        const handlers = {
            default: () => "Default handler",
            getData: () => "Some data",
            getConfig: () => JSON.stringify(require('fs').readFileSync('/etc/config.json', 'utf-8'))
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(handlers[methodName]());
    });
}
// {/fact}

// Example 14: Dynamic method with tainted data through custom header
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_14() {
    const server = http.createServer((req, res) => {
        const methodName = req.headers['x-custom-method'] as string || 'default';
        
        const apiHandlers = {
            default: () => "Default API response",
            getUsers: () => JSON.stringify(["user1", "user2"]),
            getSystemStatus: () => JSON.stringify({uptime: process.uptime(), memory: process.memoryUsage()})
        };
        
        // ruleid: typescript-unvalidated-dynamic-method-call
        res.end(apiHandlers[methodName]());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 15: Dynamic method with tainted data through websocket message
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_15() {
    const WebSocket = require('ws');
    const wss = new WebSocket.Server({ port: 8080 });
    
    wss.on('connection', (ws) => {
        ws.on('message', (message) => {
            const data = JSON.parse(message);
            const methodName = data.method;
            
            const handlers = {
                echo: (text: string) => text,
                broadcast: (text: string) => {
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN) {
                            client.send(text);
                        }
                    });
                    return "Broadcasted";
                },
                executeCommand: (cmd: string) => require('child_process').execSync(cmd).toString()
            };
            
            // This is similar to res.end in the context of websockets
            // ruleid: typescript-unvalidated-dynamic-method-call
            ws.send(handlers[methodName](data.param || ''));
        });
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Static method call with res.end
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const data = parsedUrl.query.data as string;
        
        const obj = {
            getPublicData: () => "Public data: " + data,
            getPrivateData: () => "SENSITIVE DATA: API Keys, passwords, etc."
        };
        
        // ok: typescript-unvalidated-dynamic-method-call
        res.end(obj.getPublicData());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 2: Validated dynamic method call with whitelist
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_2() {
    const app = express();
    app.use(express.json());
    
    app.post('/api/execute', (req: Request, res: Response) => {
        const methodName = req.body.method;
        
        const allowedMethods = ['formatData', 'getPublicData'];
        
        const dataProcessor = {
            formatData: () => "Formatted data",
            getPublicData: () => "Public data",
            getRawData: () => "Raw sensitive data"
        };
        
        // ok: typescript-unvalidated-dynamic-method-call
        if (allowedMethods.includes(methodName)) {
            res.end(dataProcessor[methodName]());
        } else {
            res.statusCode = 403;
            res.end("Method not allowed");
        }
    });
}
// {/fact}

// Example 3: Using a safe default method when input is invalid
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_3() {
    const server = http.createServer((req, res) => {
        const methodName = req.headers['x-method-name'] as string;
        
        const utils = {
            echo: (text: string) => text,
            log: (text: string) => `Logged: ${text}`,
            default: () => "Default response"
        };
        
        // ok: typescript-unvalidated-dynamic-method-call
        if (methodName === 'echo' || methodName === 'log') {
            res.end(utils[methodName]("Safe parameter"));
        } else {
            res.end(utils.default());
        }
    });
    
    server.listen(3000);
}
// {/fact}

// Example 4: Using a switch statement to validate method names
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/api/data', (req: Request, res: Response) => {
        const methodName = req.query.method as string;
        let result: string;
        
        // ok: typescript-unvalidated-dynamic-method-call
        switch (methodName) {
            case 'getPublicData':
                result = "Public data";
                break;
            case 'getStats':
                result = "Statistics data";
                break;
            default:
                result = "Unknown method";
                break;
        }
        
        res.end(result);
    });
}
// {/fact}

// Example 5: Using a Map for safe method mapping
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/api/:method', (req: Request, res: Response) => {
        const methodName = req.params.method;
        
        const safeMethodMap = new Map<string, () => string>([
            ['getUsers', () => JSON.stringify(["user1", "user2"])],
            ['getProducts', () => JSON.stringify(["product1", "product2"])]
        ]);
        
        // ok: typescript-unvalidated-dynamic-method-call
        if (safeMethodMap.has(methodName)) {
            res.end(safeMethodMap.get(methodName)!());
        } else {
            res.statusCode = 404;
            res.end("Method not found");
        }
    });
}
// {/fact}

// Example 6: Using object literal for safe method mapping
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_6() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const action = parsedUrl.query.action as string;
        
        // ok: typescript-unvalidated-dynamic-method-call
        const response = {
            'get': () => "Get response",
            'list': () => "List response",
            'search': () => "Search response"
        }[action] || (() => "Default response");
        
        res.end(response());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 7: Using regex pattern matching for method validation
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_7() {
    const app = express();
    app.use(express.json());
    
    app.post('/api/process', (req: Request, res: Response) => {
        const methodName = req.body.method;
        
        const operations = {
            calculate: (formula: string) => `Result: ${formula}`,
            format: (text: string) => `Formatted: ${text}`,
            query: (sql: string) => `Query: ${sql}`
        };
        
        // ok: typescript-unvalidated-dynamic-method-call
        if (methodName && /^(calculate|format|query)$/.test(methodName)) {
            res.end(operations[methodName as keyof typeof operations](req.body.param || ''));
        } else {
            res.statusCode = 400;
            res.end("Invalid method");
        }
    });
}
// {/fact}

// Example 8: Using type checking for method validation
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_8() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const methodName = parsedUrl.query.method;
        
        const actions = {
            getData: () => "Some data",
            getInfo: () => "Some info"
        };
        
        // ok: typescript-unvalidated-dynamic-method-call
        if (typeof methodName === 'string' && 
            (methodName === 'getData' || methodName === 'getInfo')) {
            res.end(actions[methodName as keyof typeof actions]());
        } else {
            res.statusCode = 400;
            res.end("Invalid method");
        }
    });
    
    server.listen(3000);
}
// {/fact}

// Example 9: Using a function to validate method names
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    function isValidMethod(method: string): boolean {
        const validMethods = ['getUsers', 'getProducts', 'getCategories'];
        return validMethods.includes(method);
    }
    
    app.get('/api/data', (req: Request, res: Response) => {
        const methodName = req.query.method as string;
        
        const dataProviders = {
            getUsers: () => JSON.stringify(["user1", "user2"]),
            getProducts: () => JSON.stringify(["product1", "product2"]),
            getCategories: () => JSON.stringify(["category1", "category2"]),
            getSecrets: () => JSON.stringify(["secret1", "secret2"])
        };
        
        // ok: typescript-unvalidated-dynamic-method-call
        if (isValidMethod(methodName)) {
            res.end(dataProviders[methodName as keyof typeof dataProviders]());
        } else {
            res.statusCode = 403;
            res.end("Method not allowed");
        }
    });
}
// {/fact}

// Example 10: Using a hardcoded method name
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_10() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        // Ignore user input, use hardcoded method
        const methodName = "getPublicData";
        
        const handlers = {
            getPublicData: () => "Public data",
            getPrivateData: () => "Private data"
        };
        
        // ok: typescript-unvalidated-dynamic-method-call
        res.end(handlers[methodName]());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 11: Using method mapping with validation
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/api/execute', (req: Request, res: Response) => {
        const userMethod = req.query.method as string;
        
        // Map potentially unsafe method names to safe implementations
        const methodMapping: Record<string, string> = {
            'get': 'getPublicData',
            'list': 'listPublicItems',
            'search': 'searchPublicData'
        };
        
        const safeMethodName = methodMapping[userMethod] || 'defaultMethod';
        
        const commands = {
            getPublicData: () => "Public data",
            listPublicItems: () => JSON.stringify(["item1", "item2"]),
            searchPublicData: () => "Search results",
            defaultMethod: () => "Default response"
        };
        
        // ok: typescript-unvalidated-dynamic-method-call
        res.end(commands[safeMethodName]());
    });
}
// {/fact}

// Example 12: Using a class with explicit method calls
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_12() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const action = parsedUrl.query.action as string;
        
        class DataService {
            getPublicData() {
                return "Public data";
            }
            
            getPrivateData() {
                return "Private data";
            }
            
            processRequest(action: string) {
                // ok: typescript-unvalidated-dynamic-method-call
                if (action === 'public') {
                    return this.getPublicData();
                } else {
                    return "Action not allowed";
                }
            }
        }
        
        const service = new DataService();
        res.end(service.processRequest(action));
    });
    
    server.listen(3000);
}
// {/fact}

// Example 13: Using a factory pattern for safe method selection
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_13() {
    const app = express();
    app.use(express.json());
    
    app.post('/api/complex', (req: Request, res: Response) => {
        const methodName = req.body.method;
        
        function createHandler(method: string) {
            // ok: typescript-unvalidated-dynamic-method-call
            switch (method) {
                case 'getData':
                    return () => "Some data";
                case 'getStats':
                    return () => "Statistics data";
                default:
                    return () => "Unknown method";
            }
        }
        
        const handler = createHandler(methodName);
        res.end(handler());
    });
}
// {/fact}

// Example 14: Using a decorator pattern for method validation
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_14() {
    const server = http.createServer((req, res) => {
        const methodName = req.headers['x-custom-method'] as string || 'default';
        
        const apiHandlers = {
            default: () => "Default API response",
            getUsers: () => JSON.stringify(["user1", "user2"]),
            getSystemStatus: () => JSON.stringify({status: "OK"})
        };
        
        function withValidation(handler: () => string, methodName: string): () => string {
            // ok: typescript-unvalidated-dynamic-method-call
            if (methodName in apiHandlers) {
                return handler;
            } else {
                return () => "Method not allowed";
            }
        }
        
        const safeHandler = withValidation(
            apiHandlers[methodName as keyof typeof apiHandlers] || apiHandlers.default,
            methodName
        );
        
        res.end(safeHandler());
    });
    
    server.listen(3000);
}
// {/fact}

// Example 15: Using a command pattern for safe method execution
// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    interface Command {
        execute(): string;
    }
    
    class GetDataCommand implements Command {
        execute(): string {
            return "Data retrieved";
        }
    }
    
    class ListItemsCommand implements Command {
        execute(): string {
            return JSON.stringify(["item1", "item2"]);
        }
    }
    
    class DefaultCommand implements Command {
        execute(): string {
            return "Unknown command";
        }
    }
    
    app.get('/api/command', (req: Request, res: Response) => {
        const commandType = req.query.type as string;
        
        // ok: typescript-unvalidated-dynamic-method-call
        let command: Command;
        if (commandType === 'getData') {
            command = new GetDataCommand();
        } else if (commandType === 'listItems') {
            command = new ListItemsCommand();
        } else {
            command = new DefaultCommand();
        }
        
        res.end(command.execute());
    });
}
// {/fact}