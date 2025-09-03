import * as http from 'http';
import * as url from 'url';
import * as util from 'util';
import * as querystring from 'querystring';
import * as express from 'express';

// TRUE POSITIVES (Vulnerable Code)

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
  
  app.post('/process', (req, res) => {
    const userObj = req.body.data;
    
    // ruleid: tofastproperties-code-execution-ts-rule
    util.toFastProperties(userObj);
    
    res.send('Data processed');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const userData = JSON.parse(body);
      
      // ruleid: tofastproperties-code-execution-ts-rule
      util.toFastProperties(userData);
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'success' }));
    });
  }).listen(8080);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split('=');
      acc[key] = value;
      return acc;
    }, {} as Record<string, string>) || {};
    
    const userConfig = JSON.parse(cookies.config || '{}');
    
    // ruleid: tofastproperties-code-execution-ts-rule
    util.toFastProperties(userConfig);
    
    res.end('Done');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/optimize', (req, res) => {
    const headerData = req.headers['x-custom-data'] as string;
    if (headerData) {
      const parsedData = JSON.parse(headerData);
      
      // ruleid: tofastproperties-code-execution-ts-rule
      util.toFastProperties(parsedData);
      
      res.send('Optimized');
    } else {
      res.status(400).send('Missing data');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/api/data') {
      let rawData = '';
      req.on('data', (chunk) => { rawData += chunk; });
      
      req.on('end', () => {
        try {
          const parsedData = querystring.parse(rawData);
          
          // ruleid: tofastproperties-code-execution-ts-rule
          util.toFastProperties(parsedData);
          
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('Success');
        } catch (e) {
          res.writeHead(400);
          res.end('Bad request');
        }
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.put('/update-settings', (req, res) => {
    const settings = req.query.settings as string;
    const parsedSettings = JSON.parse(settings);
    
    // ruleid: tofastproperties-code-execution-ts-rule
    util.toFastProperties(parsedSettings);
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const server = http.createServer((req, res) => {
    const parts = req.url?.split('?') || [];
    if (parts.length > 1) {
      const query = querystring.parse(parts[1]);
      const userObject = JSON.parse(query.data as string);
      
      // ruleid: tofastproperties-code-execution-ts-rule
      util.toFastProperties(userObject);
      
      res.writeHead(200);
      res.end('Processed');
    }
  });
  
  server.listen(8080);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.post('/process-array', (req, res) => {
    const userArray = req.body.items;
    
    if (Array.isArray(userArray)) {
      userArray.forEach(item => {
        // ruleid: tofastproperties-code-execution-ts-rule
        util.toFastProperties(item);
      });
    }
    
    res.send('Processed array items');
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  http.createServer((req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decodedToken = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      
      // ruleid: tofastproperties-code-execution-ts-rule
      util.toFastProperties(decodedToken);
      
      res.writeHead(200);
      res.end('Token processed');
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/process-nested', (req, res) => {
    const nestedData = req.query.nested as string;
    const parsed = JSON.parse(nestedData);
    
    function processObject(obj: any) {
      // ruleid: tofastproperties-code-execution-ts-rule
      util.toFastProperties(obj);
      
      for (const key in obj) {
        if (typeof obj[key] === 'object' && obj[key] !== null) {
          processObject(obj[key]);
        }
      }
    }
    
    processObject(parsed);
    res.send('Processed nested objects');
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const server = http.createServer((req, res) => {
    const referer = req.headers.referer;
    if (referer) {
      const parsedUrl = new URL(referer);
      const params = Object.fromEntries(parsedUrl.searchParams);
      
      // ruleid: tofastproperties-code-execution-ts-rule
      util.toFastProperties(params);
      
      res.writeHead(200);
      res.end('Referer processed');
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/upload-metadata', (req, res) => {
    const contentType = req.headers['content-type'] || '';
    
    if (contentType.includes('application/json')) {
      // ruleid: tofastproperties-code-execution-ts-rule
      util.toFastProperties(req.body);
      
      res.json({ status: 'Metadata processed' });
    } else {
      res.status(415).send('Unsupported Media Type');
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  http.createServer((req, res) => {
    if (req.url?.startsWith('/api/')) {
      const endpoint = req.url.substring(5);
      const userConfig = {
        endpoint: endpoint,
        timestamp: Date.now(),
        method: req.method
      };
      
      // ruleid: tofastproperties-code-execution-ts-rule
      util.toFastProperties(userConfig);
      
      res.writeHead(200);
      res.end('API request processed');
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/search', (req, res) => {
    const searchParams = {
      query: req.query.q,
      filters: req.query.filters ? JSON.parse(req.query.filters as string) : {},
      page: parseInt(req.query.page as string) || 1
    };
    
    // ruleid: tofastproperties-code-execution-ts-rule
    util.toFastProperties(searchParams);
    
    res.send('Search executed');
  });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const userInput = parsedUrl.query.input as string;
    
    // Validate and sanitize the input
    const safeObj = { value: userInput };
    
    // ok: tofastproperties-code-execution-ts-rule
    const staticObj = { prop1: "static", prop2: "value" };
    util.toFastProperties(staticObj);
    
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Processing complete');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/process', (req, res) => {
    // Create a new object with only allowed properties
    const safeObj = {
      id: 1,
      name: "Safe Object",
      timestamp: Date.now()
    };
    
    // ok: tofastproperties-code-execution-ts-rule
    util.toFastProperties(safeObj);
    
    res.send('Data processed safely');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  http.createServer((req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const configObject = {
      maxConnections: 100,
      timeout: 30000,
      retryAttempts: 3
    };
    util.toFastProperties(configObject);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'success' }));
  }).listen(8080);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split('=');
      acc[key] = value;
      return acc;
    }, {} as Record<string, string>) || {};
    
    // ok: tofastproperties-code-execution-ts-rule
    const appSettings = {
      theme: "light",
      language: "en",
      notifications: true
    };
    util.toFastProperties(appSettings);
    
    res.end('Done');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/optimize', (req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const staticConfig = {
      cacheSize: 1024,
      compressionLevel: 9,
      logLevel: "info"
    };
    util.toFastProperties(staticConfig);
    
    res.send('Optimized with safe configuration');
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/api/data') {
      // ok: tofastproperties-code-execution-ts-rule
      const systemDefaults = {
        version: "1.0.0",
        apiEndpoints: {
          users: "/api/users",
          products: "/api/products"
        },
        timeout: 5000
      };
      util.toFastProperties(systemDefaults);
      
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Success');
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.put('/update-settings', (req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const defaultSettings = {
      darkMode: false,
      fontSize: "medium",
      notifications: {
        email: true,
        push: false
      }
    };
    util.toFastProperties(defaultSettings);
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const server = http.createServer((req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const routeConfig = {
      "/home": { controller: "HomeController", action: "index" },
      "/about": { controller: "AboutController", action: "show" },
      "/contact": { controller: "ContactController", action: "form" }
    };
    util.toFastProperties(routeConfig);
    
    res.writeHead(200);
    res.end('Routes configured');
  });
  
  server.listen(8080);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.post('/process-array', (req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const predefinedItems = [
      { id: 1, name: "Item 1" },
      { id: 2, name: "Item 2" },
      { id: 3, name: "Item 3" }
    ];
    util.toFastProperties(predefinedItems);
    
    res.send('Processed predefined items');
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  http.createServer((req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const appConstants = {
      MAX_UPLOAD_SIZE: 10485760,
      ALLOWED_FILE_TYPES: ["jpg", "png", "pdf"],
      API_VERSION: "v2"
    };
    util.toFastProperties(appConstants);
    
    res.writeHead(200);
    res.end('Constants initialized');
  }).listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/process-nested', (req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const appStructure = {
      components: {
        header: { fixed: true, height: 60 },
        sidebar: { collapsible: true, width: 250 },
        footer: { sticky: false }
      },
      layout: "responsive"
    };
    util.toFastProperties(appStructure);
    
    res.send('App structure initialized');
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const server = http.createServer((req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const cacheConfig = {
      ttl: 3600,
      maxSize: 100,
      strategy: "lru"
    };
    util.toFastProperties(cacheConfig);
    
    res.writeHead(200);
    res.end('Cache configured');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/upload-metadata', (req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const metadataSchema = {
      title: { type: "string", required: true },
      description: { type: "string", required: false },
      tags: { type: "array", items: "string" }
    };
    util.toFastProperties(metadataSchema);
    
    res.json({ status: 'Schema initialized' });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  http.createServer((req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const errorMessages = {
      400: "Bad Request",
      401: "Unauthorized",
      403: "Forbidden",
      404: "Not Found",
      500: "Internal Server Error"
    };
    util.toFastProperties(errorMessages);
    
    res.writeHead(200);
    res.end('Error messages initialized');
  }).listen(3000);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/search', (req, res) => {
    // ok: tofastproperties-code-execution-ts-rule
    const searchDefaults = {
      resultsPerPage: 10,
      sortOrder: "desc",
      highlightMatches: true
    };
    util.toFastProperties(searchDefaults);
    
    res.send('Search defaults configured');
  });
}
// {/fact}