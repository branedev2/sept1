// File: unvalidated_dynamic_method_call_tests.js

const http = require('http');
const express = require('express');
const url = require('url');

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_1() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const method = parsedUrl.query.method;
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(method);
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/api', (req, res) => {
    const userMethod = req.query.method;
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(userMethod);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_3() {
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      
      // ruleid: javascript-unvalidated-dynamic-method-call
      res.end(data.method);
    });
  }).listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_4() {
  const server = http.createServer((req, res) => {
    const headers = req.headers;
    const customMethod = headers['x-custom-method'];
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(customMethod);
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/process', (req, res) => {
    const methodName = req.body.methodName;
    const processedMethod = methodName.toLowerCase();
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(processedMethod);
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_6() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie.split(';').reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split('=');
      acc[key] = value;
      return acc;
    }, {});
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(cookies.method);
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/execute/:method', (req, res) => {
    const methodToExecute = req.params.method;
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(methodToExecute);
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_8() {
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const methodParam = parsedUrl.query.action || 'default';
    
    if (methodParam.length > 0) {
      // ruleid: javascript-unvalidated-dynamic-method-call
      res.end(methodParam);
    } else {
      res.end('No method specified');
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/api/v1/execute', (req, res) => {
    const userInput = req.query;
    let methodToUse;
    
    if (userInput.primary) {
      methodToUse = userInput.primary;
    } else {
      methodToUse = userInput.fallback;
    }
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(methodToUse);
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_10() {
  const server = http.createServer((req, res) => {
    let methodName;
    
    switch(req.method) {
      case 'GET':
        methodName = url.parse(req.url, true).query.method;
        break;
      case 'POST':
        // Simplified for example
        methodName = req.body.method;
        break;
      default:
        methodName = 'unknown';
    }
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(methodName);
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.use((req, res, next) => {
    req.customMethod = req.query.method || req.headers['x-method'];
    next();
  });
  
  app.get('/execute', (req, res) => {
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(req.customMethod);
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_12() {
  http.createServer(async (req, res) => {
    const buffer = [];
    
    for await (const chunk of req) {
      buffer.push(chunk);
    }
    
    const data = JSON.parse(Buffer.concat(buffer).toString());
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(data.methodToExecute);
  }).listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/api', (req, res) => {
    const methods = req.query.methods ? req.query.methods.split(',') : [];
    
    if (methods.length > 0) {
      // ruleid: javascript-unvalidated-dynamic-method-call
      res.end(methods[0]);
    } else {
      res.end('No methods provided');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_14() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const params = parsedUrl.query;
    
    const methodObj = {
      name: params.methodName,
      version: params.version
    };
    
    // ruleid: javascript-unvalidated-dynamic-method-call
    res.end(methodObj.name);
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.post('/complex-operation', (req, res) => {
    const operation = {
      type: req.body.type,
      method: req.body.method,
      params: req.body.params
    };
    
    try {
      // Process operation
      const result = processOperation(operation);
      
      // ruleid: javascript-unvalidated-dynamic-method-call
      res.end(operation.method);
    } catch (error) {
      res.status(500).send('Error processing operation');
    }
  });
  
  function processOperation(op) {
    // Processing logic
    return true;
  }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_1() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const method = parsedUrl.query.method;
    
    // Create a map of allowed methods
    const allowedMethods = new Map([
      ['getData', 'Getting data...'],
      ['processInfo', 'Processing info...'],
      ['generateReport', 'Generating report...']
    ]);
    
    // ok: javascript-unvalidated-dynamic-method-call
    if (allowedMethods.has(method)) {
      res.end(allowedMethods.get(method));
    } else {
      res.end('Method not allowed');
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/api', (req, res) => {
    const userMethod = req.query.method;
    
    // Validate method against a whitelist
    const validMethods = ['get', 'list', 'search'];
    
    // ok: javascript-unvalidated-dynamic-method-call
    if (validMethods.includes(userMethod)) {
      res.end(`Executing ${userMethod}`);
    } else {
      res.status(400).end('Invalid method');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_3() {
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      const method = data.method;
      
      // ok: javascript-unvalidated-dynamic-method-call
      const methodMap = {
        'getData': () => 'Data retrieved',
        'processInfo': () => 'Info processed',
        'generateReport': () => 'Report generated'
      };
      
      if (method in methodMap) {
        res.end(methodMap[method]());
      } else {
        res.status(400).end('Invalid method');
      }
    });
  }).listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_4() {
  const server = http.createServer((req, res) => {
    const headers = req.headers;
    const customMethod = headers['x-custom-method'];
    
    // Validate method format using regex
    const methodRegex = /^[a-zA-Z0-9_]+$/;
    
    // ok: javascript-unvalidated-dynamic-method-call
    if (customMethod && methodRegex.test(customMethod)) {
      res.end(`Method ${customMethod} is valid`);
    } else {
      res.status(400).end('Invalid method format');
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/process', (req, res) => {
    const methodName = req.body.methodName;
    
    // ok: javascript-unvalidated-dynamic-method-call
    const methodsMap = new Map();
    methodsMap.set('getData', 'Getting data');
    methodsMap.set('processInfo', 'Processing info');
    methodsMap.set('generateReport', 'Generating report');
    
    if (methodsMap.has(methodName)) {
      res.end(methodsMap.get(methodName));
    } else {
      res.status(400).end('Unknown method');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_6() {
  const server = http.createServer((req, res) => {
    if (!req.headers.cookie) {
      res.status(400).end('No cookies provided');
      return;
    }
    
    const cookies = req.headers.cookie.split(';').reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split('=');
      acc[key] = value;
      return acc;
    }, {});
    
    // ok: javascript-unvalidated-dynamic-method-call
    const validMethods = ['method1', 'method2', 'method3'];
    const method = cookies.method;
    
    if (method && validMethods.includes(method)) {
      res.end(`Executing ${method}`);
    } else {
      res.status(400).end('Invalid method');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // Define allowed methods
  const allowedMethods = ['get', 'search', 'update', 'delete'];
  
  app.get('/execute/:method', (req, res) => {
    const methodToExecute = req.params.method;
    
    // ok: javascript-unvalidated-dynamic-method-call
    if (allowedMethods.includes(methodToExecute)) {
      res.end(`Executing ${methodToExecute}`);
    } else {
      res.status(403).end('Method not allowed');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_8() {
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const methodParam = parsedUrl.query.action || 'default';
    
    // ok: javascript-unvalidated-dynamic-method-call
    switch (methodParam) {
      case 'getData':
        res.end('Getting data');
        break;
      case 'processInfo':
        res.end('Processing info');
        break;
      case 'generateReport':
        res.end('Generating report');
        break;
      default:
        res.end('Unknown method');
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/api/v1/execute', (req, res) => {
    const userInput = req.query;
    
    // ok: javascript-unvalidated-dynamic-method-call
    const validMethods = new Set(['method1', 'method2', 'method3']);
    
    if (userInput.primary && validMethods.has(userInput.primary)) {
      res.end(`Executing primary: ${userInput.primary}`);
    } else if (userInput.fallback && validMethods.has(userInput.fallback)) {
      res.end(`Executing fallback: ${userInput.fallback}`);
    } else {
      res.status(400).end('Invalid method');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_10() {
  const server = http.createServer((req, res) => {
    let methodName;
    
    switch(req.method) {
      case 'GET':
        methodName = url.parse(req.url, true).query.method;
        break;
      case 'POST':
        // Simplified for example
        methodName = req.body.method;
        break;
      default:
        methodName = 'unknown';
    }
    
    // ok: javascript-unvalidated-dynamic-method-call
    const validMethods = Object.freeze({
      'getData': 'Getting data',
      'processInfo': 'Processing info',
      'generateReport': 'Generating report'
    });
    
    if (methodName in validMethods) {
      res.end(validMethods[methodName]);
    } else {
      res.status(400).end('Invalid method');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.use((req, res, next) => {
    req.customMethod = req.query.method || req.headers['x-method'];
    next();
  });
  
  app.get('/execute', (req, res) => {
    // ok: javascript-unvalidated-dynamic-method-call
    const methodValidator = (method) => {
      const validMethods = ['get', 'search', 'update'];
      return validMethods.includes(method);
    };
    
    if (req.customMethod && methodValidator(req.customMethod)) {
      res.end(`Executing ${req.customMethod}`);
    } else {
      res.status(400).end('Invalid method');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_12() {
  http.createServer(async (req, res) => {
    const buffer = [];
    
    for await (const chunk of req) {
      buffer.push(chunk);
    }
    
    const data = JSON.parse(Buffer.concat(buffer).toString());
    
    // ok: javascript-unvalidated-dynamic-method-call
    const methodMap = new Map([
      ['getData', 'Getting data...'],
      ['processInfo', 'Processing info...'],
      ['generateReport', 'Generating report...']
    ]);
    
    if (methodMap.has(data.methodToExecute)) {
      res.end(methodMap.get(data.methodToExecute));
    } else {
      res.status(400).end('Invalid method');
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/api', (req, res) => {
    const methods = req.query.methods ? req.query.methods.split(',') : [];
    
    // ok: javascript-unvalidated-dynamic-method-call
    const allowedMethods = new Set(['get', 'search', 'update', 'delete']);
    const validMethods = methods.filter(method => allowedMethods.has(method));
    
    if (validMethods.length > 0) {
      res.end(`Valid methods: ${validMethods.join(', ')}`);
    } else {
      res.end('No valid methods provided');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_14() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const params = parsedUrl.query;
    
    const methodObj = {
      name: params.methodName,
      version: params.version
    };
    
    // ok: javascript-unvalidated-dynamic-method-call
    const validMethodNames = ['method1', 'method2', 'method3'];
    
    if (methodObj.name && validMethodNames.includes(methodObj.name)) {
      res.end(`Executing ${methodObj.name} version ${methodObj.version || 'latest'}`);
    } else {
      res.status(400).end('Invalid method name');
    }
  });
}
// {/fact}

// {fact rule=check-result-of-file-mkdir@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.post('/complex-operation', (req, res) => {
    const operation = {
      type: req.body.type,
      method: req.body.method,
      params: req.body.params
    };
    
    // ok: javascript-unvalidated-dynamic-method-call
    const validMethods = {
      'getData': (params) => `Getting data with params: ${JSON.stringify(params)}`,
      'processInfo': (params) => `Processing info with params: ${JSON.stringify(params)}`,
      'generateReport': (params) => `Generating report with params: ${JSON.stringify(params)}`
    };
    
    try {
      if (operation.method in validMethods) {
        const result = validMethods[operation.method](operation.params);
        res.end(result);
      } else {
        res.status(400).end('Invalid method');
      }
    } catch (error) {
      res.status(500).send('Error processing operation');
    }
  });
}
// {/fact}

module.exports = {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};