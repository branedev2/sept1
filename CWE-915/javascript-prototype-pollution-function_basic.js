// Prototype Pollution Examples
// Rule ID: javascript-prototype-pollution-function

// True Positive Examples (Vulnerable Code)

// Example 1: Basic unsafe merge function
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_1() {
  const request = require('http').IncomingMessage;
  const req = new request();
  
  // User-controlled data from query parameters
  const userData = JSON.parse(req.query.data);
  
  function unsafeMerge(target, source) {
    for (const key in source) {
      // ruleid: javascript-prototype-pollution-function
      target[key] = source[key];
    }
    return target;
  }
  
  const config = {};
  unsafeMerge(config, userData);
  return config;
}
// {/fact}

// Example 2: Recursive merge without property checks
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_2() {
  const express = require('express');
  const app = express();
  
  app.post('/update-settings', (req, res) => {
    const userInput = req.body;
    const settings = {};
    
    function deepMerge(target, source) {
      for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
          if (!target[key]) target[key] = {};
          // ruleid: javascript-prototype-pollution-function
          deepMerge(target[key], source[key]);
        } else {
          // ruleid: javascript-prototype-pollution-function
          target[key] = source[key];
        }
      }
      return target;
    }
    
    deepMerge(settings, userInput);
    res.json(settings);
  });
}
// {/fact}

// Example 3: Using Object.assign without property validation
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_3() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const userData = JSON.parse(body);
      const config = {};
      
      // ruleid: javascript-prototype-pollution-function
      Object.assign(config, userData);
      
      res.end(JSON.stringify(config));
    });
  }).listen(3000);
}
// {/fact}

// Example 4: Using spread operator with unvalidated input
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_4() {
  const express = require('express');
  const app = express();
  
  app.post('/api/merge', (req, res) => {
    const defaultConfig = { theme: 'light', notifications: true };
    
    // ruleid: javascript-prototype-pollution-function
    const mergedConfig = { ...defaultConfig, ...req.body };
    
    res.json(mergedConfig);
  });
}
// {/fact}

// Example 5: Custom extend function with nested objects
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_5() {
  const http = require('http');
  
  function processRequest(req) {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
    });
    
    req.on('end', () => {
      const userInput = JSON.parse(data);
      const baseObj = { settings: {} };
      
      function extend(target, source) {
        for (const prop in source) {
          if (source.hasOwnProperty(prop)) {
            if (typeof source[prop] === 'object') {
              if (!target[prop]) {
                target[prop] = {};
              }
              // ruleid: javascript-prototype-pollution-function
              extend(target[prop], source[prop]);
            } else {
              // ruleid: javascript-prototype-pollution-function
              target[prop] = source[prop];
            }
          }
        }
        return target;
      }
      
      extend(baseObj, userInput);
    });
  }
  
  http.createServer((req, res) => {
    processRequest(req);
    res.end('Done');
  }).listen(8080);
}
// {/fact}

// Example 6: Using lodash-like merge without checks
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_6() {
  const express = require('express');
  const app = express();
  
  app.post('/update', (req, res) => {
    const userOptions = req.body;
    const defaultOptions = { display: 'grid', color: 'blue' };
    
    function customMerge(target, ...sources) {
      sources.forEach(source => {
        for (const key in source) {
          const srcVal = source[key];
          const targetVal = target[key];
          
          if (isObject(srcVal) && isObject(targetVal)) {
            // ruleid: javascript-prototype-pollution-function
            customMerge(targetVal, srcVal);
          } else {
            // ruleid: javascript-prototype-pollution-function
            target[key] = srcVal;
          }
        }
      });
      
      return target;
    }
    
    function isObject(obj) {
      return obj && typeof obj === 'object';
    }
    
    const result = customMerge({}, defaultOptions, userOptions);
    res.json(result);
  });
}
// {/fact}

// Example 7: Dynamic property assignment with user input
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_7() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const { path, value } = parsedUrl.query;
    
    if (path && value) {
      const config = {};
      const pathParts = path.split('.');
      let current = config;
      
      for (let i = 0; i < pathParts.length - 1; i++) {
        const part = pathParts[i];
        if (!current[part]) {
          current[part] = {};
        }
        current = current[part];
      }
      
      // ruleid: javascript-prototype-pollution-function
      current[pathParts[pathParts.length - 1]] = value;
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(config));
    }
  }).listen(3000);
}
// {/fact}

// Example 8: jQuery-like extend implementation
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_8() {
  const express = require('express');
  const app = express();
  
  app.post('/settings', (req, res) => {
    const userSettings = req.body;
    const defaultSettings = { theme: 'dark', fontSize: 14 };
    
    function jQueryExtend(deep, target, ...sources) {
      if (typeof deep !== 'boolean') {
        sources.unshift(target);
        target = deep;
        deep = false;
      }
      
      sources.forEach(source => {
        if (!source) return;
        
        for (const key in source) {
          if (deep && typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key] || typeof target[key] !== 'object') {
              target[key] = Array.isArray(source[key]) ? [] : {};
            }
            // ruleid: javascript-prototype-pollution-function
            jQueryExtend(deep, target[key], source[key]);
          } else {
            // ruleid: javascript-prototype-pollution-function
            target[key] = source[key];
          }
        }
      });
      
      return target;
    }
    
    const result = jQueryExtend(true, {}, defaultSettings, userSettings);
    res.json(result);
  });
}
// {/fact}

// Example 9: Using Object.defineProperty with user input
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_9() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const userData = JSON.parse(body);
      const config = {};
      
      function defineProperties(obj, props) {
        for (const key in props) {
          // ruleid: javascript-prototype-pollution-function
          Object.defineProperty(obj, key, {
            value: props[key],
            writable: true,
            enumerable: true
          });
        }
        return obj;
      }
      
      defineProperties(config, userData);
      res.end(JSON.stringify(config));
    });
  }).listen(3000);
}
// {/fact}

// Example 10: Using Object.create with user-controlled prototype
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_10() {
  const express = require('express');
  const app = express();
  
  app.post('/create-object', (req, res) => {
    const userProto = req.body;
    
    // ruleid: javascript-prototype-pollution-function
    const newObject = Object.create(userProto);
    
    res.json(newObject);
  });
}
// {/fact}

// Example 11: Using a custom setter function
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_11() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const { path, value } = parsedUrl.query;
    
    function setNestedProperty(obj, path, value) {
      const parts = path.split('.');
      let current = obj;
      
      for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i];
        if (!current[part]) {
          current[part] = {};
        }
        current = current[part];
      }
      
      const lastPart = parts[parts.length - 1];
      // ruleid: javascript-prototype-pollution-function
      current[lastPart] = value;
      
      return obj;
    }
    
    const config = {};
    setNestedProperty(config, path, value);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(config));
  }).listen(3000);
}
// {/fact}

// Example 12: Using Object.entries and fromEntries with user input
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_12() {
  const express = require('express');
  const app = express();
  
  app.post('/transform', (req, res) => {
    const userInput = req.body;
    const baseConfig = { version: '1.0' };
    
    // Transform and merge objects
    const entries = Object.entries(userInput);
    // ruleid: javascript-prototype-pollution-function
    const result = Object.assign({}, baseConfig, Object.fromEntries(entries));
    
    res.json(result);
  });
}
// {/fact}

// Example 13: Using array reduce to build an object
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_13() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const keyValuePairs = JSON.parse(body);
      const baseObj = {};
      
      // ruleid: javascript-prototype-pollution-function
      const result = keyValuePairs.reduce((acc, [key, value]) => {
        acc[key] = value;
        return acc;
      }, baseObj);
      
      res.end(JSON.stringify(result));
    });
  }).listen(3000);
}
// {/fact}

// Example 14: Using eval for dynamic property assignment
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_14() {
  const express = require('express');
  const app = express();
  
  app.post('/dynamic-set', (req, res) => {
    const { path, value } = req.body;
    const config = {};
    
    try {
      // ruleid: javascript-prototype-pollution-function
      eval(`config.${path} = ${JSON.stringify(value)}`);
      res.json(config);
    } catch (error) {
      res.status(400).json({ error: 'Invalid input' });
    }
  });
}
// {/fact}

// Example 15: Using Function constructor for dynamic property assignment
// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_15() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const { path, value } = parsedUrl.query;
    
    const config = {};
    
    try {
      // ruleid: javascript-prototype-pollution-function
      new Function('obj', 'val', `obj.${path} = val`)(config, value);
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(config));
    } catch (error) {
      res.writeHead(400);
      res.end('Invalid input');
    }
  }).listen(3000);
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Safe merge with property validation
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_1() {
  const request = require('http').IncomingMessage;
  const req = new request();
  
  const userData = JSON.parse(req.query.data);
  
  function safeMerge(target, source) {
    for (const key in source) {
      // ok: javascript-prototype-pollution-function
      if (key !== '__proto__' && key !== 'constructor' && 
          Object.prototype.hasOwnProperty.call(source, key)) {
        target[key] = source[key];
      }
    }
    return target;
  }
  
  const config = {};
  safeMerge(config, userData);
  return config;
}
// {/fact}

// Example 2: Safe recursive merge with property checks
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_2() {
  const express = require('express');
  const app = express();
  
  app.post('/update-settings', (req, res) => {
    const userInput = req.body;
    const settings = {};
    
    function safeDeepMerge(target, source) {
      for (const key in source) {
        // ok: javascript-prototype-pollution-function
        if (key === '__proto__' || key === 'constructor' || 
            !Object.prototype.hasOwnProperty.call(source, key)) {
          continue;
        }
        
        if (typeof source[key] === 'object' && source[key] !== null) {
          if (!target[key]) target[key] = {};
          safeDeepMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
      return target;
    }
    
    safeDeepMerge(settings, userInput);
    res.json(settings);
  });
}
// {/fact}

// Example 3: Using Object.assign with a whitelist
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_3() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const userData = JSON.parse(body);
      const config = {};
      const allowedKeys = ['name', 'email', 'preferences'];
      
      // ok: javascript-prototype-pollution-function
      const safeData = Object.fromEntries(
        Object.entries(userData).filter(([key]) => allowedKeys.includes(key))
      );
      
      Object.assign(config, safeData);
      res.end(JSON.stringify(config));
    });
  }).listen(3000);
}
// {/fact}

// Example 4: Using spread operator with filtered input
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_4() {
  const express = require('express');
  const app = express();
  
  app.post('/api/merge', (req, res) => {
    const defaultConfig = { theme: 'light', notifications: true };
    const userConfig = req.body;
    
    // Filter out dangerous properties
    // ok: javascript-prototype-pollution-function
    const safeUserConfig = Object.keys(userConfig)
      .filter(key => key !== '__proto__' && key !== 'constructor')
      .reduce((obj, key) => {
        obj[key] = userConfig[key];
        return obj;
      }, {});
    
    const mergedConfig = { ...defaultConfig, ...safeUserConfig };
    res.json(mergedConfig);
  });
}
// {/fact}

// Example 5: Safe extend function with property validation
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_5() {
  const http = require('http');
  
  function processRequest(req) {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
    });
    
    req.on('end', () => {
      const userInput = JSON.parse(data);
      const baseObj = { settings: {} };
      
      function safeExtend(target, source) {
        for (const prop in source) {
          // ok: javascript-prototype-pollution-function
          if (prop !== '__proto__' && 
              prop !== 'constructor' && 
              Object.prototype.hasOwnProperty.call(source, prop)) {
            
            if (typeof source[prop] === 'object' && source[prop] !== null) {
              if (!target[prop]) {
                target[prop] = {};
              }
              safeExtend(target[prop], source[prop]);
            } else {
              target[prop] = source[prop];
            }
          }
        }
        return target;
      }
      
      safeExtend(baseObj, userInput);
    });
  }
  
  http.createServer((req, res) => {
    processRequest(req);
    res.end('Done');
  }).listen(8080);
}
// {/fact}

// Example 6: Using Object.create with safe prototype
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_6() {
  const express = require('express');
  const app = express();
  
  app.post('/create-object', (req, res) => {
    // ok: javascript-prototype-pollution-function
    // Using a known safe prototype instead of user input
    const safeProto = { 
      greet: function() { return 'Hello'; } 
    };
    
    const newObject = Object.create(safeProto);
    
    // Only copy safe properties from user input
    const userProps = req.body;
    const allowedProps = ['name', 'email', 'preferences'];
    
    for (const prop of allowedProps) {
      if (userProps[prop]) {
        newObject[prop] = userProps[prop];
      }
    }
    
    res.json(newObject);
  });
}
// {/fact}

// Example 7: Safe property assignment with path validation
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_7() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const { path, value } = parsedUrl.query;
    
    function setPropertySafely(obj, path, value) {
      // ok: javascript-prototype-pollution-function
      // Validate path to prevent prototype pollution
      if (!path || path.includes('__proto__') || path.includes('constructor')) {
        return false;
      }
      
      const parts = path.split('.');
      let current = obj;
      
      for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i];
        if (!current[part]) {
          current[part] = {};
        }
        current = current[part];
      }
      
      current[parts[parts.length - 1]] = value;
      return true;
    }
    
    const config = {};
    const success = setPropertySafely(config, path, value);
    
    if (success) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(config));
    } else {
      res.writeHead(400);
      res.end('Invalid path');
    }
  }).listen(3000);
}
// {/fact}

// Example 8: Using Object.defineProperties with property validation
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_8() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const userData = JSON.parse(body);
      const config = {};
      
      function definePropertiesSafely(obj, props) {
        // ok: javascript-prototype-pollution-function
        // Filter out dangerous properties
        const safeProps = Object.entries(props).reduce((acc, [key, value]) => {
          if (key !== '__proto__' && key !== 'constructor') {
            acc[key] = {
              value,
              writable: true,
              enumerable: true
            };
          }
          return acc;
        }, {});
        
        Object.defineProperties(obj, safeProps);
        return obj;
      }
      
      definePropertiesSafely(config, userData);
      res.end(JSON.stringify(config));
    });
  }).listen(3000);
}
// {/fact}

// Example 9: Using a safe custom merge function
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_9() {
  const express = require('express');
  const app = express();
  
  app.post('/settings', (req, res) => {
    const userSettings = req.body;
    const defaultSettings = { theme: 'dark', fontSize: 14 };
    
    function safeMerge(target, source) {
      // ok: javascript-prototype-pollution-function
      // Create a new object instead of modifying existing ones
      const result = { ...target };
      
      // Only copy own properties and skip dangerous ones
      for (const key of Object.keys(source)) {
        if (key !== '__proto__' && key !== 'constructor') {
          if (typeof source[key] === 'object' && source[key] !== null && 
              typeof result[key] === 'object' && result[key] !== null) {
            result[key] = safeMerge(result[key], source[key]);
          } else {
            result[key] = source[key];
          }
        }
      }
      
      return result;
    }
    
    const result = safeMerge(defaultSettings, userSettings);
    res.json(result);
  });
}
// {/fact}

// Example 10: Using Object.freeze to prevent modifications
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_10() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const userData = JSON.parse(body);
      
      // ok: javascript-prototype-pollution-function
      // Create a safe copy of user data with filtered properties
      const safeData = Object.keys(userData)
        .filter(key => key !== '__proto__' && key !== 'constructor')
        .reduce((obj, key) => {
          obj[key] = userData[key];
          return obj;
        }, {});
      
      // Freeze the object to prevent further modifications
      const frozenData = Object.freeze(safeData);
      
      res.end(JSON.stringify(frozenData));
    });
  }).listen(3000);
}
// {/fact}

// Example 11: Using Map instead of plain objects
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_11() {
  const express = require('express');
  const app = express();
  
  app.post('/store-data', (req, res) => {
    const userData = req.body;
    
    // ok: javascript-prototype-pollution-function
    // Using Map instead of plain object prevents prototype pollution
    const dataStore = new Map();
    
    // Safely store user data
    Object.entries(userData).forEach(([key, value]) => {
      dataStore.set(key, value);
    });
    
    // Convert back to object for response if needed
    const responseData = Object.fromEntries(dataStore.entries());
    res.json(responseData);
  });
}
// {/fact}

// Example 12: Using Object.getOwnPropertyNames for safe copying
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_12() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const userData = JSON.parse(body);
      const config = {};
      
      function safeCopy(target, source) {
        // ok: javascript-prototype-pollution-function
        // Only copy own enumerable properties
        Object.getOwnPropertyNames(source).forEach(prop => {
          if (prop !== '__proto__' && prop !== 'constructor') {
            if (typeof source[prop] === 'object' && source[prop] !== null) {
              target[prop] = {};
              safeCopy(target[prop], source[prop]);
            } else {
              target[prop] = source[prop];
            }
          }
        });
        
        return target;
      }
      
      safeCopy(config, userData);
      res.end(JSON.stringify(config));
    });
  }).listen(3000);
}
// {/fact}

// Example 13: Using JSON parse/stringify to break prototype chain
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_13() {
  const express = require('express');
  const app = express();
  
  app.post('/api/config', (req, res) => {
    const userConfig = req.body;
    const defaultConfig = { theme: 'light', fontSize: 16 };
    
    // ok: javascript-prototype-pollution-function
    // Using JSON parse/stringify to create a deep copy without prototype references
    const sanitizedUserConfig = JSON.parse(JSON.stringify(userConfig));
    
    // Merge configs safely
    const mergedConfig = { ...defaultConfig };
    for (const [key, value] of Object.entries(sanitizedUserConfig)) {
      if (key !== '__proto__' && key !== 'constructor') {
        mergedConfig[key] = value;
      }
    }
    
    res.json(mergedConfig);
  });
}
// {/fact}

// Example 14: Using Object.assign with explicit property checks
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_14() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const userData = parsedUrl.query;
    
    const config = { version: '1.0' };
    
    // ok: javascript-prototype-pollution-function
    // Explicitly check each property before assignment
    for (const key in userData) {
      if (Object.prototype.hasOwnProperty.call(userData, key) && 
          key !== '__proto__' && 
          key !== 'constructor') {
        config[key] = userData[key];
      }
    }
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(config));
  }).listen(3000);
}
// {/fact}

// Example 15: Using a whitelist approach for property assignment
// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_15() {
  const express = require('express');
  const app = express();
  
  app.post('/user-profile', (req, res) => {
    const userData = req.body;
    const profile = {};
    
    // ok: javascript-prototype-pollution-function
    // Define a whitelist of allowed properties
    const allowedProps = [
      'name', 'email', 'age', 'location', 'preferences', 
      'avatar', 'bio', 'socialLinks'
    ];
    
    // Only copy whitelisted properties
    allowedProps.forEach(prop => {
      if (userData[prop] !== undefined) {
        profile[prop] = userData[prop];
      }
    });
    
    res.json(profile);
  });
}
// {/fact}