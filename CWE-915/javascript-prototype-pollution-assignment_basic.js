// Prototype Pollution Assignment Test Cases

// True Positives (Vulnerable Code)

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_1() {
  const express = require('express');
  const app = express();
  
  app.get('/api/settings', (req, res) => {
    const userSettings = {};
    const propertyName = req.query.property;
    const value = req.query.value;
    
    // ruleid: javascript-prototype-pollution-assignment
    userSettings[propertyName] = value;
    
    res.json(userSettings);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_2() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const obj = {};
    
    for (const key in parsedUrl.query) {
      // ruleid: javascript-prototype-pollution-assignment
      obj[key] = parsedUrl.query[key];
    }
    
    res.end(JSON.stringify(obj));
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_3() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/update-config', (req, res) => {
    const config = {};
    const updates = req.body;
    
    Object.keys(updates).forEach(key => {
      // ruleid: javascript-prototype-pollution-assignment
      config[key] = updates[key];
    });
    
    res.json({ success: true, config });
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_4() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      const userProfile = {};
      
      // ruleid: javascript-prototype-pollution-assignment
      userProfile[data.field] = data.value;
      
      res.end(JSON.stringify(userProfile));
    });
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_5() {
  const express = require('express');
  const app = express();
  
  app.get('/set-preference', (req, res) => {
    const preferences = {};
    const key = req.query.key;
    const value = req.query.value;
    
    if (key && value) {
      // ruleid: javascript-prototype-pollution-assignment
      preferences[key] = value;
    }
    
    res.json(preferences);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_6() {
  const WebSocket = require('ws');
  const wss = new WebSocket.Server({ port: 8080 });
  
  wss.on('connection', (ws) => {
    ws.on('message', (message) => {
      const data = JSON.parse(message);
      const settings = {};
      
      // ruleid: javascript-prototype-pollution-assignment
      settings[data.option] = data.setting;
      
      ws.send(JSON.stringify(settings));
    });
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_7() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/merge-objects', (req, res) => {
    const baseObj = {};
    const userObj = req.body.userObject;
    
    for (const prop in userObj) {
      // ruleid: javascript-prototype-pollution-assignment
      baseObj[prop] = userObj[prop];
    }
    
    res.json(baseObj);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_8() {
  const http = require('http');
  const querystring = require('querystring');
  
  http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        const postData = querystring.parse(body);
        const obj = {};
        
        // ruleid: javascript-prototype-pollution-assignment
        obj[postData.key] = postData.value;
        
        res.end(JSON.stringify(obj));
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_9() {
  const express = require('express');
  const app = express();
  
  app.get('/dynamic-property', (req, res) => {
    const dynamicObj = {};
    const propPath = req.query.path;
    
    // ruleid: javascript-prototype-pollution-assignment
    dynamicObj[propPath] = req.query.content;
    
    res.json(dynamicObj);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_10() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/update-nested', (req, res) => {
    const config = { settings: {} };
    const path = req.body.path;
    const value = req.body.value;
    
    // ruleid: javascript-prototype-pollution-assignment
    config.settings[path] = value;
    
    res.json(config);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_11() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const options = {};
    
    if (parsedUrl.pathname === '/set-option') {
      // ruleid: javascript-prototype-pollution-assignment
      options[parsedUrl.query.name] = parsedUrl.query.value;
    }
    
    res.end(JSON.stringify(options));
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_12() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/create-user', (req, res) => {
    const user = {};
    const userData = req.body;
    
    for (const [key, value] of Object.entries(userData)) {
      // ruleid: javascript-prototype-pollution-assignment
      user[key] = value;
    }
    
    res.json({ success: true, user });
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_13() {
  const http = require('http');
  
  http.createServer((req, res) => {
    if (req.url.startsWith('/api/config')) {
      const configKey = req.url.split('/')[3];
      const configValue = req.url.split('/')[4];
      const config = {};
      
      // ruleid: javascript-prototype-pollution-assignment
      config[configKey] = configValue;
      
      res.end(JSON.stringify(config));
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_14() {
  const express = require('express');
  const app = express();
  
  app.get('/search', (req, res) => {
    const searchParams = {};
    const filters = req.query.filters ? JSON.parse(req.query.filters) : {};
    
    Object.keys(filters).forEach(filter => {
      // ruleid: javascript-prototype-pollution-assignment
      searchParams[filter] = filters[filter];
    });
    
    res.json(searchParams);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_15() {
  const WebSocket = require('ws');
  const wss = new WebSocket.Server({ port: 8080 });
  
  wss.on('connection', (ws) => {
    const clientState = {};
    
    ws.on('message', (message) => {
      const command = JSON.parse(message);
      
      if (command.type === 'SET_STATE') {
        // ruleid: javascript-prototype-pollution-assignment
        clientState[command.key] = command.value;
      }
      
      ws.send(JSON.stringify(clientState));
    });
  });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_1() {
  const express = require('express');
  const app = express();
  
  app.get('/api/settings', (req, res) => {
    const userSettings = {};
    const propertyName = req.query.property;
    const value = req.query.value;
    
    // ok: javascript-prototype-pollution-assignment
    if (propertyName && Object.prototype.hasOwnProperty.call(userSettings, propertyName)) {
      userSettings[propertyName] = value;
    }
    
    res.json(userSettings);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_2() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const obj = {};
    
    for (const key in parsedUrl.query) {
      // ok: javascript-prototype-pollution-assignment
      if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
        obj[key] = parsedUrl.query[key];
      }
    }
    
    res.end(JSON.stringify(obj));
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_3() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/update-config', (req, res) => {
    const config = {};
    const updates = req.body;
    const safeKeys = ['theme', 'language', 'timezone', 'notifications'];
    
    Object.keys(updates).forEach(key => {
      // ok: javascript-prototype-pollution-assignment
      if (safeKeys.includes(key)) {
        config[key] = updates[key];
      }
    });
    
    res.json({ success: true, config });
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_4() {
  const http = require('http');
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      const userProfile = {};
      
      // ok: javascript-prototype-pollution-assignment
      if (data.field && typeof data.field === 'string' && !data.field.startsWith('__')) {
        userProfile[data.field] = data.value;
      }
      
      res.end(JSON.stringify(userProfile));
    });
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_5() {
  const express = require('express');
  const app = express();
  
  app.get('/set-preference', (req, res) => {
    const preferences = {};
    const key = req.query.key;
    const value = req.query.value;
    const allowedKeys = ['color', 'size', 'font', 'layout'];
    
    if (key && value) {
      // ok: javascript-prototype-pollution-assignment
      if (allowedKeys.includes(key)) {
        preferences[key] = value;
      }
    }
    
    res.json(preferences);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_6() {
  const WebSocket = require('ws');
  const wss = new WebSocket.Server({ port: 8080 });
  
  wss.on('connection', (ws) => {
    ws.on('message', (message) => {
      const data = JSON.parse(message);
      const settings = {};
      
      // ok: javascript-prototype-pollution-assignment
      if (Object.prototype.hasOwnProperty.call(data, 'option') && 
          Object.prototype.hasOwnProperty.call(data, 'setting')) {
        settings[data.option] = data.setting;
      }
      
      ws.send(JSON.stringify(settings));
    });
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_7() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/merge-objects', (req, res) => {
    const baseObj = {};
    const userObj = req.body.userObject;
    
    for (const prop in userObj) {
      // ok: javascript-prototype-pollution-assignment
      if (Object.prototype.hasOwnProperty.call(userObj, prop)) {
        baseObj[prop] = userObj[prop];
      }
    }
    
    res.json(baseObj);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_8() {
  const http = require('http');
  const querystring = require('querystring');
  
  http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        const postData = querystring.parse(body);
        const obj = {};
        
        // ok: javascript-prototype-pollution-assignment
        const safeKey = postData.key && typeof postData.key === 'string' ? 
                        postData.key.replace(/^__proto__|constructor|prototype$/g, 'safe_$&') : '';
        if (safeKey) {
          obj[safeKey] = postData.value;
        }
        
        res.end(JSON.stringify(obj));
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_9() {
  const express = require('express');
  const app = express();
  
  app.get('/dynamic-property', (req, res) => {
    const dynamicObj = {};
    const propPath = req.query.path;
    
    // ok: javascript-prototype-pollution-assignment
    if (propPath && propPath !== '__proto__' && propPath !== 'constructor') {
      dynamicObj[propPath] = req.query.content;
    }
    
    res.json(dynamicObj);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_10() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/update-nested', (req, res) => {
    const config = { settings: {} };
    const path = req.body.path;
    const value = req.body.value;
    const validPaths = ['theme', 'notifications', 'privacy', 'security'];
    
    // ok: javascript-prototype-pollution-assignment
    if (validPaths.includes(path)) {
      config.settings[path] = value;
    }
    
    res.json(config);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_11() {
  const http = require('http');
  const url = require('url');
  
  http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const options = {};
    
    if (parsedUrl.pathname === '/set-option') {
      const name = parsedUrl.query.name;
      // ok: javascript-prototype-pollution-assignment
      if (name && typeof name === 'string' && 
          !['__proto__', 'constructor', 'prototype'].includes(name)) {
        options[name] = parsedUrl.query.value;
      }
    }
    
    res.end(JSON.stringify(options));
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_12() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  app.post('/create-user', (req, res) => {
    const user = {};
    const userData = req.body;
    const allowedFields = ['name', 'email', 'age', 'address', 'phone'];
    
    for (const [key, value] of Object.entries(userData)) {
      // ok: javascript-prototype-pollution-assignment
      if (allowedFields.includes(key)) {
        user[key] = value;
      }
    }
    
    res.json({ success: true, user });
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_13() {
  const http = require('http');
  
  http.createServer((req, res) => {
    if (req.url.startsWith('/api/config')) {
      const configKey = req.url.split('/')[3];
      const configValue = req.url.split('/')[4];
      const config = {};
      const validKeys = ['timeout', 'retries', 'cache', 'debug'];
      
      // ok: javascript-prototype-pollution-assignment
      if (validKeys.includes(configKey)) {
        config[configKey] = configValue;
      }
      
      res.end(JSON.stringify(config));
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_14() {
  const express = require('express');
  const app = express();
  
  app.get('/search', (req, res) => {
    const searchParams = {};
    const filters = req.query.filters ? JSON.parse(req.query.filters) : {};
    
    Object.keys(filters).forEach(filter => {
      // ok: javascript-prototype-pollution-assignment
      if (filter && Object.prototype.toString.call(filter) === '[object String]' &&
          !filter.includes('__proto__') && filter !== 'constructor') {
        searchParams[filter] = filters[filter];
      }
    });
    
    res.json(searchParams);
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_15() {
  const WebSocket = require('ws');
  const wss = new WebSocket.Server({ port: 8080 });
  
  wss.on('connection', (ws) => {
    const clientState = {};
    const validStateKeys = ['username', 'status', 'preferences', 'lastSeen'];
    
    ws.on('message', (message) => {
      const command = JSON.parse(message);
      
      if (command.type === 'SET_STATE') {
        // ok: javascript-prototype-pollution-assignment
        if (validStateKeys.includes(command.key)) {
          clientState[command.key] = command.value;
        }
      }
      
      ws.send(JSON.stringify(clientState));
    });
  });
}
// {/fact}