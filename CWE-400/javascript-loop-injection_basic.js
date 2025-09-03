// Test cases for javascript-loop-injection rule
// This file contains examples of vulnerable and secure code patterns
// related to iterating over user-controlled data

// Import common libraries for HTTP handling
const express = require('express');
const app = express();
const http = require('http');
const https = require('https');
const axios = require('axios');
const querystring = require('querystring');

// True Positive Cases (Vulnerable)

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1() {
  const req = new XMLHttpRequest();
  req.open('GET', '/api/data', false);
  req.send(null);
  
  if (req.status === 200) {
    const data = JSON.parse(req.responseText);
    
    // ruleid: javascript-loop-injection
    for (const key in data) {
      console.log(key, data[key]);
      // Potentially infinite loop if data is maliciously crafted
    }
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_2() {
  fetch('/api/userdata')
    .then(response => response.json())
    .then(userData => {
      // ruleid: javascript-loop-injection
      Object.keys(userData).forEach(key => {
        // Process each key without checking the object size
        processUserData(key, userData[key]);
      });
    });
  
  function processUserData(key, value) {
    console.log(`Processing ${key}: ${value}`);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_3() {
  const http = require('http');
  
  http.get('http://example.com/api/items', (res) => {
    let data = '';
    
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      const items = JSON.parse(data);
      
      // ruleid: javascript-loop-injection
      for (let i = 0; i < items.length; i++) {
        // No limit on array length, could be exploited
        heavyOperation(items[i]);
      }
    });
  });
  
  function heavyOperation(item) {
    // Some CPU-intensive operation
    console.log(item);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4() {
  const express = require('express');
  const app = express();
  
  app.get('/process', (req, res) => {
    const userInput = req.query.data ? JSON.parse(req.query.data) : {};
    
    // ruleid: javascript-loop-injection
    Object.entries(userInput).forEach(([key, value]) => {
      // No validation on object size or structure
      processEntry(key, value);
    });
    
    res.send('Processing complete');
  });
  
  function processEntry(key, value) {
    // Some processing logic
    return key + value;
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5() {
  const axios = require('axios');
  
  axios.get('/api/config')
    .then(response => {
      const config = response.data;
      
      // ruleid: javascript-loop-injection
      while (config.hasNext()) {
        // User-controlled iterator without limit
        const item = config.next();
        processConfigItem(item);
      }
    });
  
  function processConfigItem(item) {
    console.log('Processing:', item);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6() {
  const userInput = document.getElementById('userJson').value;
  const data = JSON.parse(userInput);
  
  // ruleid: javascript-loop-injection
  for (const prop in data) {
    if (data.hasOwnProperty(prop)) {
      // No limit on object properties
      document.write(`<div>${prop}: ${data[prop]}</div>`);
    }
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7() {
  const socket = new WebSocket('ws://example.com/socket');
  
  socket.onmessage = function(event) {
    const message = JSON.parse(event.data);
    
    // ruleid: javascript-loop-injection
    message.items.map(item => {
      // No validation on array length
      processItem(item);
    });
  };
  
  function processItem(item) {
    // CPU-intensive operation
    console.log(item);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8() {
  const req = new XMLHttpRequest();
  req.open('GET', '/api/records', false);
  req.send(null);
  
  if (req.status === 200) {
    const records = JSON.parse(req.responseText);
    
    // ruleid: javascript-loop-injection
    let i = 0;
    while (i < records.length) {
      // No upper bound on iteration
      processRecord(records[i]);
      i++;
    }
  }
  
  function processRecord(record) {
    // Some processing
    console.log(record);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_9() {
  fetch('/api/comments')
    .then(response => response.json())
    .then(comments => {
      // ruleid: javascript-loop-injection
      comments.forEach((comment, index) => {
        // No validation on array size
        renderComment(comment, index);
      });
    });
  
  function renderComment(comment, index) {
    const div = document.createElement('div');
    div.textContent = `${index}: ${comment.text}`;
    document.body.appendChild(div);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10() {
  const queryString = window.location.search;
  const urlParams = new URLSearchParams(queryString);
  const filters = JSON.parse(urlParams.get('filters') || '{}');
  
  // ruleid: javascript-loop-injection
  for (const filter of Object.values(filters)) {
    // User can control the number of filters
    applyFilter(filter);
  }
  
  function applyFilter(filter) {
    // Expensive operation
    console.log('Applying filter:', filter);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_11() {
  const socket = new WebSocket('ws://example.com/events');
  
  socket.onmessage = function(event) {
    const events = JSON.parse(event.data);
    
    // ruleid: javascript-loop-injection
    let key;
    for (key in events) {
      // No type checking or size validation
      processEvent(key, events[key]);
    }
  };
  
  function processEvent(key, event) {
    console.log(`Event ${key}:`, event);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12() {
  const formData = new FormData(document.getElementById('userForm'));
  const userData = {};
  
  for (const [key, value] of formData.entries()) {
    userData[key] = value;
  }
  
  // ruleid: javascript-loop-injection
  Object.keys(userData).forEach(key => {
    // User can control form fields count
    validateField(key, userData[key]);
  });
  
  function validateField(key, value) {
    // Potentially expensive validation
    console.log(`Validating ${key} with value ${value}`);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13() {
  const req = new XMLHttpRequest();
  req.open('GET', '/api/tree', false);
  req.send(null);
  
  if (req.status === 200) {
    const tree = JSON.parse(req.responseText);
    
    // ruleid: javascript-loop-injection
    function traverseTree(node) {
      // Recursive function with no depth limit
      processNode(node);
      
      if (node.children) {
        node.children.forEach(child => traverseTree(child));
      }
    }
    
    traverseTree(tree);
  }
  
  function processNode(node) {
    console.log('Processing node:', node.id);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14() {
  const searchParams = new URLSearchParams(window.location.search);
  const operations = searchParams.get('ops') ? JSON.parse(searchParams.get('ops')) : [];
  
  // ruleid: javascript-loop-injection
  for (let i = 0; i < operations.length; i++) {
    // No limit on operations array
    executeOperation(operations[i]);
  }
  
  function executeOperation(op) {
    console.log('Executing operation:', op);
    // Potentially expensive operation
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15() {
  const req = new XMLHttpRequest();
  req.open('GET', '/api/matrix', false);
  req.send(null);
  
  if (req.status === 200) {
    const matrix = JSON.parse(req.responseText);
    
    // ruleid: javascript-loop-injection
    for (let i = 0; i < matrix.length; i++) {
      for (let j = 0; j < matrix[i].length; j++) {
        // Nested loops with no size validation
        processCell(i, j, matrix[i][j]);
      }
    }
  }
  
  function processCell(row, col, value) {
    console.log(`Cell [${row},${col}] = ${value}`);
  }
}
// {/fact}

// True Negative Cases (Secure)

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1() {
  const req = new XMLHttpRequest();
  req.open('GET', '/api/data', false);
  req.send(null);
  
  if (req.status === 200) {
    const data = JSON.parse(req.responseText);
    
    // Verify data type before iteration
    // ok: javascript-loop-injection
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const keys = Object.keys(data).slice(0, 1000); // Limit to 1000 keys
      for (const key of keys) {
        console.log(key, data[key]);
      }
    }
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_2() {
  fetch('/api/userdata')
    .then(response => response.json())
    .then(userData => {
      // ok: javascript-loop-injection
      if (userData && typeof userData === 'object') {
        const keys = Object.keys(userData);
        const safeKeys = keys.slice(0, Math.min(keys.length, 500)); // Limit to 500 keys
        
        safeKeys.forEach(key => {
          processUserData(key, userData[key]);
        });
      }
    });
  
  function processUserData(key, value) {
    console.log(`Processing ${key}: ${value}`);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3() {
  const http = require('http');
  
  http.get('http://example.com/api/items', (res) => {
    let data = '';
    
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      try {
        const items = JSON.parse(data);
        
        // ok: javascript-loop-injection
        if (Array.isArray(items)) {
          const MAX_ITEMS = 100;
          const safeItems = items.slice(0, MAX_ITEMS);
          
          for (let i = 0; i < safeItems.length; i++) {
            heavyOperation(safeItems[i]);
          }
        }
      } catch (error) {
        console.error('Failed to parse response:', error);
      }
    });
  });
  
  function heavyOperation(item) {
    console.log(item);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4() {
  const express = require('express');
  const app = express();
  
  app.get('/process', (req, res) => {
    try {
      const userInput = req.query.data ? JSON.parse(req.query.data) : {};
      
      // ok: javascript-loop-injection
      if (typeof userInput === 'object' && userInput !== null) {
        const entries = Object.entries(userInput);
        const MAX_ENTRIES = 50;
        
        entries.slice(0, MAX_ENTRIES).forEach(([key, value]) => {
          processEntry(key, value);
        });
      }
      
      res.send('Processing complete');
    } catch (error) {
      res.status(400).send('Invalid input');
    }
  });
  
  function processEntry(key, value) {
    return key + value;
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5() {
  const axios = require('axios');
  
  axios.get('/api/config')
    .then(response => {
      const config = response.data;
      
      // ok: javascript-loop-injection
      let count = 0;
      const MAX_ITERATIONS = 200;
      
      while (config.hasNext() && count < MAX_ITERATIONS) {
        const item = config.next();
        processConfigItem(item);
        count++;
      }
    });
  
  function processConfigItem(item) {
    console.log('Processing:', item);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6() {
  const userInput = document.getElementById('userJson').value;
  
  try {
    const data = JSON.parse(userInput);
    
    // ok: javascript-loop-injection
    if (typeof data === 'object' && data !== null) {
      const props = Object.keys(data).slice(0, 100); // Limit to 100 properties
      
      for (const prop of props) {
        document.write(`<div>${prop}: ${data[prop]}</div>`);
      }
    }
  } catch (error) {
    console.error('Invalid JSON input');
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7() {
  const socket = new WebSocket('ws://example.com/socket');
  
  socket.onmessage = function(event) {
    try {
      const message = JSON.parse(event.data);
      
      // ok: javascript-loop-injection
      if (Array.isArray(message.items)) {
        const MAX_ITEMS = 50;
        const safeItems = message.items.slice(0, MAX_ITEMS);
        
        safeItems.map(item => {
          processItem(item);
        });
      }
    } catch (error) {
      console.error('Invalid message format');
    }
  };
  
  function processItem(item) {
    console.log(item);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8() {
  const req = new XMLHttpRequest();
  req.open('GET', '/api/records', false);
  req.send(null);
  
  if (req.status === 200) {
    try {
      const records = JSON.parse(req.responseText);
      
      // ok: javascript-loop-injection
      if (Array.isArray(records)) {
        const MAX_RECORDS = 200;
        let i = 0;
        
        while (i < records.length && i < MAX_RECORDS) {
          processRecord(records[i]);
          i++;
        }
      }
    } catch (error) {
      console.error('Failed to parse records');
    }
  }
  
  function processRecord(record) {
    console.log(record);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9() {
  fetch('/api/comments')
    .then(response => response.json())
    .then(comments => {
      // ok: javascript-loop-injection
      if (Array.isArray(comments)) {
        const MAX_COMMENTS = 100;
        const safeComments = comments.slice(0, MAX_COMMENTS);
        
        safeComments.forEach((comment, index) => {
          renderComment(comment, index);
        });
      }
    })
    .catch(error => {
      console.error('Failed to fetch comments:', error);
    });
  
  function renderComment(comment, index) {
    const div = document.createElement('div');
    div.textContent = `${index}: ${comment.text}`;
    document.body.appendChild(div);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10() {
  const queryString = window.location.search;
  const urlParams = new URLSearchParams(queryString);
  
  try {
    const filters = JSON.parse(urlParams.get('filters') || '{}');
    
    // ok: javascript-loop-injection
    if (typeof filters === 'object' && filters !== null) {
      const values = Object.values(filters);
      const MAX_FILTERS = 20;
      
      for (let i = 0; i < Math.min(values.length, MAX_FILTERS); i++) {
        applyFilter(values[i]);
      }
    }
  } catch (error) {
    console.error('Invalid filters format');
  }
  
  function applyFilter(filter) {
    console.log('Applying filter:', filter);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11() {
  const socket = new WebSocket('ws://example.com/events');
  
  socket.onmessage = function(event) {
    try {
      const events = JSON.parse(event.data);
      
      // ok: javascript-loop-injection
      if (typeof events === 'object' && events !== null) {
        const keys = Object.keys(events).slice(0, 50); // Limit to 50 events
        
        for (const key of keys) {
          processEvent(key, events[key]);
        }
      }
    } catch (error) {
      console.error('Invalid event data');
    }
  };
  
  function processEvent(key, event) {
    console.log(`Event ${key}:`, event);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12() {
  const formData = new FormData(document.getElementById('userForm'));
  const userData = {};
  
  for (const [key, value] of formData.entries()) {
    userData[key] = value;
  }
  
  // ok: javascript-loop-injection
  const MAX_FIELDS = 30;
  const keys = Object.keys(userData).slice(0, MAX_FIELDS);
  
  keys.forEach(key => {
    validateField(key, userData[key]);
  });
  
  function validateField(key, value) {
    console.log(`Validating ${key} with value ${value}`);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13() {
  const req = new XMLHttpRequest();
  req.open('GET', '/api/tree', false);
  req.send(null);
  
  if (req.status === 200) {
    try {
      const tree = JSON.parse(req.responseText);
      
      // ok: javascript-loop-injection
      function traverseTree(node, depth = 0) {
        // Limit recursion depth
        const MAX_DEPTH = 10;
        
        if (depth >= MAX_DEPTH) {
          return;
        }
        
        processNode(node);
        
        if (node.children && Array.isArray(node.children)) {
          const safeChildren = node.children.slice(0, 20); // Limit children per node
          safeChildren.forEach(child => traverseTree(child, depth + 1));
        }
      }
      
      traverseTree(tree);
    } catch (error) {
      console.error('Invalid tree data');
    }
  }
  
  function processNode(node) {
    console.log('Processing node:', node.id);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14() {
  const searchParams = new URLSearchParams(window.location.search);
  
  try {
    const operations = searchParams.get('ops') ? JSON.parse(searchParams.get('ops')) : [];
    
    // ok: javascript-loop-injection
    if (Array.isArray(operations)) {
      const MAX_OPS = 50;
      
      for (let i = 0; i < Math.min(operations.length, MAX_OPS); i++) {
        executeOperation(operations[i]);
      }
    }
  } catch (error) {
    console.error('Invalid operations format');
  }
  
  function executeOperation(op) {
    console.log('Executing operation:', op);
  }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15() {
  const req = new XMLHttpRequest();
  req.open('GET', '/api/matrix', false);
  req.send(null);
  
  if (req.status === 200) {
    try {
      const matrix = JSON.parse(req.responseText);
      
      // ok: javascript-loop-injection
      if (Array.isArray(matrix)) {
        const MAX_ROWS = 50;
        const MAX_COLS = 50;
        
        for (let i = 0; i < Math.min(matrix.length, MAX_ROWS); i++) {
          if (Array.isArray(matrix[i])) {
            for (let j = 0; j < Math.min(matrix[i].length, MAX_COLS); j++) {
              processCell(i, j, matrix[i][j]);
            }
          }
        }
      }
    } catch (error) {
      console.error('Invalid matrix data');
    }
  }
  
  function processCell(row, col, value) {
    console.log(`Cell [${row},${col}] = ${value}`);
  }
}
// {/fact}