// JavaScript Resource Exhaustion Test Cases
// Rule ID: javascript-resource-exhaustion
// CWE: 400, 664

const express = require('express');
const app = express();
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const zlib = require('zlib');
const child_process = require('child_process');
const { Worker } = require('worker_threads');
const { setTimeout } = require('timers/promises');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1() {
  app.get('/create-array', (req, res) => {
    const size = parseInt(req.query.size);
    // ruleid: javascript-resource-exhaustion
    const array = new Array(size);
    for (let i = 0; i < size; i++) {
      array[i] = i;
    }
    res.json({ length: array.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_2() {
  app.post('/allocate-buffer', (req, res) => {
    const bufferSize = parseInt(req.body.size);
    // ruleid: javascript-resource-exhaustion
    const buffer = Buffer.alloc(bufferSize);
    res.json({ allocated: buffer.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_3() {
  app.get('/create-regex', (req, res) => {
    const pattern = req.query.pattern;
    // ruleid: javascript-resource-exhaustion
    const regex = new RegExp(pattern);
    const testString = 'test string to match against';
    const result = regex.test(testString);
    res.json({ matches: result });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4() {
  app.post('/read-file', (req, res) => {
    const chunkSize = parseInt(req.body.chunkSize);
    // ruleid: javascript-resource-exhaustion
    const readStream = fs.createReadStream('large-file.txt', { 
      highWaterMark: chunkSize 
    });
    
    let data = '';
    readStream.on('data', (chunk) => {
      data += chunk;
    });
    
    readStream.on('end', () => {
      res.send({ success: true });
    });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5() {
  app.get('/hash-data', (req, res) => {
    const iterations = parseInt(req.query.iterations);
    const data = 'some data to hash';
    
    // ruleid: javascript-resource-exhaustion
    crypto.pbkdf2('password', 'salt', iterations, 64, 'sha512', (err, derivedKey) => {
      if (err) throw err;
      res.send({ result: derivedKey.toString('hex') });
    });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6() {
  app.post('/spawn-processes', (req, res) => {
    const count = parseInt(req.body.count);
    const processes = [];
    
    // ruleid: javascript-resource-exhaustion
    for (let i = 0; i < count; i++) {
      processes.push(child_process.spawn('echo', ['process ' + i]));
    }
    
    res.json({ spawned: processes.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7() {
  app.get('/create-workers', (req, res) => {
    const workerCount = parseInt(req.query.workers);
    const workers = [];
    
    // ruleid: javascript-resource-exhaustion
    for (let i = 0; i < workerCount; i++) {
      workers.push(new Worker('./worker.js'));
    }
    
    res.json({ created: workers.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8() {
  app.post('/compress-data', (req, res) => {
    const level = parseInt(req.body.level);
    const data = Buffer.from('A'.repeat(1000000));
    
    // ruleid: javascript-resource-exhaustion
    zlib.deflate(data, { level }, (err, compressed) => {
      if (err) throw err;
      res.json({ compressedSize: compressed.length });
    });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_9() {
  app.get('/string-repeat', (req, res) => {
    const count = parseInt(req.query.count);
    const char = req.query.char || 'A';
    
    // ruleid: javascript-resource-exhaustion
    const result = char.repeat(count);
    res.send({ length: result.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10() {
  app.post('/timeout', (req, res) => {
    const delay = parseInt(req.body.delay);
    
    // ruleid: javascript-resource-exhaustion
    setTimeout(delay).then(() => {
      res.json({ success: true });
    });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_11() {
  app.get('/http-request', (req, res) => {
    const timeout = parseInt(req.query.timeout);
    
    // ruleid: javascript-resource-exhaustion
    const request = http.request({
      hostname: 'example.com',
      timeout: timeout
    }, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.json({ success: true });
      });
    });
    
    request.end();
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12() {
  app.post('/json-parse', (req, res) => {
    const depth = parseInt(req.body.depth);
    const jsonString = req.body.json;
    
    try {
      // ruleid: javascript-resource-exhaustion
      const parsed = JSON.parse(jsonString, null, { depth });
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13() {
  app.get('/string-split', (req, res) => {
    const limit = parseInt(req.query.limit);
    const text = req.query.text || '';
    const delimiter = req.query.delimiter || ',';
    
    // ruleid: javascript-resource-exhaustion
    const parts = text.split(delimiter, limit);
    res.json({ parts });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14() {
  app.post('/map-creation', (req, res) => {
    const size = parseInt(req.body.size);
    
    // ruleid: javascript-resource-exhaustion
    const map = new Map();
    for (let i = 0; i < size; i++) {
      map.set(`key${i}`, `value${i}`);
    }
    
    res.json({ mapSize: map.size });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15() {
  app.get('/recursive-function', (req, res) => {
    const depth = parseInt(req.query.depth);
    
    function recursiveFunction(n) {
      if (n <= 0) return 0;
      return n + recursiveFunction(n - 1);
    }
    
    // ruleid: javascript-resource-exhaustion
    const result = recursiveFunction(depth);
    res.json({ result });
  });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1() {
  app.get('/create-array-safe', (req, res) => {
    let size = parseInt(req.query.size);
    // ok: javascript-resource-exhaustion
    if (size > 1000 || size < 0) {
      size = 1000; // Limit to a reasonable size
    }
    const array = new Array(size);
    for (let i = 0; i < size; i++) {
      array[i] = i;
    }
    res.json({ length: array.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_2() {
  app.post('/allocate-buffer-safe', (req, res) => {
    let bufferSize = parseInt(req.body.size);
    // ok: javascript-resource-exhaustion
    const maxSize = 1024 * 1024; // 1MB max
    if (isNaN(bufferSize) || bufferSize <= 0 || bufferSize > maxSize) {
      bufferSize = maxSize;
    }
    const buffer = Buffer.alloc(bufferSize);
    res.json({ allocated: buffer.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3() {
  app.get('/create-regex-safe', (req, res) => {
    const pattern = req.query.pattern;
    
    // ok: javascript-resource-exhaustion
    if (pattern && pattern.length > 100) {
      return res.status(400).json({ error: 'Pattern too complex' });
    }
    
    try {
      const regex = new RegExp(pattern);
      const testString = 'test string to match against';
      const result = regex.test(testString);
      res.json({ matches: result });
    } catch (e) {
      res.status(400).json({ error: 'Invalid regex pattern' });
    }
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4() {
  app.post('/read-file-safe', (req, res) => {
    let chunkSize = parseInt(req.body.chunkSize);
    
    // ok: javascript-resource-exhaustion
    const minChunkSize = 1024;     // 1KB min
    const maxChunkSize = 1024 * 64; // 64KB max
    
    if (isNaN(chunkSize) || chunkSize < minChunkSize || chunkSize > maxChunkSize) {
      chunkSize = minChunkSize;
    }
    
    const readStream = fs.createReadStream('large-file.txt', { 
      highWaterMark: chunkSize 
    });
    
    let data = '';
    readStream.on('data', (chunk) => {
      data += chunk;
    });
    
    readStream.on('end', () => {
      res.send({ success: true });
    });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5() {
  app.get('/hash-data-safe', (req, res) => {
    let iterations = parseInt(req.query.iterations);
    const data = 'some data to hash';
    
    // ok: javascript-resource-exhaustion
    const maxIterations = 10000;
    const minIterations = 1000;
    
    if (isNaN(iterations) || iterations < minIterations || iterations > maxIterations) {
      iterations = minIterations;
    }
    
    crypto.pbkdf2('password', 'salt', iterations, 64, 'sha512', (err, derivedKey) => {
      if (err) throw err;
      res.send({ result: derivedKey.toString('hex') });
    });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6() {
  app.post('/spawn-processes-safe', (req, res) => {
    let count = parseInt(req.body.count);
    
    // ok: javascript-resource-exhaustion
    const maxProcesses = 5;
    if (isNaN(count) || count <= 0 || count > maxProcesses) {
      count = maxProcesses;
    }
    
    const processes = [];
    for (let i = 0; i < count; i++) {
      processes.push(child_process.spawn('echo', ['process ' + i]));
    }
    
    res.json({ spawned: processes.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7() {
  app.get('/create-workers-safe', (req, res) => {
    let workerCount = parseInt(req.query.workers);
    
    // ok: javascript-resource-exhaustion
    const maxWorkers = Math.max(1, require('os').cpus().length - 1); // Leave one CPU free
    if (isNaN(workerCount) || workerCount <= 0 || workerCount > maxWorkers) {
      workerCount = maxWorkers;
    }
    
    const workers = [];
    for (let i = 0; i < workerCount; i++) {
      workers.push(new Worker('./worker.js'));
    }
    
    res.json({ created: workers.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8() {
  app.post('/compress-data-safe', (req, res) => {
    let level = parseInt(req.body.level);
    const data = Buffer.from('A'.repeat(1000000));
    
    // ok: javascript-resource-exhaustion
    if (isNaN(level) || level < 1 || level > 9) {
      level = 6; // Default zlib compression level
    }
    
    zlib.deflate(data, { level }, (err, compressed) => {
      if (err) throw err;
      res.json({ compressedSize: compressed.length });
    });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9() {
  app.get('/string-repeat-safe', (req, res) => {
    let count = parseInt(req.query.count);
    const char = req.query.char || 'A';
    
    // ok: javascript-resource-exhaustion
    const maxRepeat = 100000;
    if (isNaN(count) || count < 0 || count > maxRepeat) {
      count = maxRepeat;
    }
    
    const result = char.repeat(count);
    res.send({ length: result.length });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10() {
  app.post('/timeout-safe', (req, res) => {
    let delay = parseInt(req.body.delay);
    
    // ok: javascript-resource-exhaustion
    const maxDelay = 30000; // 30 seconds max
    if (isNaN(delay) || delay <= 0 || delay > maxDelay) {
      delay = maxDelay;
    }
    
    setTimeout(delay).then(() => {
      res.json({ success: true });
    });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11() {
  app.get('/http-request-safe', (req, res) => {
    let timeout = parseInt(req.query.timeout);
    
    // ok: javascript-resource-exhaustion
    const maxTimeout = 10000; // 10 seconds max
    if (isNaN(timeout) || timeout <= 0 || timeout > maxTimeout) {
      timeout = 5000; // Default to 5 seconds
    }
    
    const request = http.request({
      hostname: 'example.com',
      timeout: timeout
    }, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.json({ success: true });
      });
    });
    
    request.end();
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12() {
  app.post('/json-parse-safe', (req, res) => {
    let depth = parseInt(req.body.depth);
    const jsonString = req.body.json;
    
    // ok: javascript-resource-exhaustion
    const maxDepth = 100;
    if (isNaN(depth) || depth <= 0 || depth > maxDepth) {
      depth = maxDepth;
    }
    
    try {
      const parsed = JSON.parse(jsonString, null, { depth });
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13() {
  app.get('/string-split-safe', (req, res) => {
    let limit = parseInt(req.query.limit);
    const text = req.query.text || '';
    const delimiter = req.query.delimiter || ',';
    
    // ok: javascript-resource-exhaustion
    const maxLimit = 1000;
    if (isNaN(limit) || limit < 0 || limit > maxLimit) {
      limit = maxLimit;
    }
    
    const parts = text.split(delimiter, limit);
    res.json({ parts });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14() {
  app.post('/map-creation-safe', (req, res) => {
    let size = parseInt(req.body.size);
    
    // ok: javascript-resource-exhaustion
    const maxSize = 10000;
    if (isNaN(size) || size < 0 || size > maxSize) {
      size = maxSize;
    }
    
    const map = new Map();
    for (let i = 0; i < size; i++) {
      map.set(`key${i}`, `value${i}`);
    }
    
    res.json({ mapSize: map.size });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15() {
  app.get('/recursive-function-safe', (req, res) => {
    let depth = parseInt(req.query.depth);
    
    // ok: javascript-resource-exhaustion
    const maxDepth = 1000;
    if (isNaN(depth) || depth < 0 || depth > maxDepth) {
      depth = maxDepth;
    }
    
    // Use iteration instead of recursion to avoid stack overflow
    let result = 0;
    for (let i = 1; i <= depth; i++) {
      result += i;
    }
    
    res.json({ result });
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});