import * as http from 'http';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as express from 'express';
import * as url from 'url';
import * as zlib from 'zlib';
import * as child_process from 'child_process';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const size = parseInt(parsedUrl.query.size as string);
    
    // ruleid: typescript-resource-exhaustion
    const buffer = Buffer.alloc(size); // Unbounded allocation based on user input
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ allocated: size }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_2() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const iterations = parseInt(parsedUrl.query.iterations as string);
    
    const result = [];
    // ruleid: typescript-resource-exhaustion
    for (let i = 0; i < iterations; i++) {
      result.push(crypto.randomBytes(1000).toString('hex'));
    }
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/download', (req, res) => {
    const fileName = req.query.file as string;
    
    // ruleid: typescript-resource-exhaustion
    const fileContent = fs.readFileSync(fileName); // Reads entire file into memory
    
    res.send(fileContent);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4() {
  const server = http.createServer((req, res) => {
    let body = '';
    
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      const arraySize = data.size;
      
      // ruleid: typescript-resource-exhaustion
      const hugeArray = new Array(arraySize).fill('x');
      
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`Created array of size ${hugeArray.length}`);
    });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/compress', (req, res) => {
    const level = parseInt(req.query.level as string);
    const input = req.body.data;
    
    // ruleid: typescript-resource-exhaustion
    zlib.deflate(input, { level }, (err, compressed) => {
      if (err) {
        res.status(500).send('Compression failed');
        return;
      }
      res.send(compressed);
    });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const depth = parseInt(parsedUrl.query.depth as string);
    
    function recursiveFunction(n: number): number {
      if (n <= 0) return 1;
      return recursiveFunction(n - 1) + recursiveFunction(n - 1);
    }
    
    // ruleid: typescript-resource-exhaustion
    const result = recursiveFunction(depth); // Exponential complexity based on user input
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ result }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/regex', (req, res) => {
    const pattern = req.query.pattern as string;
    const text = req.query.text as string;
    
    // ruleid: typescript-resource-exhaustion
    const regex = new RegExp(pattern);
    const matches = text.match(regex);
    
    res.json({ matches });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const count = parseInt(parsedUrl.query.count as string);
    
    // ruleid: typescript-resource-exhaustion
    const promises = Array(count).fill(0).map(() => {
      return new Promise(resolve => {
        setTimeout(() => resolve(Math.random()), 1000);
      });
    });
    
    Promise.all(promises).then(results => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ results }));
    });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/sort', (req, res) => {
    const size = parseInt(req.query.size as string);
    
    // ruleid: typescript-resource-exhaustion
    const array = Array(size).fill(0).map(() => Math.random());
    array.sort(); // O(n log n) operation on user-controlled size
    
    res.json({ sorted: array });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10() {
  const server = http.createServer((req, res) => {
    let body = '';
    
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      
      // ruleid: typescript-resource-exhaustion
      const worker = child_process.spawn('node', ['-e', `
        const result = [];
        for (let i = 0; i < ${data.iterations}; i++) {
          result.push(Math.random());
        }
        console.log(JSON.stringify(result));
      `]);
      
      let output = '';
      worker.stdout.on('data', (chunk) => {
        output += chunk.toString();
      });
      
      worker.on('close', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(output);
      });
    });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/matrix', (req, res) => {
    const n = parseInt(req.query.size as string);
    
    // ruleid: typescript-resource-exhaustion
    const matrix = Array(n).fill(0).map(() => Array(n).fill(0));
    
    // Matrix multiplication (O(n³) operation)
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        for (let k = 0; k < n; k++) {
          matrix[i][j] += i * j * k;
        }
      }
    }
    
    res.json({ result: 'Matrix calculation complete' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const jsonData = parsedUrl.query.data as string;
    
    try {
      // ruleid: typescript-resource-exhaustion
      const data = JSON.parse(jsonData); // Can cause DoS with deeply nested JSON
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ parsed: true }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/map', (req, res) => {
    const size = parseInt(req.query.size as string);
    
    // ruleid: typescript-resource-exhaustion
    const map = new Map();
    for (let i = 0; i < size; i++) {
      map.set(`key${i}`, `value${i}`);
    }
    
    res.json({ mapSize: map.size });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const text = parsedUrl.query.text as string;
    
    // ruleid: typescript-resource-exhaustion
    const permutations: string[] = [];
    function generatePermutations(str: string, result: string = '') {
      if (str.length === 0) {
        permutations.push(result);
      } else {
        for (let i = 0; i < str.length; i++) {
          const rest = str.slice(0, i) + str.slice(i + 1);
          generatePermutations(rest, result + str[i]);
        }
      }
    }
    
    generatePermutations(text); // Factorial complexity!
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ count: permutations.length }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/threads', (req, res) => {
    const count = parseInt(req.query.count as string);
    
    // ruleid: typescript-resource-exhaustion
    for (let i = 0; i < count; i++) {
      child_process.spawn('node', ['-e', 'while(true) { console.log("Worker running"); }']);
    }
    
    res.send(`Started ${count} worker threads`);
  });
  
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    let size = parseInt(parsedUrl.query.size as string);
    
    // ok: typescript-resource-exhaustion
    const MAX_SIZE = 1024 * 1024; // 1MB limit
    size = Math.min(size, MAX_SIZE);
    
    const buffer = Buffer.alloc(size);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ allocated: size }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_2() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    let iterations = parseInt(parsedUrl.query.iterations as string);
    
    // ok: typescript-resource-exhaustion
    const MAX_ITERATIONS = 100;
    iterations = isNaN(iterations) ? 10 : Math.min(iterations, MAX_ITERATIONS);
    
    const result = [];
    for (let i = 0; i < iterations; i++) {
      result.push(crypto.randomBytes(100).toString('hex'));
    }
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/download', (req, res) => {
    const fileName = req.query.file as string;
    
    // ok: typescript-resource-exhaustion
    const readStream = fs.createReadStream(fileName); // Stream instead of loading entire file
    
    readStream.pipe(res);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4() {
  const server = http.createServer((req, res) => {
    let body = '';
    
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      let arraySize = data.size;
      
      // ok: typescript-resource-exhaustion
      const MAX_SIZE = 10000;
      arraySize = Math.min(arraySize, MAX_SIZE);
      
      const safeArray = new Array(arraySize).fill('x');
      
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`Created array of size ${safeArray.length}`);
    });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/compress', (req, res) => {
    let level = parseInt(req.query.level as string);
    const input = req.body.data;
    
    // ok: typescript-resource-exhaustion
    // Validate compression level
    if (isNaN(level) || level < 0 || level > 9) {
      level = 6; // Default compression level
    }
    
    zlib.deflate(input, { level }, (err, compressed) => {
      if (err) {
        res.status(500).send('Compression failed');
        return;
      }
      res.send(compressed);
    });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    let depth = parseInt(parsedUrl.query.depth as string);
    
    // ok: typescript-resource-exhaustion
    const MAX_DEPTH = 10;
    depth = Math.min(depth, MAX_DEPTH);
    
    // Use memoization to avoid exponential complexity
    const memo: Record<number, number> = {};
    function fibonacci(n: number): number {
      if (n <= 1) return n;
      if (memo[n]) return memo[n];
      memo[n] = fibonacci(n - 1) + fibonacci(n - 2);
      return memo[n];
    }
    
    const result = fibonacci(depth);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ result }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/regex', (req, res) => {
    const pattern = req.query.pattern as string;
    const text = req.query.text as string;
    
    // ok: typescript-resource-exhaustion
    // Validate pattern length and complexity
    if (!pattern || pattern.length > 100 || pattern.includes('(.*)*')) {
      return res.status(400).json({ error: 'Invalid or unsafe regex pattern' });
    }
    
    try {
      const regex = new RegExp(pattern);
      const matches = text.match(regex);
      res.json({ matches });
    } catch (e) {
      res.status(400).json({ error: 'Invalid regex pattern' });
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    let count = parseInt(parsedUrl.query.count as string);
    
    // ok: typescript-resource-exhaustion
    const MAX_PROMISES = 50;
    count = Math.min(count, MAX_PROMISES);
    
    const promises = Array(count).fill(0).map(() => {
      return new Promise(resolve => {
        setTimeout(() => resolve(Math.random()), 100);
      });
    });
    
    Promise.all(promises).then(results => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ results }));
    });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/sort', (req, res) => {
    let size = parseInt(req.query.size as string);
    
    // ok: typescript-resource-exhaustion
    const MAX_SIZE = 10000;
    size = isNaN(size) ? 100 : Math.min(size, MAX_SIZE);
    
    const array = Array(size).fill(0).map(() => Math.random());
    array.sort();
    
    res.json({ sortedCount: array.length });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10() {
  const server = http.createServer((req, res) => {
    let body = '';
    
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      let iterations = data.iterations;
      
      // ok: typescript-resource-exhaustion
      const MAX_ITERATIONS = 1000;
      iterations = Math.min(iterations, MAX_ITERATIONS);
      
      const worker = child_process.spawn('node', ['-e', `
        const result = [];
        for (let i = 0; i < ${iterations}; i++) {
          result.push(Math.random());
        }
        console.log(JSON.stringify(result));
      `]);
      
      let output = '';
      worker.stdout.on('data', (chunk) => {
        output += chunk.toString();
      });
      
      worker.on('close', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(output);
      });
    });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/matrix', (req, res) => {
    let n = parseInt(req.query.size as string);
    
    // ok: typescript-resource-exhaustion
    const MAX_SIZE = 100;
    n = isNaN(n) ? 10 : Math.min(n, MAX_SIZE);
    
    const matrix = Array(n).fill(0).map(() => Array(n).fill(0));
    
    // Matrix operation with bounded size
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        matrix[i][j] = i * j;
      }
    }
    
    res.json({ result: 'Matrix calculation complete', size: n });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const jsonData = parsedUrl.query.data as string;
    
    // ok: typescript-resource-exhaustion
    // Limit JSON size
    if (jsonData && jsonData.length > 10000) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'JSON data too large' }));
      return;
    }
    
    try {
      const data = JSON.parse(jsonData);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ parsed: true }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/map', (req, res) => {
    let size = parseInt(req.query.size as string);
    
    // ok: typescript-resource-exhaustion
    const MAX_SIZE = 10000;
    size = isNaN(size) ? 100 : Math.min(size, MAX_SIZE);
    
    const map = new Map();
    for (let i = 0; i < size; i++) {
      map.set(`key${i}`, `value${i}`);
    }
    
    res.json({ mapSize: map.size });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const text = parsedUrl.query.text as string;
    
    // ok: typescript-resource-exhaustion
    // Limit input length to avoid factorial explosion
    if (!text || text.length > 8) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Text too long for permutation calculation' }));
      return;
    }
    
    const permutations: string[] = [];
    function generatePermutations(str: string, result: string = '') {
      if (str.length === 0) {
        permutations.push(result);
      } else {
        for (let i = 0; i < str.length; i++) {
          const rest = str.slice(0, i) + str.slice(i + 1);
          generatePermutations(rest, result + str[i]);
        }
      }
    }
    
    generatePermutations(text);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ count: permutations.length }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/threads', (req, res) => {
    let count = parseInt(req.query.count as string);
    
    // ok: typescript-resource-exhaustion
    const MAX_THREADS = 4;
    count = isNaN(count) ? 1 : Math.min(count, MAX_THREADS);
    
    const workers = [];
    for (let i = 0; i < count; i++) {
      const worker = child_process.spawn('node', ['-e', `
        setTimeout(() => {
          console.log("Worker ${i} completed");
          process.exit(0);
        }, 1000);
      `]);
      workers.push(worker);
    }
    
    res.send(`Started ${count} worker threads with limits`);
  });
  
  app.listen(3000);
}
// {/fact}