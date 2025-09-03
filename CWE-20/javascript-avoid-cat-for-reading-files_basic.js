// Filename: cat_vulnerability_examples.js
const { exec, execSync } = require('child_process');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable code examples)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1() {
  const http = require('http');
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/read-file')) {
      const filename = req.url.split('=')[1];
      // ruleid: javascript-avoid-cat-for-reading-files
      exec(`cat ${filename}`, (error, stdout, stderr) => {
        if (error) {
          res.writeHead(500);
          res.end('Error reading file');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(stdout);
      });
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2() {
  app.get('/view-log', (req, res) => {
    const logFile = req.query.file || 'app.log';
    // ruleid: javascript-avoid-cat-for-reading-files
    exec(`cat ${logFile}`, (error, stdout) => {
      if (error) {
        return res.status(500).send('Error reading log file');
      }
      res.send(`<pre>${stdout}</pre>`);
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3() {
  app.post('/read-config', (req, res) => {
    const configFile = req.body.configPath;
    try {
      // ruleid: javascript-avoid-cat-for-reading-files
      const fileContent = execSync(`cat ${configFile}`).toString();
      res.json({ content: fileContent });
    } catch (error) {
      res.status(500).json({ error: 'Failed to read config file' });
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        const data = JSON.parse(body);
        // ruleid: javascript-avoid-cat-for-reading-files
        exec(`cat ${data.filename}`, (err, stdout) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ content: stdout }));
        });
      });
    }
  });
  server.listen(8080);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5() {
  app.get('/user-file', (req, res) => {
    const userId = req.query.id;
    const fileName = req.query.name;
    // ruleid: javascript-avoid-cat-for-reading-files
    const fileData = execSync(`cat ./users/${userId}/${fileName}`);
    res.send(fileData);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6() {
  const server = http.createServer((req, res) => {
    const urlParts = new URL(req.url, `http://${req.headers.host}`);
    const filePath = urlParts.searchParams.get('path');
    if (filePath) {
      // ruleid: javascript-avoid-cat-for-reading-files
      const child = spawn('cat', [filePath]);
      child.stdout.pipe(res);
      child.stderr.on('data', (data) => {
        console.error(`Error: ${data}`);
      });
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7() {
  app.get('/api/documents/:id', (req, res) => {
    const docId = req.params.id;
    const format = req.query.format || 'txt';
    // ruleid: javascript-avoid-cat-for-reading-files
    exec(`cat ./documents/${docId}.${format}`, (error, stdout) => {
      if (error) {
        return res.status(404).send('Document not found');
      }
      res.send(stdout);
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8() {
  app.post('/process-file', (req, res) => {
    const filePath = req.body.path;
    if (!filePath) {
      return res.status(400).send('File path is required');
    }
    
    try {
      // ruleid: javascript-avoid-cat-for-reading-files
      const output = execSync(`cat ${filePath} | grep "ERROR"`).toString();
      res.json({ errors: output.split('\n').filter(Boolean) });
    } catch (error) {
      res.status(500).send('Error processing file');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9() {
  const server = http.createServer((req, res) => {
    if (req.headers['x-file-path']) {
      const filePath = req.headers['x-file-path'];
      // ruleid: javascript-avoid-cat-for-reading-files
      exec(`cat ${filePath}`, (error, stdout) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(stdout);
      });
    } else {
      res.writeHead(400);
      res.end('Missing file path header');
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10() {
  app.get('/download', (req, res) => {
    const file = req.query.file;
    // ruleid: javascript-avoid-cat-for-reading-files
    exec(`cat ${file}`, (error, stdout) => {
      if (error) {
        return res.status(500).send('Error reading file');
      }
      res.setHeader('Content-Disposition', `attachment; filename="${file}"`);
      res.send(stdout);
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split('=');
      acc[key] = value;
      return acc;
    }, {});
    
    if (cookies && cookies.filePath) {
      // ruleid: javascript-avoid-cat-for-reading-files
      exec(`cat ${cookies.filePath}`, (error, stdout) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(stdout);
      });
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12() {
  app.get('/read-multiple', (req, res) => {
    const files = req.query.files.split(',');
    let output = '';
    
    for (const file of files) {
      try {
        // ruleid: javascript-avoid-cat-for-reading-files
        const content = execSync(`cat ${file}`).toString();
        output += `--- ${file} ---\n${content}\n\n`;
      } catch (error) {
        output += `Error reading ${file}\n`;
      }
    }
    
    res.send(output);
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13() {
  app.post('/append-log', (req, res) => {
    const { logFile, message } = req.body;
    
    try {
      // First read the existing log
      // ruleid: javascript-avoid-cat-for-reading-files
      const existingLog = execSync(`cat ${logFile}`).toString();
      
      // Then append the new message
      fs.writeFileSync(logFile, existingLog + '\n' + message);
      res.send('Log updated');
    } catch (error) {
      res.status(500).send('Error updating log');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14() {
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/tail-log')) {
      const query = new URLSearchParams(req.url.split('?')[1]);
      const lines = query.get('lines') || '10';
      const file = query.get('file');
      
      if (file) {
        // ruleid: javascript-avoid-cat-for-reading-files
        exec(`cat ${file} | tail -n ${lines}`, (error, stdout) => {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(stdout);
        });
      }
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15() {
  app.get('/search-file', (req, res) => {
    const { file, term } = req.query;
    
    if (!file || !term) {
      return res.status(400).send('Missing required parameters');
    }
    
    try {
      // ruleid: javascript-avoid-cat-for-reading-files
      const result = execSync(`cat ${file} | grep -i "${term}"`).toString();
      res.send(result || 'No matches found');
    } catch (error) {
      res.status(500).send('Error searching file');
    }
  });
}
// {/fact}

// TRUE NEGATIVES (Safe code examples)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1() {
  const http = require('http');
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/read-file')) {
      const filename = req.url.split('=')[1];
      // ok: javascript-avoid-cat-for-reading-files
      fs.readFile(filename, 'utf8', (err, data) => {
        if (err) {
          res.writeHead(500);
          res.end('Error reading file');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(data);
      });
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2() {
  app.get('/view-log', (req, res) => {
    const logFile = req.query.file || 'app.log';
    // ok: javascript-avoid-cat-for-reading-files
    fs.readFile(logFile, 'utf8', (err, data) => {
      if (err) {
        return res.status(500).send('Error reading log file');
      }
      res.send(`<pre>${data}</pre>`);
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3() {
  app.post('/read-config', (req, res) => {
    const configFile = req.body.configPath;
    try {
      // ok: javascript-avoid-cat-for-reading-files
      const fileContent = fs.readFileSync(configFile, 'utf8');
      res.json({ content: fileContent });
    } catch (error) {
      res.status(500).json({ error: 'Failed to read config file' });
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        const data = JSON.parse(body);
        // ok: javascript-avoid-cat-for-reading-files
        fs.readFile(data.filename, 'utf8', (err, content) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          if (err) {
            return res.end(JSON.stringify({ error: 'File read error' }));
          }
          res.end(JSON.stringify({ content }));
        });
      });
    }
  });
  server.listen(8080);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5() {
  app.get('/user-file', (req, res) => {
    const userId = req.query.id;
    const fileName = req.query.name;
    // ok: javascript-avoid-cat-for-reading-files
    fs.readFile(`./users/${userId}/${fileName}`, (err, data) => {
      if (err) {
        return res.status(404).send('File not found');
      }
      res.send(data);
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6() {
  const server = http.createServer((req, res) => {
    const urlParts = new URL(req.url, `http://${req.headers.host}`);
    const filePath = urlParts.searchParams.get('path');
    if (filePath) {
      // ok: javascript-avoid-cat-for-reading-files
      const readStream = fs.createReadStream(filePath);
      readStream.on('error', (error) => {
        res.writeHead(500);
        res.end(`Error reading file: ${error.message}`);
      });
      readStream.pipe(res);
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7() {
  app.get('/api/documents/:id', (req, res) => {
    const docId = req.params.id;
    const format = req.query.format || 'txt';
    const filePath = `./documents/${docId}.${format}`;
    
    // ok: javascript-avoid-cat-for-reading-files
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
        return res.status(404).send('Document not found');
      }
      res.send(data);
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8() {
  app.post('/process-file', (req, res) => {
    const filePath = req.body.path;
    if (!filePath) {
      return res.status(400).send('File path is required');
    }
    
    try {
      // ok: javascript-avoid-cat-for-reading-files
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const errors = fileContent.split('\n').filter(line => line.includes('ERROR'));
      res.json({ errors });
    } catch (error) {
      res.status(500).send('Error processing file');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9() {
  const server = http.createServer((req, res) => {
    if (req.headers['x-file-path']) {
      const filePath = req.headers['x-file-path'];
      // ok: javascript-avoid-cat-for-reading-files
      fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
          res.writeHead(500);
          res.end('Error reading file');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(data);
      });
    } else {
      res.writeHead(400);
      res.end('Missing file path header');
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10() {
  app.get('/download', (req, res) => {
    const file = req.query.file;
    // ok: javascript-avoid-cat-for-reading-files
    fs.readFile(file, (err, data) => {
      if (err) {
        return res.status(500).send('Error reading file');
      }
      res.setHeader('Content-Disposition', `attachment; filename="${file}"`);
      res.send(data);
    });
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split('=');
      acc[key] = value;
      return acc;
    }, {});
    
    if (cookies && cookies.filePath) {
      // ok: javascript-avoid-cat-for-reading-files
      fs.readFile(cookies.filePath, 'utf8', (err, data) => {
        if (err) {
          res.writeHead(500);
          res.end('Error reading file');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(data);
      });
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12() {
  app.get('/read-multiple', (req, res) => {
    const files = req.query.files.split(',');
    let output = '';
    let filesProcessed = 0;
    
    for (const file of files) {
      // ok: javascript-avoid-cat-for-reading-files
      fs.readFile(file, 'utf8', (err, content) => {
        if (err) {
          output += `Error reading ${file}\n`;
        } else {
          output += `--- ${file} ---\n${content}\n\n`;
        }
        
        filesProcessed++;
        if (filesProcessed === files.length) {
          res.send(output);
        }
      });
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13() {
  app.post('/append-log', (req, res) => {
    const { logFile, message } = req.body;
    
    try {
      // First read the existing log
      // ok: javascript-avoid-cat-for-reading-files
      const existingLog = fs.readFileSync(logFile, 'utf8');
      
      // Then append the new message
      fs.writeFileSync(logFile, existingLog + '\n' + message);
      res.send('Log updated');
    } catch (error) {
      res.status(500).send('Error updating log');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14() {
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/tail-log')) {
      const query = new URLSearchParams(req.url.split('?')[1]);
      const lines = parseInt(query.get('lines') || '10', 10);
      const file = query.get('file');
      
      if (file) {
        // ok: javascript-avoid-cat-for-reading-files
        fs.readFile(file, 'utf8', (err, data) => {
          if (err) {
            res.writeHead(500);
            res.end('Error reading file');
            return;
          }
          
          const allLines = data.split('\n');
          const lastLines = allLines.slice(-lines).join('\n');
          
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(lastLines);
        });
      }
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15() {
  app.get('/search-file', (req, res) => {
    const { file, term } = req.query;
    
    if (!file || !term) {
      return res.status(400).send('Missing required parameters');
    }
    
    try {
      // ok: javascript-avoid-cat-for-reading-files
      const fileContent = fs.readFileSync(file, 'utf8');
      const matches = fileContent
        .split('\n')
        .filter(line => line.toLowerCase().includes(term.toLowerCase()));
      
      res.send(matches.join('\n') || 'No matches found');
    } catch (error) {
      res.status(500).send('Error searching file');
    }
  });
}
// {/fact}

// Start the server if this file is run directly
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};