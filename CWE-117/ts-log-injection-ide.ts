import * as express from 'express';
import * as winston from 'winston';
import * as fs from 'fs';
import * as http from 'http';
import * as url from 'url';
import * as querystring from 'querystring';
import * as crypto from 'crypto';

// Set up a basic logger for examples
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.simple(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'app.log' })
  ]
});

// Utility function to sanitize log messages
function sanitizeLogMessage(message: string): string {
  return message.replace(/[\r\n\t]/g, ' ');
}

// True Positive Examples (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.get('/login', (req, res) => {
    const username = req.query.username as string;
    
    // ruleid: ts-log-injection-ide
    logger.info(`User login attempt: ${username}`);
    
    res.send('Login attempt logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.post('/submit-comment', (req, res) => {
    const comment = req.body.comment;
    
    // ruleid: ts-log-injection-ide
    console.log(`New comment received: ${comment}`);
    
    res.send('Comment received');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_3() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const userAgent = req.headers['user-agent'] || '';
    
    // ruleid: ts-log-injection-ide
    fs.appendFileSync('access.log', `Access from user agent: ${userAgent}\n`);
    
    res.end('Request logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.get('/search', (req, res) => {
    const searchTerm = req.query.q as string;
    const ip = req.ip;
    
    // ruleid: ts-log-injection-ide
    logger.warn(`Failed search from ${ip} with term: ${searchTerm}`);
    
    res.send('Search results');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/update-profile', (req, res) => {
    const userId = req.body.userId;
    const changes = JSON.stringify(req.body.changes);
    
    // ruleid: ts-log-injection-ide
    process.stdout.write(`Profile update for user ${userId}: ${changes}\n`);
    
    res.send('Profile updated');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.get('/download', (req, res) => {
    const filePath = req.query.file as string;
    
    try {
      // Some file operations
      // ruleid: ts-log-injection-ide
      logger.info(`File download request for: ${filePath}`);
    } catch (error) {
      res.status(404).send('File not found');
    }
    
    res.send('File download initiated');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_7() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const referer = req.headers.referer || '';
    
    // ruleid: ts-log-injection-ide
    fs.appendFileSync('referer.log', `Referer: ${referer}\n`);
    
    res.end('Request processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.post('/api/auth', (req, res) => {
    const username = req.body.username;
    const loginStatus = authenticate(username, req.body.password) ? 'success' : 'failure';
    
    // ruleid: ts-log-injection-ide
    logger.info(`Authentication ${loginStatus} for user: ${username}`);
    
    res.json({ status: loginStatus });
  });
  
  function authenticate(username: string, password: string): boolean {
    return username === 'admin' && password === 'password';
  }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/error', (req, res) => {
    const errorMessage = req.query.message as string;
    
    try {
      throw new Error(errorMessage);
    } catch (error) {
      // ruleid: ts-log-injection-ide
      logger.error(`Application error: ${error.message}`);
      res.status(500).send('Error occurred');
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_10() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie || '';
    
    // ruleid: ts-log-injection-ide
    console.log(`Request cookies: ${cookies}`);
    
    res.end('Request processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.post('/upload', (req, res) => {
    const fileName = req.body.fileName;
    const fileSize = req.body.fileSize;
    
    // ruleid: ts-log-injection-ide
    logger.info(`File upload: ${fileName} (${fileSize} bytes)`);
    
    res.send('Upload processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.get('/api/products', (req, res) => {
    const category = req.query.category as string;
    const sortBy = req.query.sortBy as string;
    
    // ruleid: ts-log-injection-ide
    fs.appendFileSync('query.log', `Product query - category: ${category}, sort: ${sortBy}\n`);
    
    res.json([{ name: 'Product 1' }]);
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/contact', (req, res) => {
    const formData = req.body;
    
    // ruleid: ts-log-injection-ide
    logger.info(`Contact form submission from ${formData.email} with message: ${formData.message}`);
    
    res.send('Thank you for your message');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_14() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const queryParams = querystring.stringify(parsedUrl.query);
    
    // ruleid: ts-log-injection-ide
    console.log(`Request with query parameters: ${queryParams}`);
    
    res.end('Request processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;
    const action = req.query.action as string;
    
    // ruleid: ts-log-injection-ide
    logger.info(`User ${userId} performed action: ${action}`);
    
    res.json({ status: 'success' });
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/login', (req, res) => {
    const username = req.query.username as string;
    
    // ok: ts-log-injection-ide
    logger.info(`User login attempt: ${sanitizeLogMessage(username)}`);
    
    res.send('Login attempt logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/submit-comment', (req, res) => {
    const comment = req.body.comment;
    
    // ok: ts-log-injection-ide
    console.log(`New comment received: ${comment.replace(/[\r\n]/g, '')}`);
    
    res.send('Comment received');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_3() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const userAgent = req.headers['user-agent'] || '';
    
    // ok: ts-log-injection-ide
    fs.appendFileSync('access.log', `Access from user agent: ${userAgent.replace(/[\r\n\t]/g, ' ')}\n`);
    
    res.end('Request logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.get('/search', (req, res) => {
    const searchTerm = req.query.q as string;
    const ip = req.ip;
    
    const sanitizedTerm = searchTerm ? searchTerm.replace(/[\r\n\t]/g, '') : '';
    // ok: ts-log-injection-ide
    logger.warn(`Failed search from ${ip} with term: ${sanitizedTerm}`);
    
    res.send('Search results');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/update-profile', (req, res) => {
    const userId = req.body.userId;
    const changes = JSON.stringify(req.body.changes);
    
    // ok: ts-log-injection-ide
    process.stdout.write(`Profile update for user ${userId.toString().replace(/[\r\n]/g, '')}: ${changes.replace(/[\r\n]/g, '')}\n`);
    
    res.send('Profile updated');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.get('/download', (req, res) => {
    const filePath = req.query.file as string;
    
    try {
      // Some file operations
      const safeFilePath = filePath.replace(/[\r\n\t"']/g, '');
      // ok: ts-log-injection-ide
      logger.info(`File download request for: ${safeFilePath}`);
    } catch (error) {
      res.status(404).send('File not found');
    }
    
    res.send('File download initiated');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_7() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const referer = req.headers.referer || '';
    
    // ok: ts-log-injection-ide
    fs.appendFileSync('referer.log', `Referer: ${sanitizeLogMessage(referer)}\n`);
    
    res.end('Request processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.post('/api/auth', (req, res) => {
    const username = req.body.username;
    const loginStatus = authenticate(username, req.body.password) ? 'success' : 'failure';
    
    // ok: ts-log-injection-ide
    logger.info(`Authentication ${loginStatus} for user: ${username.toString().replace(/[\r\n\t]/g, '_')}`);
    
    res.json({ status: loginStatus });
  });
  
  function authenticate(username: string, password: string): boolean {
    return username === 'admin' && password === 'password';
  }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/error', (req, res) => {
    const errorMessage = req.query.message as string;
    
    try {
      throw new Error(errorMessage);
    } catch (error) {
      const safeErrorMessage = error.message.replace(/[\r\n\t]/g, ' ');
      // ok: ts-log-injection-ide
      logger.error(`Application error: ${safeErrorMessage}`);
      res.status(500).send('Error occurred');
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_10() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie || '';
    
    // ok: ts-log-injection-ide
    console.log(`Request cookies: ${cookies.toString().replace(/[\r\n]/g, '[filtered]')}`);
    
    res.end('Request processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.post('/upload', (req, res) => {
    const fileName = req.body.fileName;
    const fileSize = req.body.fileSize;
    
    // Using JSON.stringify to safely encode potentially dangerous characters
    // ok: ts-log-injection-ide
    logger.info(`File upload: ${JSON.stringify(fileName)} (${fileSize} bytes)`);
    
    res.send('Upload processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/api/products', (req, res) => {
    const category = req.query.category as string;
    const sortBy = req.query.sortBy as string;
    
    const sanitizedCategory = category ? sanitizeLogMessage(category) : '';
    const sanitizedSortBy = sortBy ? sanitizeLogMessage(sortBy) : '';
    
    // ok: ts-log-injection-ide
    fs.appendFileSync('query.log', `Product query - category: ${sanitizedCategory}, sort: ${sanitizedSortBy}\n`);
    
    res.json([{ name: 'Product 1' }]);
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/contact', (req, res) => {
    const formData = req.body;
    const safeEmail = formData.email ? formData.email.replace(/[\r\n\t]/g, '') : '';
    const safeMessage = formData.message ? formData.message.replace(/[\r\n\t]/g, ' ') : '';
    
    // ok: ts-log-injection-ide
    logger.info(`Contact form submission from ${safeEmail} with message: ${safeMessage}`);
    
    res.send('Thank you for your message');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_14() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    
    // Instead of directly logging query parameters, log a safe representation
    const safeQueryParams = Object.entries(parsedUrl.query).map(
      ([key, value]) => `${key}=${typeof value === 'string' ? value.replace(/[\r\n\t]/g, '') : value}`
    ).join('&');
    
    // ok: ts-log-injection-ide
    console.log(`Request with query parameters: ${safeQueryParams}`);
    
    res.end('Request processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;
    const action = req.query.action as string;
    
    // Using a dedicated logging function that handles sanitization
    function logSafely(message: string, params: Record<string, any>) {
      const safeParams = Object.fromEntries(
        Object.entries(params).map(([k, v]) => [k, typeof v === 'string' ? v.replace(/[\r\n\t]/g, '') : v])
      );
      logger.info(message, safeParams);
    }
    
    // ok: ts-log-injection-ide
    logSafely('User action', { userId, action });
    
    res.json({ status: 'success' });
  });
}
// {/fact}