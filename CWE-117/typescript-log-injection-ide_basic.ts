// Import necessary libraries
import * as express from 'express';
import * as winston from 'winston';
import * as fs from 'fs';
import * as http from 'http';
import * as https from 'https';
import * as axios from 'axios';
import * as querystring from 'querystring';
import * as url from 'url';

// Set up a logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'application.log' })
  ]
});

// Simple console logger
const consoleLogger = {
  log: (message: string) => console.log(message),
  info: (message: string) => console.info(message),
  warn: (message: string) => console.warn(message),
  error: (message: string) => console.error(message)
};

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
  
  app.post('/submit', (req, res) => {
    const userInput = req.body.comment;
    // ruleid: ts-log-injection-ide
    console.log(`New comment submitted: ${userInput}`);
    
    res.send('Comment received');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/search', (req, res) => {
    const searchTerm = req.query.q as string;
    // ruleid: ts-log-injection-ide
    fs.appendFileSync('search_logs.txt', `Search query: ${searchTerm}\n`);
    
    res.send('Search logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.post('/register', (req, res) => {
    const userAgent = req.headers['user-agent'] as string;
    // ruleid: ts-log-injection-ide
    logger.warn(`New registration from: ${userAgent}`);
    
    res.send('Registration logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/profile', (req, res) => {
    const userId = req.query.id as string;
    const referrer = req.headers.referer as string;
    
    // ruleid: ts-log-injection-ide
    consoleLogger.info(`Profile accessed for user ${userId} from referrer ${referrer}`);
    
    res.send('Profile access logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.post('/feedback', (req, res) => {
    const feedback = req.body.text;
    const email = req.body.email;
    
    // ruleid: ts-log-injection-ide
    process.stdout.write(`Feedback received from ${email}: ${feedback}\n`);
    
    res.send('Feedback logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/download', (req, res) => {
    const fileName = req.query.file as string;
    const ipAddress = req.ip;
    
    // ruleid: ts-log-injection-ide
    logger.error(`Failed download attempt for file ${fileName} from IP ${ipAddress}`);
    
    res.status(404).send('File not found');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.post('/api/data', (req, res) => {
    const payload = JSON.stringify(req.body);
    
    // ruleid: ts-log-injection-ide
    console.error(`Invalid API request: ${payload}`);
    
    res.status(400).send('Bad request');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_9() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const query = parsedUrl.query.term as string;
    
    // ruleid: ts-log-injection-ide
    fs.writeFileSync('query_log.txt', `Query: ${query}\n`, { flag: 'a' });
    
    res.end('Query logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.get('/error', (req, res) => {
    const errorCode = req.query.code as string;
    const errorMessage = req.query.message as string;
    
    // ruleid: ts-log-injection-ide
    logger.error(`Error ${errorCode}: ${errorMessage}`);
    
    res.send('Error logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.post('/upload', (req, res) => {
    const fileName = req.body.fileName;
    const fileSize = req.body.fileSize;
    
    try {
      // Some file processing logic
      throw new Error('Upload failed');
    } catch (error) {
      // ruleid: ts-log-injection-ide
      console.log(`Error uploading file ${fileName} (${fileSize} bytes): ${error.message}`);
      res.status(500).send('Upload failed');
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.get('/audit', (req, res) => {
    const action = req.query.action as string;
    const username = req.query.user as string;
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      action: action,
      user: username
    };
    
    // ruleid: ts-log-injection-ide
    fs.appendFileSync('audit.log', `${JSON.stringify(logEntry)}\n`);
    
    res.send('Action audited');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/contact', (req, res) => {
    const name = req.body.name;
    const message = req.body.message;
    
    // ruleid: ts-log-injection-ide
    process.stderr.write(`Contact form submission from ${name}: ${message}\n`);
    
    res.send('Message received');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_14() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie;
    
    // ruleid: ts-log-injection-ide
    logger.info(`Request received with cookies: ${cookies}`);
    
    res.end('Request processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/redirect', (req, res) => {
    const destination = req.query.url as string;
    
    // ruleid: ts-log-injection-ide
    console.log(`Redirecting user to: ${destination}`);
    
    res.redirect(destination);
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/login', (req, res) => {
    const username = req.query.username as string;
    // Sanitize input before logging
    // ok: ts-log-injection-ide
    logger.info(`User login attempt: ${sanitizeLogMessage(username)}`);
    
    res.send('Login attempt logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/submit', (req, res) => {
    const userInput = req.body.comment;
    // Replace newlines with spaces
    const sanitizedInput = userInput.replace(/[\r\n]/g, ' ');
    // ok: ts-log-injection-ide
    console.log(`New comment submitted: ${sanitizedInput}`);
    
    res.send('Comment received');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/search', (req, res) => {
    const searchTerm = req.query.q as string;
    // Encode special characters
    const safeSearchTerm = encodeURIComponent(searchTerm);
    // ok: ts-log-injection-ide
    fs.appendFileSync('search_logs.txt', `Search query: ${safeSearchTerm}\n`);
    
    res.send('Search logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.post('/register', (req, res) => {
    const userAgent = req.headers['user-agent'] as string;
    // JSON.stringify safely escapes control characters
    // ok: ts-log-injection-ide
    logger.warn(`New registration from: ${JSON.stringify(userAgent)}`);
    
    res.send('Registration logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/profile', (req, res) => {
    const userId = req.query.id as string;
    const referrer = req.headers.referer as string;
    
    // Use a sanitization function
    const sanitizedUserId = sanitizeLogMessage(userId);
    const sanitizedReferrer = sanitizeLogMessage(referrer);
    
    // ok: ts-log-injection-ide
    consoleLogger.info(`Profile accessed for user ${sanitizedUserId} from referrer ${sanitizedReferrer}`);
    
    res.send('Profile access logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.post('/feedback', (req, res) => {
    const feedback = req.body.text;
    const email = req.body.email;
    
    // Remove control characters
    const safeFeedback = feedback.replace(/[\x00-\x1F\x7F-\x9F]/g, '');
    const safeEmail = email.replace(/[\x00-\x1F\x7F-\x9F]/g, '');
    
    // ok: ts-log-injection-ide
    process.stdout.write(`Feedback received from ${safeEmail}: ${safeFeedback}\n`);
    
    res.send('Feedback logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/download', (req, res) => {
    const fileName = req.query.file as string;
    const ipAddress = req.ip;
    
    // Use object logging instead of string interpolation
    // ok: ts-log-injection-ide
    logger.error({
      message: 'Failed download attempt',
      file: fileName,
      ip: ipAddress
    });
    
    res.status(404).send('File not found');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.post('/api/data', (req, res) => {
    // Use safe object logging
    // ok: ts-log-injection-ide
    console.error({
      message: 'Invalid API request',
      payload: req.body
    });
    
    res.status(400).send('Bad request');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_9() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const query = parsedUrl.query.term as string;
    
    // Sanitize before writing to log file
    const safeQuery = query ? query.replace(/[\r\n]/g, '') : '';
    
    // ok: ts-log-injection-ide
    fs.writeFileSync('query_log.txt', `Query: ${safeQuery}\n`, { flag: 'a' });
    
    res.end('Query logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.get('/error', (req, res) => {
    const errorCode = req.query.code as string;
    const errorMessage = req.query.message as string;
    
    // Use template literal with sanitized inputs
    const safeErrorCode = errorCode.replace(/[\r\n\t]/g, '');
    const safeErrorMessage = errorMessage.replace(/[\r\n\t]/g, '');
    
    // ok: ts-log-injection-ide
    logger.error(`Error ${safeErrorCode}: ${safeErrorMessage}`);
    
    res.send('Error logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.post('/upload', (req, res) => {
    const fileName = req.body.fileName;
    const fileSize = req.body.fileSize;
    
    try {
      // Some file processing logic
      throw new Error('Upload failed');
    } catch (error) {
      // Sanitize user inputs before logging
      const safeFileName = sanitizeLogMessage(fileName);
      
      // ok: ts-log-injection-ide
      console.log(`Error uploading file ${safeFileName} (${fileSize} bytes): ${error.message}`);
      res.status(500).send('Upload failed');
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/audit', (req, res) => {
    const action = req.query.action as string;
    const username = req.query.user as string;
    
    // Use JSON structure for logging
    const logEntry = {
      timestamp: new Date().toISOString(),
      action: action,
      user: username
    };
    
    // ok: ts-log-injection-ide
    fs.appendFileSync('audit.log', JSON.stringify(logEntry) + '\n');
    
    res.send('Action audited');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/contact', (req, res) => {
    const name = req.body.name;
    const message = req.body.message;
    
    // Use a custom sanitizer function
    const sanitizedName = sanitizeLogMessage(name);
    const sanitizedMessage = sanitizeLogMessage(message);
    
    // ok: ts-log-injection-ide
    process.stderr.write(`Contact form submission from ${sanitizedName}: ${sanitizedMessage}\n`);
    
    res.send('Message received');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_14() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie;
    
    // Don't log sensitive data directly, use a hash or truncated version
    const cookieHash = cookies ? 
      require('crypto').createHash('sha256').update(cookies).digest('hex').substring(0, 8) : 
      'none';
    
    // ok: ts-log-injection-ide
    logger.info(`Request received with cookie hash: ${cookieHash}`);
    
    res.end('Request processed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/redirect', (req, res) => {
    const destination = req.query.url as string;
    
    // Use structured logging
    // ok: ts-log-injection-ide
    console.log({
      message: 'Redirecting user',
      destination: destination
    });
    
    res.redirect(destination);
  });
}
// {/fact}