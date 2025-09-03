const express = require('express');
const app = express();
const winston = require('winston');
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Utility function for sanitizing logs
function sanitizeLog(input) {
  if (typeof input !== 'string') return input;
  return input.replace(/[\r\n]/g, ' ');
}

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_1() {
  app.get('/login', (req, res) => {
    const username = req.query.username;
    // ruleid: javascript-log-injection
    console.log("User login attempt: " + username);
    res.send('Login attempt recorded');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_2() {
  app.post('/submit-form', (req, res) => {
    const userInput = req.body.message;
    // ruleid: javascript-log-injection
    logger.info(`Form submission received: ${userInput}`);
    res.send('Form submitted');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_3() {
  app.get('/search', (req, res) => {
    const searchQuery = req.query.q;
    // ruleid: javascript-log-injection
    console.error("Error processing search query: " + searchQuery);
    res.status(500).send('Search error');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_4() {
  app.get('/profile', (req, res) => {
    const userId = req.headers['user-id'];
    // ruleid: javascript-log-injection
    logger.warn(`Unusual access pattern for user: ${userId}`);
    res.send('Profile accessed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_5() {
  app.post('/comment', (req, res) => {
    const comment = req.body.text;
    const ip = req.ip;
    // ruleid: javascript-log-injection
    console.log(`New comment from IP ${ip}: ${comment}`);
    res.send('Comment posted');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_6() {
  app.get('/download', (req, res) => {
    const filePath = req.query.file;
    // ruleid: javascript-log-injection
    logger.debug("File download requested: " + filePath);
    res.download(filePath);
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_7() {
  app.post('/register', (req, res) => {
    const email = req.body.email;
    // ruleid: javascript-log-injection
    console.info(`New user registration: ${email}`);
    res.send('Registration successful');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_8() {
  app.get('/api/data', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    // ruleid: javascript-log-injection
    logger.log('info', `API access with key: ${apiKey}`);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_9() {
  app.post('/payment', (req, res) => {
    const amount = req.body.amount;
    const userId = req.cookies.userId;
    // ruleid: javascript-log-injection
    console.log(`Payment initiated by user ${userId} for amount ${amount}`);
    res.send('Payment processing');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_10() {
  app.get('/error', (req, res) => {
    const errorMsg = req.query.message;
    // ruleid: javascript-log-injection
    logger.error(`Client reported error: ${errorMsg}`);
    res.status(200).send('Error logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_11() {
  app.post('/feedback', (req, res) => {
    const feedback = req.body.feedback;
    const userAgent = req.headers['user-agent'];
    // ruleid: javascript-log-injection
    console.log("Feedback received from " + userAgent + ": " + feedback);
    res.send('Thank you for your feedback');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_12() {
  app.get('/verify', (req, res) => {
    const token = req.query.token;
    // ruleid: javascript-log-injection
    logger.info("Verification attempt with token: " + token);
    res.send('Verification in progress');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_13() {
  app.post('/upload', (req, res) => {
    const fileName = req.body.fileName;
    // ruleid: javascript-log-injection
    console.warn(`Suspicious file upload detected: ${fileName}`);
    res.status(403).send('Upload rejected');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_14() {
  app.get('/metrics', (req, res) => {
    const clientId = req.query.client;
    const referrer = req.headers.referer;
    // ruleid: javascript-log-injection
    logger.debug(`Metrics accessed by ${clientId} from ${referrer}`);
    res.send('Metrics data');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_15() {
  app.post('/contact', (req, res) => {
    const name = req.body.name;
    const message = req.body.message;
    // ruleid: javascript-log-injection
    console.log(`Contact form: ${name} said: ${message}`);
    res.send('Message sent');
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_1() {
  app.get('/login', (req, res) => {
    const username = req.query.username;
    // ok: javascript-log-injection
    console.log("User login attempt: " + sanitizeLog(username));
    res.send('Login attempt recorded');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_2() {
  app.post('/submit-form', (req, res) => {
    const userInput = req.body.message;
    // ok: javascript-log-injection
    logger.info(`Form submission received: ${sanitizeLog(userInput)}`);
    res.send('Form submitted');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_3() {
  app.get('/search', (req, res) => {
    const searchQuery = req.query.q;
    // ok: javascript-log-injection
    console.error("Error processing search query: " + searchQuery.replace(/[\r\n]/g, ''));
    res.status(500).send('Search error');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_4() {
  app.get('/profile', (req, res) => {
    const userId = req.headers['user-id'];
    // Using JSON.stringify to safely log objects
    // ok: javascript-log-injection
    logger.warn(`Unusual access pattern for user: ${JSON.stringify(userId).replace(/^"|"$/g, '')}`);
    res.send('Profile accessed');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_5() {
  app.post('/comment', (req, res) => {
    const comment = req.body.text;
    const ip = req.ip;
    // ok: javascript-log-injection
    console.log(`New comment from IP ${sanitizeLog(ip)}: ${sanitizeLog(comment)}`);
    res.send('Comment posted');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_6() {
  app.get('/download', (req, res) => {
    const filePath = req.query.file;
    // Using a dedicated logging library with sanitization
    // ok: javascript-log-injection
    logger.debug({
      message: "File download requested",
      file: filePath.toString().replace(/[\r\n]/g, '')
    });
    res.download(filePath);
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_7() {
  app.post('/register', (req, res) => {
    const email = req.body.email;
    // ok: javascript-log-injection
    console.info(`New user registration: ${email.split('\n')[0]}`);
    res.send('Registration successful');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_8() {
  app.get('/api/data', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    // Masking sensitive data and sanitizing
    // ok: javascript-log-injection
    const maskedKey = apiKey ? apiKey.substring(0, 4) + '...' : 'none';
    logger.log('info', `API access with key: ${sanitizeLog(maskedKey)}`);
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_9() {
  app.post('/payment', (req, res) => {
    const amount = req.body.amount;
    const userId = req.cookies.userId;
    // ok: javascript-log-injection
    console.log(`Payment initiated by user ${sanitizeLog(userId)} for amount ${parseFloat(amount)}`);
    res.send('Payment processing');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_10() {
  app.get('/error', (req, res) => {
    const errorMsg = req.query.message;
    // Using structured logging
    // ok: javascript-log-injection
    logger.error({
      event: 'client_error',
      message: sanitizeLog(errorMsg)
    });
    res.status(200).send('Error logged');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_11() {
  app.post('/feedback', (req, res) => {
    const feedback = req.body.feedback;
    const userAgent = req.headers['user-agent'];
    // ok: javascript-log-injection
    const sanitizedFeedback = typeof feedback === 'string' ? feedback.replace(/[\r\n]/g, ' ') : '';
    console.log("Feedback received from " + sanitizeLog(userAgent) + ": " + sanitizedFeedback);
    res.send('Thank you for your feedback');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_12() {
  app.get('/verify', (req, res) => {
    const token = req.query.token;
    // Only logging a hash of the token for security
    // ok: javascript-log-injection
    const crypto = require('crypto');
    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
    logger.info("Verification attempt with token hash: " + tokenHash);
    res.send('Verification in progress');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_13() {
  app.post('/upload', (req, res) => {
    const fileName = req.body.fileName;
    // ok: javascript-log-injection
    const path = require('path');
    const safeFileName = path.basename(sanitizeLog(fileName));
    console.warn(`Suspicious file upload detected: ${safeFileName}`);
    res.status(403).send('Upload rejected');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_14() {
  app.get('/metrics', (req, res) => {
    const clientId = req.query.client;
    const referrer = req.headers.referer;
    // ok: javascript-log-injection
    logger.debug({
      event: 'metrics_access',
      client: sanitizeLog(clientId),
      referrer: sanitizeLog(referrer)
    });
    res.send('Metrics data');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_15() {
  app.post('/contact', (req, res) => {
    const name = req.body.name;
    const message = req.body.message;
    // ok: javascript-log-injection
    const sanitizedName = sanitizeLog(name);
    const sanitizedMessage = sanitizeLog(message);
    console.log(`Contact form: ${sanitizedName} said: ${sanitizedMessage}`);
    res.send('Message sent');
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});