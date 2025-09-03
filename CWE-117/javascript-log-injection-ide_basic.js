// Import necessary modules
const express = require('express');
const winston = require('winston');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);
const app = express();
const logger = winston.createLogger({
  transports: [new winston.transports.Console()]
});

// Configure express
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_1() {
  app.get('/login', (req, res) => {
    const username = req.query.username;
    // ruleid: js-log-injection-ide
    console.log(`User login attempt: ${username}`);
    res.send('Login attempt recorded');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_2() {
  app.post('/submit-form', (req, res) => {
    const formData = req.body.data;
    // ruleid: js-log-injection-ide
    logger.info(`Form submission received: ${formData}`);
    res.send('Form received');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_3() {
  app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // ruleid: js-log-injection-ide
    console.error(`Failed to find results for: ${searchTerm}`);
    res.send('No results found');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_4() {
  app.post('/update-profile', (req, res) => {
    try {
      // Some processing
      throw new Error('Profile update failed');
    } catch (error) {
      // ruleid: js-log-injection-ide
      console.warn(`Error updating profile for user ${req.body.userId}: ${error.message}`);
      res.status(500).send('Error updating profile');
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_5() {
  app.get('/api/products', (req, res) => {
    const category = req.query.category;
    // ruleid: js-log-injection-ide
    logger.debug(`Product category requested: ${category}`);
    res.json({ products: [] });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_6() {
  app.get('/download', (req, res) => {
    const fileId = req.query.fileId;
    const userAgent = req.headers['user-agent'];
    // ruleid: js-log-injection-ide
    console.log(`File ${fileId} downloaded by user agent: ${userAgent}`);
    res.download(`/path/to/file/${fileId}`);
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_7() {
  app.post('/contact', (req, res) => {
    const { name, email, message } = req.body;
    // ruleid: js-log-injection-ide
    logger.info(`Contact form submission - Name: ${name}, Email: ${email}, Message: ${message}`);
    res.send('Thank you for your message');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_8() {
  app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;
    const referer = req.headers.referer;
    // ruleid: js-log-injection-ide
    console.log(`User profile ${userId} accessed from referrer: ${referer}`);
    res.json({ user: {} });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_9() {
  app.post('/api/comments', (req, res) => {
    const comment = req.body.comment;
    // ruleid: js-log-injection-ide
    logger.warn(`New comment needs moderation: ${comment}`);
    res.status(201).send('Comment submitted for review');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_10() {
  app.get('/api/metrics', (req, res) => {
    const clientIp = req.ip;
    const endpoint = req.query.endpoint;
    // ruleid: js-log-injection-ide
    console.info(`Metrics requested for ${endpoint} from IP: ${clientIp}`);
    res.json({ metrics: {} });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_11() {
  app.post('/api/upload', (req, res) => {
    const fileName = req.body.fileName;
    // ruleid: js-log-injection-ide
    logger.info(`File upload initiated: ${fileName}`);
    res.status(200).send('Upload started');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_12() {
  app.get('/api/search', (req, res) => {
    const searchParams = new URLSearchParams(req.url.split('?')[1]);
    const term = searchParams.get('term');
    // ruleid: js-log-injection-ide
    console.log(`Search performed with term: ${term}`);
    res.json({ results: [] });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_13() {
  app.use((err, req, res, next) => {
    const path = req.path;
    // ruleid: js-log-injection-ide
    logger.error(`Error occurred on path ${path}: ${err.message}`);
    res.status(500).send('Server error');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_14() {
  app.get('/api/config', (req, res) => {
    const configName = req.query.name;
    let configValue;
    
    try {
      // Get config value
      configValue = "test";
    } catch (error) {
      // ruleid: js-log-injection-ide
      console.error(`Failed to retrieve config ${configName}: ${error.message}`);
      return res.status(500).send('Error retrieving configuration');
    }
    
    res.json({ name: configName, value: configValue });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_15() {
  app.post('/api/feedback', (req, res) => {
    const { rating, feedback } = req.body;
    
    switch(parseInt(rating)) {
      case 1:
      case 2:
        // ruleid: js-log-injection-ide
        logger.warn(`Negative feedback received: ${feedback}`);
        break;
      case 3:
      case 4:
      case 5:
        // ruleid: js-log-injection-ide
        logger.info(`Positive feedback received: ${feedback}`);
        break;
      default:
        // ruleid: js-log-injection-ide
        logger.error(`Invalid rating provided with feedback: ${feedback}`);
    }
    
    res.send('Thank you for your feedback');
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_1() {
  app.get('/login', (req, res) => {
    const username = req.query.username;
    // ok: js-log-injection-ide
    console.log(`User login attempt: ${encodeURIComponent(username)}`);
    res.send('Login attempt recorded');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_2() {
  app.post('/submit-form', (req, res) => {
    const formData = req.body.data;
    // ok: js-log-injection-ide
    logger.info(`Form submission received: ${purify.sanitize(formData)}`);
    res.send('Form received');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_3() {
  app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    const sanitizedTerm = encodeURIComponent(searchTerm);
    // ok: js-log-injection-ide
    console.error(`Failed to find results for: ${sanitizedTerm}`);
    res.send('No results found');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_4() {
  app.post('/update-profile', (req, res) => {
    try {
      // Some processing
      throw new Error('Profile update failed');
    } catch (error) {
      const sanitizedUserId = encodeURIComponent(req.body.userId);
      // ok: js-log-injection-ide
      console.warn(`Error updating profile for user ${sanitizedUserId}: ${error.message}`);
      res.status(500).send('Error updating profile');
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_5() {
  app.get('/api/products', (req, res) => {
    const category = req.query.category;
    // ok: js-log-injection-ide
    logger.debug(`Product category requested: ${purify.sanitize(category)}`);
    res.json({ products: [] });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_6() {
  app.get('/download', (req, res) => {
    const fileId = req.query.fileId;
    const userAgent = req.headers['user-agent'];
    // ok: js-log-injection-ide
    console.log(`File ${encodeURIComponent(fileId)} downloaded by user agent: ${encodeURIComponent(userAgent)}`);
    res.download(`/path/to/file/${fileId}`);
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_7() {
  app.post('/contact', (req, res) => {
    const { name, email, message } = req.body;
    const sanitizedName = purify.sanitize(name);
    const sanitizedEmail = purify.sanitize(email);
    const sanitizedMessage = purify.sanitize(message);
    // ok: js-log-injection-ide
    logger.info(`Contact form submission - Name: ${sanitizedName}, Email: ${sanitizedEmail}, Message: ${sanitizedMessage}`);
    res.send('Thank you for your message');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_8() {
  app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;
    const referer = req.headers.referer || '';
    // ok: js-log-injection-ide
    console.log(`User profile ${encodeURIComponent(userId)} accessed from referrer: ${encodeURIComponent(referer)}`);
    res.json({ user: {} });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_9() {
  app.post('/api/comments', (req, res) => {
    const comment = req.body.comment;
    // Using a function to sanitize
    function sanitizeForLog(input) {
      return encodeURIComponent(String(input));
    }
    // ok: js-log-injection-ide
    logger.warn(`New comment needs moderation: ${sanitizeForLog(comment)}`);
    res.status(201).send('Comment submitted for review');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_10() {
  app.get('/api/metrics', (req, res) => {
    const clientIp = req.ip;
    const endpoint = req.query.endpoint;
    const sanitizedIp = encodeURIComponent(clientIp);
    const sanitizedEndpoint = encodeURIComponent(endpoint);
    // ok: js-log-injection-ide
    console.info(`Metrics requested for ${sanitizedEndpoint} from IP: ${sanitizedIp}`);
    res.json({ metrics: {} });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_11() {
  app.post('/api/upload', (req, res) => {
    const fileName = req.body.fileName;
    // Using DOMPurify for sanitization
    const sanitizedFileName = purify.sanitize(fileName);
    // ok: js-log-injection-ide
    logger.info(`File upload initiated: ${sanitizedFileName}`);
    res.status(200).send('Upload started');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_12() {
  app.get('/api/search', (req, res) => {
    const searchParams = new URLSearchParams(req.url.split('?')[1]);
    const term = searchParams.get('term');
    // Sanitize before logging
    const sanitizedTerm = term ? encodeURIComponent(term) : '';
    // ok: js-log-injection-ide
    console.log(`Search performed with term: ${sanitizedTerm}`);
    res.json({ results: [] });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_13() {
  app.use((err, req, res, next) => {
    const path = req.path;
    // ok: js-log-injection-ide
    logger.error(`Error occurred on path ${encodeURIComponent(path)}: ${err.message}`);
    res.status(500).send('Server error');
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_14() {
  app.get('/api/config', (req, res) => {
    const configName = req.query.name;
    let configValue;
    
    try {
      // Get config value
      configValue = "test";
    } catch (error) {
      const sanitizedConfigName = purify.sanitize(configName);
      // ok: js-log-injection-ide
      console.error(`Failed to retrieve config ${sanitizedConfigName}: ${error.message}`);
      return res.status(500).send('Error retrieving configuration');
    }
    
    res.json({ name: configName, value: configValue });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_15() {
  app.post('/api/feedback', (req, res) => {
    const { rating, feedback } = req.body;
    const sanitizedFeedback = encodeURIComponent(feedback);
    
    switch(parseInt(rating)) {
      case 1:
      case 2:
        // ok: js-log-injection-ide
        logger.warn(`Negative feedback received: ${sanitizedFeedback}`);
        break;
      case 3:
      case 4:
      case 5:
        // ok: js-log-injection-ide
        logger.info(`Positive feedback received: ${sanitizedFeedback}`);
        break;
      default:
        // ok: js-log-injection-ide
        logger.error(`Invalid rating provided with feedback: ${sanitizedFeedback}`);
    }
    
    res.send('Thank you for your feedback');
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});