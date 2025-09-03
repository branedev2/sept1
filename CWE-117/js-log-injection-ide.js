// Import necessary libraries
const express = require('express');
const app = express();
const logger = require('winston');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// Configure body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set up logging
logger.configure({
  transports: [
    new logger.transports.Console(),
    new logger.transports.File({ filename: 'app.log' })
  ]
});

// BAD CASES - Log Injection Vulnerabilities

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_1(req, res) {
  const username = req.query.username;
  // ruleid: js-log-injection-ide
  console.log("User login attempt: " + username);
  res.send("Login attempt logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_2(req, res) {
  const searchTerm = req.body.search;
  // ruleid: js-log-injection-ide
  logger.info(`Search performed for: ${searchTerm}`);
  res.send("Search logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_3(req, res) {
  const userAgent = req.headers['user-agent'];
  // ruleid: js-log-injection-ide
  console.error("Error occurred for user with agent: " + userAgent);
  res.status(500).send("Error logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_4(req, res) {
  const ipAddress = req.ip;
  const action = req.query.action;
  // ruleid: js-log-injection-ide
  console.warn(`User from IP ${ipAddress} attempted action: ${action}`);
  res.send("Action logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_5(req, res) {
  const referrer = req.headers.referer;
  // ruleid: js-log-injection-ide
  logger.debug("Request referred from: " + referrer);
  res.send("Referrer logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_6(req, res) {
  const email = req.body.email;
  // ruleid: js-log-injection-ide
  process.stdout.write(`User registration attempt with email: ${email}\n`);
  res.send("Registration logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_7(req, res) {
  const errorMessage = req.query.error;
  // ruleid: js-log-injection-ide
  console.log("Error reported by user: " + errorMessage);
  res.send("Error logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_8(req, res) {
  const productId = req.params.id;
  const userId = req.cookies.userId;
  // ruleid: js-log-injection-ide
  logger.info(`User ${userId} viewed product ${productId}`);
  res.send("Product view logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_9(req, res) {
  const formData = JSON.stringify(req.body);
  // ruleid: js-log-injection-ide
  console.log("Form submission data: " + formData);
  res.send("Form submission logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_10(req, res) {
  const authToken = req.headers.authorization;
  // ruleid: js-log-injection-ide
  logger.warn(`Failed authentication attempt with token: ${authToken}`);
  res.status(401).send("Unauthorized");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_11(req, res) {
  const queryParams = req.url.split('?')[1];
  // ruleid: js-log-injection-ide
  console.log("Request received with query parameters: " + queryParams);
  res.send("Request logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_12(req, res) {
  const username = req.body.username;
  const password = req.body.password; // Not logging password, but username is still vulnerable
  // ruleid: js-log-injection-ide
  logger.info("Login attempt by: " + username);
  res.send("Login attempt processed");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_13(req, res) {
  let userInput = '';
  for (const key in req.query) {
    userInput += `${key}=${req.query[key]}, `;
  }
  // ruleid: js-log-injection-ide
  console.log("Received parameters: " + userInput);
  res.send("Parameters logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_14(req, res) {
  const commentText = req.body.comment;
  if (commentText.length > 0) {
    // ruleid: js-log-injection-ide
    logger.info(`New comment posted: ${commentText}`);
  }
  res.send("Comment logged");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_15(req, res) {
  try {
    throw new Error("Process failed");
  } catch (error) {
    const errorContext = req.query.context;
    // ruleid: js-log-injection-ide
    console.error(`Error occurred in context ${errorContext}: ${error.message}`);
    res.status(500).send("Error logged");
  }
}
// {/fact}

// GOOD CASES - Safe Logging Practices

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_1(req, res) {
  const username = req.query.username;
  // ok: js-log-injection-ide
  console.log("User login attempt: " + encodeURIComponent(username));
  res.send("Login attempt logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_2(req, res) {
  const searchTerm = req.body.search;
  // ok: js-log-injection-ide
  logger.info(`Search performed for: ${encodeURIComponent(searchTerm)}`);
  res.send("Search logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_3(req, res) {
  const userAgent = req.headers['user-agent'];
  // ok: js-log-injection-ide
  console.error("Error occurred for user with agent: " + purify.sanitize(userAgent));
  res.status(500).send("Error logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_4(req, res) {
  const ipAddress = req.ip;
  const action = req.query.action;
  // ok: js-log-injection-ide
  console.warn(`User from IP ${encodeURIComponent(ipAddress)} attempted action: ${encodeURIComponent(action)}`);
  res.send("Action logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_5(req, res) {
  const referrer = req.headers.referer;
  // ok: js-log-injection-ide
  logger.debug("Request referred from: " + purify.sanitize(referrer));
  res.send("Referrer logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_6(req, res) {
  const email = req.body.email;
  // ok: js-log-injection-ide
  process.stdout.write(`User registration attempt with email: ${encodeURIComponent(email)}\n`);
  res.send("Registration logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_7(req, res) {
  const errorMessage = req.query.error;
  // Using a custom sanitization function
  const sanitizeForLog = (input) => {
    return input.replace(/[\r\n\t]/g, ' ');
  };
  // ok: js-log-injection-ide
  console.log("Error reported by user: " + sanitizeForLog(errorMessage));
  res.send("Error logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_8(req, res) {
  const productId = req.params.id;
  const userId = req.cookies.userId;
  // ok: js-log-injection-ide
  logger.info(`User ${encodeURIComponent(userId)} viewed product ${encodeURIComponent(productId)}`);
  res.send("Product view logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_9(req, res) {
  // Using JSON.stringify for objects is safe as it escapes special characters
  const safeFormData = {};
  for (const key in req.body) {
    safeFormData[key] = typeof req.body[key] === 'string' ? 
      encodeURIComponent(req.body[key]) : req.body[key];
  }
  // ok: js-log-injection-ide
  console.log("Form submission data: " + JSON.stringify(safeFormData));
  res.send("Form submission logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_10(req, res) {
  const authToken = req.headers.authorization;
  // Only log a portion of the token for security
  const tokenPreview = authToken ? authToken.substring(0, 10) + '...' : 'none';
  // ok: js-log-injection-ide
  logger.warn(`Failed authentication attempt with token preview: ${encodeURIComponent(tokenPreview)}`);
  res.status(401).send("Unauthorized");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_11(req, res) {
  const queryParams = req.url.split('?')[1] || '';
  // ok: js-log-injection-ide
  console.log("Request received with query parameters: " + purify.sanitize(queryParams));
  res.send("Request logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_12(req, res) {
  const username = req.body.username;
  // Using a regular expression to remove potentially dangerous characters
  const safeUsername = username.replace(/[^\w\s]/gi, '');
  // ok: js-log-injection-ide
  logger.info("Login attempt by: " + safeUsername);
  res.send("Login attempt processed safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_13(req, res) {
  let userInput = '';
  for (const key in req.query) {
    userInput += `${encodeURIComponent(key)}=${encodeURIComponent(req.query[key])}, `;
  }
  // ok: js-log-injection-ide
  console.log("Received parameters: " + userInput);
  res.send("Parameters logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_14(req, res) {
  const commentText = req.body.comment;
  if (commentText.length > 0) {
    // ok: js-log-injection-ide
    logger.info(`New comment posted: ${purify.sanitize(commentText)}`);
  }
  res.send("Comment logged safely");
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_15(req, res) {
  try {
    throw new Error("Process failed");
  } catch (error) {
    const errorContext = req.query.context || 'unknown';
    // ok: js-log-injection-ide
    console.error(`Error occurred in context ${encodeURIComponent(errorContext)}: ${error.message}`);
    res.status(500).send("Error logged safely");
  }
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;