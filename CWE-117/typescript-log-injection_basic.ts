import * as express from 'express';
import * as winston from 'winston';
import * as log4js from 'log4js';
import * as bunyan from 'bunyan';
import * as pino from 'pino';
import { sanitizeLogData } from './sanitizer'; // Hypothetical sanitizer module

// Configure loggers
const winstonLogger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

log4js.configure({
  appenders: { console: { type: 'console' } },
  categories: { default: { appenders: ['console'], level: 'info' } }
});
const log4jsLogger = log4js.getLogger();

const bunyanLogger = bunyan.createLogger({ name: 'app' });
const pinoLogger = pino();

const app = express();
app.use(express.json());

// ==================== TRUE POSITIVES ====================

// Example 1: Basic log injection with console.log
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_1(req: express.Request, res: express.Response) {
  const username = req.query.username;
  // ruleid: typescript-log-injection
  console.log(`User login attempt: ${username}`);
  res.send('Login attempt logged');
}
// {/fact}

// Example 2: Winston logger with unsanitized input
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_2(req: express.Request, res: express.Response) {
  const searchTerm = req.query.q as string;
  // ruleid: typescript-log-injection
  winstonLogger.info(`Search query executed: ${searchTerm}`);
  res.send('Search logged');
}
// {/fact}

// Example 3: Log4js with template literal containing user input
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_3(req: express.Request, res: express.Response) {
  const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  // ruleid: typescript-log-injection
  log4jsLogger.info(`Connection from IP: ${ipAddress}`);
  res.send('Connection logged');
}
// {/fact}

// Example 4: Bunyan logger with user input in object
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_4(req: express.Request, res: express.Response) {
  const userId = req.params.id;
  // ruleid: typescript-log-injection
  bunyanLogger.info({ event: 'user_access', userId: userId, message: `User ${userId} accessed the system` });
  res.send('Access logged');
}
// {/fact}

// Example 5: Pino logger with user input
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_5(req: express.Request, res: express.Response) {
  const errorMessage = req.query.error as string;
  // ruleid: typescript-log-injection
  pinoLogger.error(`Client reported error: ${errorMessage}`);
  res.status(400).send('Error logged');
}
// {/fact}

// Example 6: Console error with user input
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_6(req: express.Request, res: express.Response) {
  const failedEndpoint = req.path;
  // ruleid: typescript-log-injection
  console.error(`Failed request to endpoint: ${failedEndpoint}`);
  res.status(404).send('Not found');
}
// {/fact}

// Example 7: Winston logger with multiple user inputs
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_7(req: express.Request, res: express.Response) {
  const { username, action } = req.body;
  // ruleid: typescript-log-injection
  winstonLogger.warn(`User ${username} attempted restricted action: ${action}`);
  res.status(403).send('Unauthorized action');
}
// {/fact}

// Example 8: Log4js with user input in conditional
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_8(req: express.Request, res: express.Response) {
  const userAgent = req.headers['user-agent'];
  if (userAgent && userAgent.includes('Bot')) {
    // ruleid: typescript-log-injection
    log4jsLogger.warn(`Potential bot detected with user-agent: ${userAgent}`);
  }
  res.send('Request processed');
}
// {/fact}

// Example 9: Bunyan with user input in array iteration
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_9(req: express.Request, res: express.Response) {
  const items = req.body.items as string[];
  items.forEach(item => {
    // ruleid: typescript-log-injection
    bunyanLogger.info(`Processing item: ${item}`);
  });
  res.send('Items processed');
}
// {/fact}

// Example 10: Pino with user input in try/catch
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_10(req: express.Request, res: express.Response) {
  try {
    const data = JSON.parse(req.body.data);
    res.json(data);
  } catch (error) {
    // ruleid: typescript-log-injection
    pinoLogger.error(`Error parsing JSON from user: ${req.body.data}`);
    res.status(400).send('Invalid JSON');
  }
}
// {/fact}

// Example 11: Console log with user input in promise chain
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_11(req: express.Request, res: express.Response) {
  const orderId = req.params.orderId;
  Promise.resolve(orderId)
    .then(id => {
      // ruleid: typescript-log-injection
      console.log(`Order processed: ${id}`);
      res.send('Order processed');
    })
    .catch(err => res.status(500).send('Error'));
}
// {/fact}

// Example 12: Winston with user input in async function
// {fact rule=ldap-injection@v1.0 defects=1}
async function bad_case_12(req: express.Request, res: express.Response) {
  const email = req.body.email;
  try {
    // Some async operation
    await new Promise(resolve => setTimeout(resolve, 100));
    // ruleid: typescript-log-injection
    winstonLogger.info(`Password reset requested for: ${email}`);
    res.send('Password reset email sent');
  } catch (error) {
    res.status(500).send('Error');
  }
}
// {/fact}

// Example 13: Log4js with user input in switch statement
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_13(req: express.Request, res: express.Response) {
  const action = req.query.action as string;
  switch (action) {
    case 'login':
      // ruleid: typescript-log-injection
      log4jsLogger.info(`Login action performed by user: ${req.query.username}`);
      break;
    case 'logout':
      // ruleid: typescript-log-injection
      log4jsLogger.info(`Logout action performed by user: ${req.query.username}`);
      break;
    default:
      // ruleid: typescript-log-injection
      log4jsLogger.info(`Unknown action '${action}' performed by user: ${req.query.username}`);
  }
  res.send('Action logged');
}
// {/fact}

// Example 14: Bunyan with user input in object destructuring
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
  const { username, role } = req.body;
  // ruleid: typescript-log-injection
  bunyanLogger.info(`Role change for user ${username} to ${role}`);
  res.send('Role updated');
}
// {/fact}

// Example 15: Pino with template literal containing multiple user inputs
// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
  const { from, to, message } = req.body;
  // ruleid: typescript-log-injection
  pinoLogger.info(`Message from ${from} to ${to}: ${message}`);
  res.send('Message sent');
}
// {/fact}

// ==================== TRUE NEGATIVES ====================

// Example 1: Console log with sanitized input
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_1(req: express.Request, res: express.Response) {
  const username = req.query.username as string;
  const sanitizedUsername = sanitizeLogData(username);
  // ok: typescript-log-injection
  console.log(`User login attempt: ${sanitizedUsername}`);
  res.send('Login attempt logged');
}
// {/fact}

// Example 2: Winston logger with sanitized input
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_2(req: express.Request, res: express.Response) {
  const searchTerm = req.query.q as string;
  const sanitizedSearchTerm = sanitizeLogData(searchTerm);
  // ok: typescript-log-injection
  winstonLogger.info(`Search query executed: ${sanitizedSearchTerm}`);
  res.send('Search logged');
}
// {/fact}

// Example 3: Log4js with sanitized user input
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_3(req: express.Request, res: express.Response) {
  const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const sanitizedIp = sanitizeLogData(ipAddress as string);
  // ok: typescript-log-injection
  log4jsLogger.info(`Connection from IP: ${sanitizedIp}`);
  res.send('Connection logged');
}
// {/fact}

// Example 4: Bunyan logger with sanitized object
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_4(req: express.Request, res: express.Response) {
  const userId = req.params.id;
  const sanitizedUserId = sanitizeLogData(userId);
  // ok: typescript-log-injection
  bunyanLogger.info({ 
    event: 'user_access', 
    userId: sanitizedUserId, 
    message: `User ${sanitizedUserId} accessed the system` 
  });
  res.send('Access logged');
}
// {/fact}

// Example 5: Pino logger with sanitized input
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_5(req: express.Request, res: express.Response) {
  const errorMessage = req.query.error as string;
  const sanitizedError = sanitizeLogData(errorMessage);
  // ok: typescript-log-injection
  pinoLogger.error(`Client reported error: ${sanitizedError}`);
  res.status(400).send('Error logged');
}
// {/fact}

// Example 6: Console error with hardcoded values only
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_6(req: express.Request, res: express.Response) {
  // ok: typescript-log-injection
  console.error('Failed request to endpoint');
  res.status(404).send('Not found');
}
// {/fact}

// Example 7: Winston logger with structured logging instead of string interpolation
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_7(req: express.Request, res: express.Response) {
  const { username, action } = req.body;
  // ok: typescript-log-injection
  winstonLogger.warn({
    message: 'User attempted restricted action',
    user: sanitizeLogData(username),
    action: sanitizeLogData(action)
  });
  res.status(403).send('Unauthorized action');
}
// {/fact}

// Example 8: Log4js with regex validation before logging
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_8(req: express.Request, res: express.Response) {
  const userAgent = req.headers['user-agent'] as string;
  if (userAgent && userAgent.includes('Bot')) {
    // Validate user agent with regex to ensure it only contains safe characters
    if (/^[\w\s\-\.\/\(\);:,]+$/.test(userAgent)) {
      // ok: typescript-log-injection
      log4jsLogger.warn(`Potential bot detected with user-agent: ${userAgent}`);
    } else {
      log4jsLogger.warn('Potential bot detected with invalid user-agent');
    }
  }
  res.send('Request processed');
}
// {/fact}

// Example 9: Bunyan with mapped sanitized values
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_9(req: express.Request, res: express.Response) {
  const items = req.body.items as string[];
  const sanitizedItems = items.map(item => sanitizeLogData(item));
  sanitizedItems.forEach(item => {
    // ok: typescript-log-injection
    bunyanLogger.info(`Processing item: ${item}`);
  });
  res.send('Items processed');
}
// {/fact}

// Example 10: Pino with JSON.stringify and sanitization
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_10(req: express.Request, res: express.Response) {
  try {
    const data = JSON.parse(req.body.data);
    res.json(data);
  } catch (error) {
    const sanitizedData = sanitizeLogData(req.body.data);
    // ok: typescript-log-injection
    pinoLogger.error(`Error parsing JSON: ${sanitizedData}`);
    res.status(400).send('Invalid JSON');
  }
}
// {/fact}

// Example 11: Console log with constant values
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_11(req: express.Request, res: express.Response) {
  const orderId = req.params.orderId;
  Promise.resolve(orderId)
    .then(id => {
      // ok: typescript-log-injection
      console.log('Order processed successfully');
      res.send('Order processed');
    })
    .catch(err => res.status(500).send('Error'));
}
// {/fact}

// Example 12: Winston with separate fields for structured logging
// {fact rule=ldap-injection@v1.0 defects=0}
async function good_case_12(req: express.Request, res: express.Response) {
  const email = req.body.email;
  try {
    // Some async operation
    await new Promise(resolve => setTimeout(resolve, 100));
    // ok: typescript-log-injection
    winstonLogger.info({
      message: 'Password reset requested',
      email: sanitizeLogData(email)
    });
    res.send('Password reset email sent');
  } catch (error) {
    res.status(500).send('Error');
  }
}
// {/fact}

// Example 13: Log4js with enum validation
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_13(req: express.Request, res: express.Response) {
  enum ValidActions {
    LOGIN = 'login',
    LOGOUT = 'logout'
  }
  
  const action = req.query.action as string;
  const username = sanitizeLogData(req.query.username as string);
  
  // Validate action is one of the allowed values
  const validatedAction = Object.values(ValidActions).includes(action as ValidActions) 
    ? action 
    : 'unknown';
  
  // ok: typescript-log-injection
  log4jsLogger.info(`${validatedAction} action performed by user: ${username}`);
  res.send('Action logged');
}
// {/fact}

// Example 14: Bunyan with numeric or validated input only
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
  const userId = parseInt(req.params.id, 10);
  // Numeric values are safe from log injection
  // ok: typescript-log-injection
  bunyanLogger.info(`User ID accessed: ${userId}`);
  res.send('User accessed');
}
// {/fact}

// Example 15: Pino with constant message and metadata object
// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_15(req: express.Request, res: express.Response) {
  const { from, to, message } = req.body;
  // ok: typescript-log-injection
  pinoLogger.info({
    event: 'message_sent',
    sender: sanitizeLogData(from),
    recipient: sanitizeLogData(to),
    content: sanitizeLogData(message)
  });
  res.send('Message sent');
}
// {/fact}

export default app;