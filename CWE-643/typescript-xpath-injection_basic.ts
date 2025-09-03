import * as http from 'http';
import * as url from 'url';
import * as xpath from 'xpath';
import { DOMParser } from 'xmldom';
import * as express from 'express';
import * as sanitizeXml from 'sanitize-xml-string';
import * as escapeXpathString from 'escape-xpath-string';

// XML document for testing
const xmlDoc = `
<users>
  <user id="1">
    <username>admin</username>
    <password>adminpass</password>
    <role>administrator</role>
  </user>
  <user id="2">
    <username>user</username>
    <password>userpass</password>
    <role>regular</role>
  </user>
</users>
`;

// Helper function to parse XML
function parseXml(xml: string) {
  return new DOMParser().parseFromString(xml);
}

// True Positives (Vulnerable Code)

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_1() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const username = parsedUrl.query.username as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const query = xpath.select(`//user[username='${username}']`, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ results: query.length }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/user', (req, res) => {
    const username = req.query.username as string;
    const password = req.query.password as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const nodes = xpath.select(`//user[username='${username}' and password='${password}']`, doc);
    
    if (nodes.length > 0) {
      res.send({ authenticated: true });
    } else {
      res.send({ authenticated: false });
    }
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_3() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const role = parsedUrl.query.role as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const users = xpath.select(`//user[role='${role}']`, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ users }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.post('/search', express.json(), (req, res) => {
    const searchTerm = req.body.term;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const results = xpath.select(`//*[contains(., '${searchTerm}')]`, doc);
    
    res.json({ results: results.length });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_5() {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      const userId = data.id;
      
      const doc = parseXml(xmlDoc);
      // ruleid: typescript-xpath-injection
      const user = xpath.select(`//user[@id='${userId}']`, doc);
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ user }));
    });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.get('/users', (req, res) => {
    const attribute = req.query.attribute as string;
    const value = req.query.value as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const results = xpath.select(`//user[${attribute}='${value}']`, doc);
    
    res.json({ results });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_7() {
  const server = http.createServer((req, res) => {
    const headers = req.headers;
    const userAgent = headers['user-agent'] as string;
    
    // Log user agent in XML format for analytics
    const logXml = `<log><entry>${userAgent}</entry></log>`;
    const doc = parseXml(logXml);
    
    // ruleid: typescript-xpath-injection
    const entry = xpath.select(`//entry[text()='${userAgent}']`, doc);
    
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Logged');
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/filter', (req, res) => {
    const filter = req.query.filter as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const query = `//user[${filter}]`;
    const results = xpath.select(query, doc);
    
    res.json({ results: results.length });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_9() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie?.split(';') || [];
    let sessionId = '';
    
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'sessionId') {
        sessionId = value;
        break;
      }
    }
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const user = xpath.select(`//user[session='${sessionId}']`, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.get('/xpath', (req, res) => {
    const path = req.query.path as string;
    
    const doc = parseXml(xmlDoc);
    try {
      // ruleid: typescript-xpath-injection
      const results = xpath.select(path, doc);
      res.json({ results });
    } catch (error) {
      res.status(400).json({ error: 'Invalid XPath query' });
    }
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/complex-query', (req, res) => {
    const username = req.query.username as string;
    const role = req.query.role as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const query = `//user[username='${username}' or role='${role}']`;
    const results = xpath.select(query, doc);
    
    res.json({ results: results.length });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_12() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const searchField = parsedUrl.query.field as string;
    const searchValue = parsedUrl.query.value as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const dynamicQuery = `//user[${searchField}='${searchValue}']`;
    const results = xpath.select(dynamicQuery, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ count: results.length }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/attribute-search', (req, res) => {
    const attrName = req.query.attr as string;
    const attrValue = req.query.value as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const results = xpath.select(`//user[@${attrName}='${attrValue}']`, doc);
    
    res.json({ results });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_14() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const operator = parsedUrl.query.operator as string; // could be > < = etc.
    const value = parsedUrl.query.value as string;
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const query = `//user[id${operator}'${value}']`;
    const results = xpath.select(query, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ results }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.post('/advanced-search', express.json(), (req, res) => {
    const conditions = req.body.conditions as Array<{field: string, value: string}>;
    
    let xpathQuery = '//user[';
    for (let i = 0; i < conditions.length; i++) {
      if (i > 0) xpathQuery += ' and ';
      xpathQuery += `${conditions[i].field}='${conditions[i].value}'`;
    }
    xpathQuery += ']';
    
    const doc = parseXml(xmlDoc);
    // ruleid: typescript-xpath-injection
    const results = xpath.select(xpathQuery, doc);
    
    res.json({ results });
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_1() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const username = parsedUrl.query.username as string;
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const query = xpath.select("//user", doc).filter((node: any) => {
      const usernameNode = xpath.select("username/text()", node);
      return usernameNode.length > 0 && usernameNode[0].nodeValue === username;
    });
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ results: query.length }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/user', (req, res) => {
    const username = req.query.username as string;
    const password = req.query.password as string;
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const escapedUsername = escapeXpathString(username);
    const escapedPassword = escapeXpathString(password);
    const nodes = xpath.select(`//user[username=${escapedUsername} and password=${escapedPassword}]`, doc);
    
    if (nodes.length > 0) {
      res.send({ authenticated: true });
    } else {
      res.send({ authenticated: false });
    }
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_3() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const role = parsedUrl.query.role as string;
    
    // Validate input against allowed values
    const allowedRoles = ['administrator', 'regular', 'guest'];
    if (!allowedRoles.includes(role)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid role' }));
      return;
    }
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const users = xpath.select(`//user[role='${role}']`, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ users }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.post('/search', express.json(), (req, res) => {
    const searchTerm = req.body.term;
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const escapedTerm = escapeXpathString(searchTerm);
    const results = xpath.select(`//*[contains(., ${escapedTerm})]`, doc);
    
    res.json({ results: results.length });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_5() {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      const data = JSON.parse(body);
      const userId = data.id;
      
      // Validate userId is numeric
      if (!/^\d+$/.test(userId)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid user ID' }));
        return;
      }
      
      const doc = parseXml(xmlDoc);
      // ok: typescript-xpath-injection
      const user = xpath.select(`//user[@id='${userId}']`, doc);
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ user }));
    });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.get('/users', (req, res) => {
    const attribute = req.query.attribute as string;
    const value = req.query.value as string;
    
    // Whitelist allowed attributes
    const allowedAttributes = ['username', 'role'];
    if (!allowedAttributes.includes(attribute)) {
      return res.status(400).json({ error: 'Invalid attribute' });
    }
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const escapedValue = escapeXpathString(value);
    const results = xpath.select(`//user[${attribute}=${escapedValue}]`, doc);
    
    res.json({ results });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_7() {
  const server = http.createServer((req, res) => {
    const headers = req.headers;
    const userAgent = headers['user-agent'] as string;
    
    // Sanitize user agent for XML
    const sanitizedUserAgent = sanitizeXml(userAgent);
    
    // Log user agent in XML format for analytics
    const logXml = `<log><entry>${sanitizedUserAgent}</entry></log>`;
    const doc = parseXml(logXml);
    
    // ok: typescript-xpath-injection
    const escapedUserAgent = escapeXpathString(userAgent);
    const entry = xpath.select(`//entry[text()=${escapedUserAgent}]`, doc);
    
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Logged');
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/filter', (req, res) => {
    const filter = req.query.filter as string;
    
    // Predefined filters only
    const allowedFilters: {[key: string]: string} = {
      'admin': "role='administrator'",
      'user': "role='regular'",
      'recent': "id>1"
    };
    
    if (!Object.keys(allowedFilters).includes(filter)) {
      return res.status(400).json({ error: 'Invalid filter' });
    }
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const query = `//user[${allowedFilters[filter]}]`;
    const results = xpath.select(query, doc);
    
    res.json({ results: results.length });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_9() {
  const server = http.createServer((req, res) => {
    const cookies = req.headers.cookie?.split(';') || [];
    let sessionId = '';
    
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'sessionId') {
        sessionId = value;
        break;
      }
    }
    
    // Validate session ID format (e.g., UUID)
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid session ID' }));
      return;
    }
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const user = xpath.select(`//user[session='${sessionId}']`, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.get('/xpath', (req, res) => {
    // Only allow predefined XPath queries
    const allowedQueries: {[key: string]: string} = {
      'all-users': '//user',
      'admins': '//user[role="administrator"]',
      'regular-users': '//user[role="regular"]'
    };
    
    const queryKey = req.query.query as string;
    if (!Object.keys(allowedQueries).includes(queryKey)) {
      return res.status(400).json({ error: 'Invalid query' });
    }
    
    const doc = parseXml(xmlDoc);
    try {
      // ok: typescript-xpath-injection
      const results = xpath.select(allowedQueries[queryKey], doc);
      res.json({ results });
    } catch (error) {
      res.status(400).json({ error: 'Invalid XPath query' });
    }
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/complex-query', (req, res) => {
    const username = req.query.username as string;
    const role = req.query.role as string;
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const escapedUsername = escapeXpathString(username);
    const escapedRole = escapeXpathString(role);
    const query = `//user[username=${escapedUsername} or role=${escapedRole}]`;
    const results = xpath.select(query, doc);
    
    res.json({ results: results.length });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_12() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const searchField = parsedUrl.query.field as string;
    const searchValue = parsedUrl.query.value as string;
    
    // Whitelist allowed fields
    const allowedFields = ['username', 'role', 'id'];
    if (!allowedFields.includes(searchField)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid search field' }));
      return;
    }
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const escapedValue = escapeXpathString(searchValue);
    const dynamicQuery = `//user[${searchField}=${escapedValue}]`;
    const results = xpath.select(dynamicQuery, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ count: results.length }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/attribute-search', (req, res) => {
    const attrName = req.query.attr as string;
    const attrValue = req.query.value as string;
    
    // Whitelist allowed attributes
    const allowedAttributes = ['id', 'type'];
    if (!allowedAttributes.includes(attrName)) {
      return res.status(400).json({ error: 'Invalid attribute name' });
    }
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const escapedValue = escapeXpathString(attrValue);
    const results = xpath.select(`//user[@${attrName}=${escapedValue}]`, doc);
    
    res.json({ results });
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_14() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const operator = parsedUrl.query.operator as string;
    const value = parsedUrl.query.value as string;
    
    // Whitelist allowed operators
    const allowedOperators = ['=', '<', '>', '<=', '>='];
    if (!allowedOperators.includes(operator)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid operator' }));
      return;
    }
    
    // Validate value is numeric
    if (!/^\d+$/.test(value)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid value' }));
      return;
    }
    
    const doc = parseXml(xmlDoc);
    // ok: typescript-xpath-injection
    const query = `//user[id${operator}'${value}']`;
    const results = xpath.select(query, doc);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ results }));
  });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.post('/advanced-search', express.json(), (req, res) => {
    const conditions = req.body.conditions as Array<{field: string, value: string}>;
    
    // Whitelist allowed fields
    const allowedFields = ['username', 'role', 'id'];
    
    let xpathQuery = '//user[';
    for (let i = 0; i < conditions.length; i++) {
      if (!allowedFields.includes(conditions[i].field)) {
        return res.status(400).json({ error: 'Invalid field' });
      }
      
      if (i > 0) xpathQuery += ' and ';
      // ok: typescript-xpath-injection
      const escapedValue = escapeXpathString(conditions[i].value);
      xpathQuery += `${conditions[i].field}=${escapedValue}`;
    }
    xpathQuery += ']';
    
    const doc = parseXml(xmlDoc);
    const results = xpath.select(xpathQuery, doc);
    
    res.json({ results });
  });
}
// {/fact}