const express = require('express');
const xpath = require('xpath');
const dom = require('xmldom').DOMParser;
const libxmljs = require('libxmljs');
const sanitizeXPath = require('xpath-sanitizer');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// XML document for testing
const xmlString = `
<users>
  <user id="1">
    <username>admin</username>
    <password>admin123</password>
    <role>administrator</role>
  </user>
  <user id="2">
    <username>john</username>
    <password>john123</password>
    <role>user</role>
  </user>
</users>
`;

// True Positive Examples (Vulnerable Code)

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_1(req, res) {
  const username = req.query.username;
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const nodes = xpath.select(`//user[username='${username}']`, doc);
  
  if (nodes.length > 0) {
    res.send(`User found: ${nodes[0].toString()}`);
  } else {
    res.send('User not found');
  }
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_2(req, res) {
  const userId = req.body.id;
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const result = xpath.select(`//user[@id='${userId}']/role/text()`, doc);
  
  res.send(`User role: ${result}`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_3(req, res) {
  const role = req.params.role;
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const users = xpath.select(`//user[role='${role}']`, doc);
  
  const userList = [];
  for (let i = 0; i < users.length; i++) {
    userList.push(users[i].toString());
  }
  
  res.json(userList);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_4(req, res) {
  const searchField = req.query.field || 'username';
  const searchValue = req.query.value || '';
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const query = `/users/user[${searchField}='${searchValue}']`;
  const result = xpath.select(query, doc);
  
  res.send(`Found ${result.length} matching users`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_5(req, res) {
  const userInput = req.headers['x-search-query'];
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const results = xpath.select(`//user[contains(username, '${userInput}')]`, doc);
  
  res.json({ count: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_6(req, res) {
  const attribute = req.query.attr;
  const value = req.query.value;
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const xpathQuery = `//user[@${attribute}='${value}']`;
  const nodes = xpath.select(xpathQuery, doc);
  
  res.send(`Found ${nodes.length} users`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_7(req, res) {
  const cookie = req.cookies.searchTerm;
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const results = xpath.select(`/users/user[username='${cookie}']`, doc);
  
  res.json(results.map(node => node.toString()));
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_8(req, res) {
  let operator = req.query.operator || '=';
  let searchValue = req.query.value || '';
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const nodes = xpath.select(`//user[username${operator}'${searchValue}']`, doc);
  
  res.send(`Found ${nodes.length} results`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_9(req, res) {
  const userInput = req.body.xpath || '';
  const doc = new dom().parseFromString(xmlString);
  
  try {
    // ruleid: javascript-xpath-injection
    const results = xpath.select(userInput, doc);
    res.json({ results: results.length });
  } catch (error) {
    res.status(400).send('Invalid XPath query');
  }
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_10(req, res) {
  const field1 = req.query.field1;
  const value1 = req.query.value1;
  const field2 = req.query.field2;
  const value2 = req.query.value2;
  const doc = new dom().parseFromString(xmlString);
  
  // ruleid: javascript-xpath-injection
  const query = `//user[${field1}='${value1}' and ${field2}='${value2}']`;
  const results = xpath.select(query, doc);
  
  res.json({ count: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_11(req, res) {
  const xmlDoc = libxmljs.parseXml(xmlString);
  const username = req.query.username;
  
  // ruleid: javascript-xpath-injection
  const nodes = xmlDoc.find(`//user[username='${username}']`);
  
  res.send(`Found ${nodes.length} users`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_12(req, res) {
  const doc = new dom().parseFromString(xmlString);
  const searchTerms = JSON.parse(req.body.searchTerms);
  let query = '//user[';
  
  for (let i = 0; i < searchTerms.length; i++) {
    if (i > 0) query += ' and ';
    query += `${searchTerms[i].field}='${searchTerms[i].value}'`;
  }
  query += ']';
  
  // ruleid: javascript-xpath-injection
  const results = xpath.select(query, doc);
  
  res.json({ results: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_13(req, res) {
  const doc = new dom().parseFromString(xmlString);
  const searchType = req.query.type;
  const searchValue = req.query.value;
  
  let xpathQuery;
  if (searchType === 'id') {
    // ruleid: javascript-xpath-injection
    xpathQuery = `//user[@id='${searchValue}']`;
  } else {
    // ruleid: javascript-xpath-injection
    xpathQuery = `//user[${searchType}='${searchValue}']`;
  }
  
  const results = xpath.select(xpathQuery, doc);
  res.send(`Found ${results.length} results`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_14(req, res) {
  const userRole = req.query.role;
  const doc = new dom().parseFromString(xmlString);
  
  // Template literal with expression
  // ruleid: javascript-xpath-injection
  const query = `//user[role=${userRole ? `'${userRole}'` : "'user'"}]`;
  const results = xpath.select(query, doc);
  
  res.json({ count: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=1}
function bad_case_15(req, res) {
  const doc = new dom().parseFromString(xmlString);
  const userInput = req.query.q;
  
  // String concatenation
  // ruleid: javascript-xpath-injection
  const xpathQuery = "//user[username='" + userInput + "']";
  const results = xpath.select(xpathQuery, doc);
  
  res.send(`Found ${results.length} users`);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_1(req, res) {
  const username = req.query.username;
  const doc = new dom().parseFromString(xmlString);
  
  // ok: javascript-xpath-injection
  const nodes = xpath.select("//user", doc);
  
  const filteredNodes = nodes.filter(node => {
    const usernameNode = xpath.select("username/text()", node)[0];
    return usernameNode && usernameNode.nodeValue === username;
  });
  
  res.send(`Found ${filteredNodes.length} users`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_2(req, res) {
  const userId = req.body.id;
  const doc = new dom().parseFromString(xmlString);
  
  // Using numeric comparison for IDs
  // ok: javascript-xpath-injection
  const result = xpath.select(`//user`, doc).filter(node => {
    const id = node.getAttribute('id');
    return id === userId;
  });
  
  res.send(`User found: ${result.length > 0}`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_3(req, res) {
  const doc = new dom().parseFromString(xmlString);
  
  // ok: javascript-xpath-injection
  const users = xpath.select("//user", doc);
  
  // Filter after query
  const role = req.params.role;
  const matchingUsers = users.filter(user => {
    const userRole = xpath.select("role/text()", user)[0];
    return userRole && userRole.nodeValue === role;
  });
  
  res.json({ count: matchingUsers.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_4(req, res) {
  const searchValue = req.query.value || '';
  const doc = new dom().parseFromString(xmlString);
  
  // ok: javascript-xpath-injection
  const allUsers = xpath.select("//user", doc);
  const matchingUsers = allUsers.filter(user => {
    const username = xpath.select("username/text()", user)[0];
    return username && username.nodeValue.includes(searchValue);
  });
  
  res.send(`Found ${matchingUsers.length} matching users`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_5(req, res) {
  const userInput = req.headers['x-search-query'];
  const doc = new dom().parseFromString(xmlString);
  
  // Using a sanitizer library
  // ok: javascript-xpath-injection
  const sanitizedInput = sanitizeXPath(userInput);
  const results = xpath.select(`//user[contains(username, '${sanitizedInput}')]`, doc);
  
  res.json({ count: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_6(req, res) {
  const doc = new dom().parseFromString(xmlString);
  
  // Using parameterized XPath with allowed values only
  const allowedAttributes = ['id', 'role'];
  const attribute = req.query.attr;
  const value = req.query.value;
  
  if (!allowedAttributes.includes(attribute)) {
    return res.status(400).send('Invalid attribute');
  }
  
  // ok: javascript-xpath-injection
  let nodes;
  if (attribute === 'id') {
    nodes = xpath.select(`//user[@id='${value}']`, doc);
  } else {
    nodes = xpath.select(`//user[role='${value}']`, doc);
  }
  
  res.send(`Found ${nodes.length} users`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_7(req, res) {
  const cookie = req.cookies.searchTerm;
  const doc = new dom().parseFromString(xmlString);
  
  // Using a whitelist of allowed values
  const allowedSearchTerms = ['admin', 'john', 'user'];
  
  if (!allowedSearchTerms.includes(cookie)) {
    return res.status(400).send('Invalid search term');
  }
  
  // ok: javascript-xpath-injection
  const results = xpath.select(`/users/user[username='${cookie}']`, doc);
  
  res.json(results.map(node => node.toString()));
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_8(req, res) {
  const searchValue = req.query.value || '';
  const doc = new dom().parseFromString(xmlString);
  
  // Using a regex to validate input
  if (!/^[a-zA-Z0-9]+$/.test(searchValue)) {
    return res.status(400).send('Invalid search value');
  }
  
  // ok: javascript-xpath-injection
  const nodes = xpath.select(`//user[username='${searchValue}']`, doc);
  
  res.send(`Found ${nodes.length} results`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_9(req, res) {
  const doc = new dom().parseFromString(xmlString);
  
  // Using predefined queries only
  const queryType = req.body.type;
  let xpathQuery;
  
  switch (queryType) {
    case 'admins':
      // ok: javascript-xpath-injection
      xpathQuery = "//user[role='administrator']";
      break;
    case 'users':
      // ok: javascript-xpath-injection
      xpathQuery = "//user[role='user']";
      break;
    default:
      // ok: javascript-xpath-injection
      xpathQuery = "//user";
  }
  
  const results = xpath.select(xpathQuery, doc);
  res.json({ results: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_10(req, res) {
  const field1 = req.query.field1;
  const value1 = req.query.value1;
  const doc = new dom().parseFromString(xmlString);
  
  // Using a map of allowed fields
  const allowedFields = {
    'username': true,
    'role': true
  };
  
  if (!allowedFields[field1]) {
    return res.status(400).send('Invalid field');
  }
  
  // Escaping single quotes in the value
  const escapedValue = value1.replace(/'/g, "&apos;");
  
  // ok: javascript-xpath-injection
  const query = `//user[${field1}='${escapedValue}']`;
  const results = xpath.select(query, doc);
  
  res.json({ count: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_11(req, res) {
  const xmlDoc = libxmljs.parseXml(xmlString);
  const username = req.query.username;
  
  // Using a separate variable for each part of the query
  const prefix = "//user[username='";
  const suffix = "']";
  
  // Escape special characters
  const escapedUsername = username
    .replace(/'/g, "&apos;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  
  // ok: javascript-xpath-injection
  const nodes = xmlDoc.find(prefix + escapedUsername + suffix);
  
  res.send(`Found ${nodes.length} users`);
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_12(req, res) {
  const doc = new dom().parseFromString(xmlString);
  
  // Using hardcoded XPath query
  // ok: javascript-xpath-injection
  const results = xpath.select("//user[role='administrator']", doc);
  
  res.json({ adminCount: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_13(req, res) {
  const doc = new dom().parseFromString(xmlString);
  const userId = req.query.id;
  
  // Validate that ID is numeric
  if (!/^\d+$/.test(userId)) {
    return res.status(400).send('ID must be numeric');
  }
  
  // ok: javascript-xpath-injection
  const results = xpath.select(`//user[@id='${userId}']`, doc);
  
  res.json(results.map(node => node.toString()));
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_14(req, res) {
  const doc = new dom().parseFromString(xmlString);
  
  // Using a prepared statement pattern
  const preparedQueries = {
    findById: (id) => `//user[@id='${id}']`,
    findByRole: (role) => `//user[role='${role}']`,
    findByUsername: (username) => `//user[username='${username}']`
  };
  
  const queryType = req.query.type;
  const queryValue = req.query.value;
  
  // Validate query type
  if (!preparedQueries[queryType]) {
    return res.status(400).send('Invalid query type');
  }
  
  // Validate query value
  if (!/^[a-zA-Z0-9]+$/.test(queryValue)) {
    return res.status(400).send('Invalid query value');
  }
  
  // ok: javascript-xpath-injection
  const results = xpath.select(preparedQueries[queryType](queryValue), doc);
  
  res.json({ count: results.length });
}
// {/fact}

// {fact rule=xpath-injection@v1.0 defects=0}
function good_case_15(req, res) {
  const doc = new dom().parseFromString(xmlString);
  const searchTerm = req.query.q;
  
  // Using a custom sanitization function
  function sanitizeXPathValue(input) {
    if (typeof input !== 'string') return '';
    return input.replace(/['"<>&]/g, '');
  }
  
  const sanitizedTerm = sanitizeXPathValue(searchTerm);
  
  // ok: javascript-xpath-injection
  const xpathQuery = `//user[contains(username, '${sanitizedTerm}')]`;
  const results = xpath.select(xpathQuery, doc);
  
  res.send(`Found ${results.length} users`);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});