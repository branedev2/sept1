// Import required modules
const express = require('express');
const mysql = require('mysql');
const mysql2 = require('mysql2');
const { Client } = require('pg');
const sqlite3 = require('sqlite3');
const sanitizeHtml = require('sanitize-html');
const validator = require('validator');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection setup
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'mydb'
});

const connection2 = mysql2.createConnection({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'mydb'
});

const pgClient = new Client({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'mydb'
});

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
  const userId = req.params.id;
  // Direct use of user input in SQL query
  // ruleid: javascript-unsanitized-query
  connection.query(`SELECT * FROM users WHERE id = ${userId}`, (err, results) => {
    if (err) {
      res.status(500).send('Error fetching user data');
      return;
    }
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
  const searchTerm = req.query.search;
  // String concatenation with user input
  // ruleid: javascript-unsanitized-query
  connection.query("SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'", (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
  const { username, password } = req.body;
  // Multiple unsanitized inputs in query
  // ruleid: javascript-unsanitized-query
  connection.query(`SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
  const category = req.query.category;
  const minPrice = req.query.minPrice;
  // Template literal with multiple inputs
  // ruleid: javascript-unsanitized-query
  connection.query(`SELECT * FROM products WHERE category = '${category}' AND price > ${minPrice}`, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
  const sortField = req.query.sort || 'id';
  const sortOrder = req.query.order || 'ASC';
  // Unsanitized input used for sorting
  // ruleid: javascript-unsanitized-query
  connection.query(`SELECT * FROM products ORDER BY ${sortField} ${sortOrder}`, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
  const userId = req.cookies.userId;
  // Using cookie data without sanitization
  // ruleid: javascript-unsanitized-query
  connection.query(`DELETE FROM sessions WHERE user_id = ${userId}`, (err, results) => {
    if (err) throw err;
    res.send('Session cleared');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
  const productId = req.params.id;
  const updates = req.body;
  let updateQuery = 'UPDATE products SET ';
  
  // Building dynamic query from request body
  Object.keys(updates).forEach((key, index, array) => {
    updateQuery += `${key} = '${updates[key]}'`;
    if (index < array.length - 1) updateQuery += ', ';
  });
  
  updateQuery += ` WHERE id = ${productId}`;
  
  // ruleid: javascript-unsanitized-query
  connection.query(updateQuery, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
  const userAgent = req.headers['user-agent'];
  // Using HTTP header without sanitization
  // ruleid: javascript-unsanitized-query
  connection.query(`INSERT INTO analytics (user_agent, visit_time) VALUES ('${userAgent}', NOW())`, (err, results) => {
    if (err) throw err;
    res.send('Analytics recorded');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
  const referer = req.headers.referer;
  // Using another HTTP header without sanitization
  // ruleid: javascript-unsanitized-query
  connection.query(`INSERT INTO page_visits (referer_url, timestamp) VALUES ('${referer}', NOW())`, (err, results) => {
    if (err) throw err;
    res.send('Visit recorded');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
  const limit = req.query.limit || 10;
  const offset = req.query.offset || 0;
  // Using limit and offset from query params without validation
  // ruleid: javascript-unsanitized-query
  connection.query(`SELECT * FROM products LIMIT ${limit} OFFSET ${offset}`, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
  const tables = req.query.tables.split(',');
  let query = 'SELECT * FROM ';
  
  // Constructing query with user-provided table names
  tables.forEach((table, index) => {
    query += table;
    if (index < tables.length - 1) query += ', ';
  });
  
  // ruleid: javascript-unsanitized-query
  connection.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
  const userId = req.params.id;
  // Using mysql2 connection with unsanitized input
  // ruleid: javascript-unsanitized-query
  connection2.query(`SELECT * FROM users WHERE id = ${userId}`, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
  const searchTerm = req.query.search;
  // Minimal processing that doesn't sanitize
  const processedTerm = searchTerm.toLowerCase();
  
  // ruleid: javascript-unsanitized-query
  connection.query(`SELECT * FROM products WHERE LOWER(name) LIKE '%${processedTerm}%'`, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
  const id = req.params.id;
  // Insufficient sanitization (just trims spaces)
  const trimmedId = id.trim();
  
  // ruleid: javascript-unsanitized-query
  connection.query(`SELECT * FROM users WHERE id = ${trimmedId}`, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
  // Complex object with nested properties from request
  const filters = req.body.filters;
  let query = 'SELECT * FROM products WHERE 1=1';
  
  if (filters.category) {
    query += ` AND category = '${filters.category}'`;
  }
  
  if (filters.price && filters.price.min) {
    query += ` AND price >= ${filters.price.min}`;
  }
  
  if (filters.price && filters.price.max) {
    query += ` AND price <= ${filters.price.max}`;
  }
  
  // ruleid: javascript-unsanitized-query
  connection.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
  const userId = req.params.id;
  // Using parameterized query
  // ok: javascript-unsanitized-query
  connection.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) {
      res.status(500).send('Error fetching user data');
      return;
    }
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
  const searchTerm = req.query.search;
  // Using parameterized query with LIKE
  // ok: javascript-unsanitized-query
  connection.query("SELECT * FROM products WHERE name LIKE ?", [`%${searchTerm}%`], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
  const { username, password } = req.body;
  // Multiple parameters in safe query
  // ok: javascript-unsanitized-query
  connection.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
  const category = req.query.category;
  const minPrice = req.query.minPrice;
  
  // Validating numeric input
  if (isNaN(minPrice)) {
    return res.status(400).send('Invalid price value');
  }
  
  // ok: javascript-unsanitized-query
  connection.query('SELECT * FROM products WHERE category = ? AND price > ?', [category, Number(minPrice)], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
  let sortField = req.query.sort || 'id';
  const sortOrder = req.query.order || 'ASC';
  
  // Whitelist validation for sort field and order
  const allowedFields = ['id', 'name', 'price', 'created_at'];
  const allowedOrders = ['ASC', 'DESC'];
  
  if (!allowedFields.includes(sortField)) sortField = 'id';
  const finalOrder = allowedOrders.includes(sortOrder.toUpperCase()) ? sortOrder : 'ASC';
  
  // ok: javascript-unsanitized-query
  connection.query('SELECT * FROM products ORDER BY ?? ?', [sortField, finalOrder], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
  const userId = req.cookies.userId;
  
  // Validating that userId is a number
  if (!validator.isNumeric(userId)) {
    return res.status(400).send('Invalid user ID');
  }
  
  // ok: javascript-unsanitized-query
  connection.query('DELETE FROM sessions WHERE user_id = ?', [Number(userId)], (err, results) => {
    if (err) throw err;
    res.send('Session cleared');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
  const productId = req.params.id;
  const updates = req.body;
  
  // Creating safe parameter array and query
  const params = [];
  const setValues = [];
  
  Object.keys(updates).forEach(key => {
    setValues.push(`${key} = ?`);
    params.push(updates[key]);
  });
  
  params.push(productId);
  
  // ok: javascript-unsanitized-query
  connection.query(`UPDATE products SET ${setValues.join(', ')} WHERE id = ?`, params, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
  const userAgent = req.headers['user-agent'];
  
  // Sanitizing header input
  const sanitizedUserAgent = sanitizeHtml(userAgent, {
    allowedTags: [],
    allowedAttributes: {}
  });
  
  // ok: javascript-unsanitized-query
  connection.query('INSERT INTO analytics (user_agent, visit_time) VALUES (?, NOW())', [sanitizedUserAgent], (err, results) => {
    if (err) throw err;
    res.send('Analytics recorded');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
  const referer = req.headers.referer || '';
  
  // Using mysql2 with parameterized query
  // ok: javascript-unsanitized-query
  connection2.query('INSERT INTO page_visits (referer_url, timestamp) VALUES (?, NOW())', [referer], (err, results) => {
    if (err) throw err;
    res.send('Visit recorded');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
  let limit = req.query.limit || 10;
  let offset = req.query.offset || 0;
  
  // Converting to numbers and applying constraints
  limit = Math.min(Math.max(1, Number(limit)), 100); // Between 1 and 100
  offset = Math.max(0, Number(offset)); // At least 0
  
  // ok: javascript-unsanitized-query
  connection.query('SELECT * FROM products LIMIT ? OFFSET ?', [limit, offset], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
  const tableInput = req.query.tables || '';
  
  // Whitelist validation for table names
  const allowedTables = ['products', 'categories', 'suppliers'];
  const requestedTables = tableInput.split(',');
  
  const validTables = requestedTables.filter(table => allowedTables.includes(table));
  
  if (validTables.length === 0) {
    return res.status(400).send('No valid tables specified');
  }
  
  // Safely constructing query with validated table names
  const query = `SELECT * FROM ${validTables.join(', ')}`;
  
  // ok: javascript-unsanitized-query
  connection.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
  const userId = req.params.id;
  
  // Using a different database library with parameterized query
  const db = new sqlite3.Database(':memory:');
  
  // ok: javascript-unsanitized-query
  db.all('SELECT * FROM users WHERE id = ?', [userId], (err, rows) => {
    if (err) {
      res.status(500).send('Database error');
      return;
    }
    res.json(rows);
    db.close();
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
  const searchTerm = req.query.search || '';
  
  // Using PostgreSQL client with parameterized query
  // ok: javascript-unsanitized-query
  pgClient.query('SELECT * FROM products WHERE name ILIKE $1', [`%${searchTerm}%`], (err, result) => {
    if (err) {
      res.status(500).send('Database error');
      return;
    }
    res.json(result.rows);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
  const id = req.params.id;
  
  // Comprehensive validation
  if (!id || !validator.isNumeric(id)) {
    return res.status(400).send('Invalid ID format');
  }
  
  const numericId = parseInt(id, 10);
  
  // ok: javascript-unsanitized-query
  connection.query('SELECT * FROM users WHERE id = ?', [numericId], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
  // Complex object with nested properties from request
  const filters = req.body.filters || {};
  const params = [];
  let query = 'SELECT * FROM products WHERE 1=1';
  
  if (filters.category) {
    query += ' AND category = ?';
    params.push(filters.category);
  }
  
  if (filters.price && filters.price.min) {
    query += ' AND price >= ?';
    params.push(Number(filters.price.min));
  }
  
  if (filters.price && filters.price.max) {
    query += ' AND price <= ?';
    params.push(Number(filters.price.max));
  }
  
  // ok: javascript-unsanitized-query
  connection.query(query, params, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});