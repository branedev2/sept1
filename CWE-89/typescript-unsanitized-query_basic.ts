import express from 'express';
import mysql from 'mysql';
import { Request, Response } from 'express';
import { escape, escapeId } from 'mysql';
import * as sanitizer from 'mysql-sanitizer';
import validator from 'validator';

// Database connection setup
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'mydb'
});

// Vulnerable examples (True Positives)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
  const userId = req.query.id;
  
  // Direct injection of user input into query
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
  const username = req.body.username;
  
  // String concatenation with user input
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const limit = req.query.limit || 10;
  
  // Template literal with multiple user inputs
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%' LIMIT ${limit}`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
  const category = req.params.category;
  const sortField = req.query.sort || 'name';
  
  // User input in ORDER BY clause
  const query = `SELECT * FROM products WHERE category = '${category}' ORDER BY ${sortField}`;
  
  // ruleid: typescript-unsanitized-query
  connection.execute(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
  const tableName = req.body.table;
  
  // User input as table name
  const query = `SELECT COUNT(*) FROM ${tableName}`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
  const userId = req.cookies.userId;
  
  // User input from cookies
  const query = `UPDATE users SET last_login = NOW() WHERE id = ${userId}`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
  const userIds = req.body.ids.join(','); // Assuming ids is an array from JSON body
  
  // User input in IN clause
  const query = `SELECT * FROM users WHERE id IN (${userIds})`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
  const token = req.headers.authorization?.split(' ')[1];
  
  // User input from headers
  const query = `SELECT * FROM sessions WHERE token = '${token}'`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
  let conditions = '';
  
  // Building dynamic query based on multiple parameters
  if (req.query.name) {
    conditions += ` AND name LIKE '%${req.query.name}%'`;
  }
  
  if (req.query.category) {
    conditions += ` AND category = '${req.query.category}'`;
  }
  
  const query = `SELECT * FROM products WHERE 1=1${conditions}`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
  const email = req.body.email;
  
  // Partial attempt at sanitization that's still vulnerable
  const sanitizedEmail = email.replace("'", "''");
  const query = `SELECT * FROM users WHERE email = '${sanitizedEmail}'`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
  const fields = req.query.fields as string;
  
  // User input in SELECT clause
  const query = `SELECT ${fields} FROM users`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
  const userId = req.query.id;
  const userData = {
    name: req.body.name,
    email: req.body.email
  };
  
  // String interpolation in UPDATE statement
  let query = `UPDATE users SET `;
  for (const [key, value] of Object.entries(userData)) {
    query += `${key} = '${value}', `;
  }
  query = query.slice(0, -2); // Remove trailing comma and space
  query += ` WHERE id = ${userId}`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
  const searchQuery = req.query.q as string;
  
  // Trying to be clever with backticks but still vulnerable
  const query = `SELECT * FROM products WHERE MATCH(description) AGAINST(\`${searchQuery}\` IN BOOLEAN MODE)`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
  const startDate = req.query.start as string;
  const endDate = req.query.end as string;
  
  // Date range with user input
  const query = `SELECT * FROM orders WHERE order_date BETWEEN '${startDate}' AND '${endDate}'`;
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
  const userId = req.query.id;
  
  // Using a function but still concatenating
  function getUserQuery(id: string) {
    return `SELECT * FROM users WHERE id = ${id}`;
  }
  
  const query = getUserQuery(userId as string);
  
  // ruleid: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Secure examples (True Negatives)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
  const userId = req.query.id;
  
  // Using parameterized query
  const query = "SELECT * FROM users WHERE id = ?";
  
  // ok: typescript-unsanitized-query
  connection.query(query, [userId], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
  const username = req.body.username;
  
  // Using multiple parameters
  const query = "SELECT * FROM users WHERE username = ? AND active = ?";
  
  // ok: typescript-unsanitized-query
  connection.query(query, [username, 1], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const limit = parseInt(req.query.limit as string) || 10;
  
  // Using parameters for LIKE query
  const query = "SELECT * FROM products WHERE name LIKE ? LIMIT ?";
  
  // ok: typescript-unsanitized-query
  connection.query(query, [`%${searchTerm}%`, limit], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
  const category = req.params.category;
  const sortField = req.query.sort as string || 'name';
  
  // Using escapeId for column names
  const query = `SELECT * FROM products WHERE category = ? ORDER BY ${escapeId(sortField)}`;
  
  // ok: typescript-unsanitized-query
  connection.query(query, [category], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
  const tableName = req.body.table;
  
  // Validating table name against whitelist
  const allowedTables = ['users', 'products', 'orders'];
  if (!allowedTables.includes(tableName)) {
    return res.status(400).json({ error: 'Invalid table name' });
  }
  
  const query = `SELECT COUNT(*) FROM ${escapeId(tableName)}`;
  
  // ok: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
  const userId = req.cookies.userId;
  
  // Using escape function
  const query = `UPDATE users SET last_login = NOW() WHERE id = ${escape(userId)}`;
  
  // ok: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
  const userIds = req.body.ids; // Assuming ids is an array from JSON body
  
  // Using parameterized query with IN clause
  const query = "SELECT * FROM users WHERE id IN (?)";
  
  // ok: typescript-unsanitized-query
  connection.query(query, [userIds], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
  const token = req.headers.authorization?.split(' ')[1];
  
  // Using prepared statement
  const query = "SELECT * FROM sessions WHERE token = ?";
  
  // ok: typescript-unsanitized-query
  connection.prepare(query, (err, statement) => {
    if (err) throw err;
    statement.execute([token], (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
  const params: any[] = [];
  let query = "SELECT * FROM products WHERE 1=1";
  
  // Building parameterized query
  if (req.query.name) {
    query += " AND name LIKE ?";
    params.push(`%${req.query.name}%`);
  }
  
  if (req.query.category) {
    query += " AND category = ?";
    params.push(req.query.category);
  }
  
  // ok: typescript-unsanitized-query
  connection.query(query, params, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
  const email = req.body.email;
  
  // Using proper sanitization library
  const sanitizedEmail = sanitizer.sanitize(email);
  const query = "SELECT * FROM users WHERE email = ?";
  
  // ok: typescript-unsanitized-query
  connection.query(query, [sanitizedEmail], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
  const fields = req.query.fields as string;
  
  // Validating fields against whitelist
  const allowedFields = ['id', 'name', 'email', 'created_at'];
  const requestedFields = fields.split(',').filter(field => allowedFields.includes(field));
  
  if (requestedFields.length === 0) {
    requestedFields.push('id'); // Default field
  }
  
  const safeFields = requestedFields.map(field => escapeId(field)).join(', ');
  const query = `SELECT ${safeFields} FROM users`;
  
  // ok: typescript-unsanitized-query
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
  const userId = req.query.id;
  const userData = {
    name: req.body.name,
    email: req.body.email
  };
  
  // Using parameterized query for UPDATE
  const query = "UPDATE users SET ? WHERE id = ?";
  
  // ok: typescript-unsanitized-query
  connection.query(query, [userData, userId], (error, results) => {
    if (error) throw error;
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
  const searchQuery = req.query.q as string;
  
  // Input validation before using in query
  if (!validator.isAlphanumeric(searchQuery.replace(/\s/g, ''))) {
    return res.status(400).json({ error: 'Invalid search query' });
  }
  
  const query = "SELECT * FROM products WHERE MATCH(description) AGAINST(? IN BOOLEAN MODE)";
  
  // ok: typescript-unsanitized-query
  connection.query(query, [searchQuery], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
  const startDate = req.query.start as string;
  const endDate = req.query.end as string;
  
  // Validating date format
  if (!validator.isDate(startDate) || !validator.isDate(endDate)) {
    return res.status(400).json({ error: 'Invalid date format' });
  }
  
  const query = "SELECT * FROM orders WHERE order_date BETWEEN ? AND ?";
  
  // ok: typescript-unsanitized-query
  connection.query(query, [startDate, endDate], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
  const userId = req.query.id;
  
  // Using a function with parameterized query
  function getUserQuery(id: any) {
    return {
      sql: "SELECT * FROM users WHERE id = ?",
      params: [id]
    };
  }
  
  const queryObj = getUserQuery(userId);
  
  // ok: typescript-unsanitized-query
  connection.query(queryObj.sql, queryObj.params, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}