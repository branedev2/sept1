// Import necessary modules for examples
const express = require('express');
const mysql = require('mysql');
const { Sequelize, DataTypes } = require('sequelize');
const knex = require('knex');
const sqlite3 = require('sqlite3');
const pg = require('pg');
const mongodb = require('mongodb');
const sanitizeHtml = require('sanitize-html');
const validator = require('validator');

// MySQL connection setup for examples
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'testdb'
});

// Sequelize setup for examples
const sequelize = new Sequelize('database', 'username', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

// Knex setup for examples
const knexDb = knex({
  client: 'mysql',
  connection: {
    host: 'localhost',
    user: 'user',
    password: 'password',
    database: 'testdb'
  }
});

// PostgreSQL setup for examples
const pgClient = new pg.Client({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'testdb'
});

// MongoDB setup for examples
const mongoClient = new mongodb.MongoClient('mongodb://localhost:27017');

// Express app setup for examples
const app = express();
app.use(express.json());

// ==================== TRUE POSITIVES (VULNERABLE CODE) ====================

// Bad case 1: Direct SQL injection in MySQL query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 2: SQL injection in template literal
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
  const username = req.body.username;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`SELECT * FROM users WHERE username = '${username}'`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 3: SQL injection with string concatenation and minimal processing
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
  let email = req.query.email;
  email = email.toLowerCase();
  const query = "SELECT * FROM users WHERE email = '" + email + "'";
  
  // ruleid: javascript-sql-injection-ide
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 4: SQL injection in Sequelize raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
  const role = req.query.role;
  
  // ruleid: javascript-sql-injection-ide
  sequelize.query(
    "SELECT * FROM users WHERE role = '" + role + "'",
    { type: Sequelize.QueryTypes.SELECT }
  ).then(users => {
    res.json(users);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
}
// {/fact}

// Bad case 5: SQL injection in Knex raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
  const category = req.params.category;
  
  // ruleid: javascript-sql-injection-ide
  knexDb.raw("SELECT * FROM products WHERE category = '" + category + "'")
    .then(result => {
      res.json(result[0]);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Bad case 6: SQL injection with multiple concatenated parameters
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
  const minAge = req.query.minAge;
  const maxAge = req.query.maxAge;
  const query = "SELECT * FROM users WHERE age >= " + minAge + " AND age <= " + maxAge;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 7: SQL injection in SQLite
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
  const db = new sqlite3.Database(':memory:');
  const productId = req.query.id;
  
  // ruleid: javascript-sql-injection-ide
  db.all("SELECT * FROM products WHERE id = " + productId, (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
}
// {/fact}

// Bad case 8: SQL injection in PostgreSQL
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
  const status = req.query.status;
  
  // ruleid: javascript-sql-injection-ide
  pgClient.query("SELECT * FROM orders WHERE status = '" + status + "'", (err, result) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(result.rows);
  });
}
// {/fact}

// Bad case 9: SQL injection with object property access
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
  const filters = req.body.filters;
  const query = "SELECT * FROM products WHERE category = '" + filters.category + "'";
  
  // ruleid: javascript-sql-injection-ide
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 10: SQL injection with array index
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
  const searchTerms = req.body.terms;
  const query = "SELECT * FROM articles WHERE title LIKE '%" + searchTerms[0] + "%'";
  
  // ruleid: javascript-sql-injection-ide
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 11: SQL injection with header data
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
  const clientId = req.headers['x-client-id'];
  const query = "SELECT * FROM clients WHERE id = " + clientId;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 12: SQL injection with cookie data
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
  const userId = req.cookies.userId;
  
  // ruleid: javascript-sql-injection-ide
  connection.query("SELECT * FROM sessions WHERE user_id = " + userId, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 13: SQL injection with insufficient sanitization
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
  let username = req.query.username;
  // This only removes single quotes but doesn't prevent all SQL injection
  username = username.replace(/'/g, "''");
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`SELECT * FROM users WHERE username = '${username}'`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 14: SQL injection with template literals and expressions
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
  const sortField = req.query.sort || 'id';
  const sortOrder = req.query.order || 'ASC';
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`SELECT * FROM products ORDER BY ${sortField} ${sortOrder}`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Bad case 15: SQL injection with string interpolation in a complex query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
  const category = req.query.category;
  const minPrice = req.query.minPrice || '0';
  const maxPrice = req.query.maxPrice || '1000';
  
  const query = `
    SELECT p.*, c.name as category_name 
    FROM products p
    JOIN categories c ON p.category_id = c.id
    WHERE c.slug = '${category}'
    AND p.price BETWEEN ${minPrice} AND ${maxPrice}
    ORDER BY p.created_at DESC
  `;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// ==================== TRUE NEGATIVES (SECURE CODE) ====================

// Good case 1: Parameterized query with MySQL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
  const userId = req.query.id;
  
  // ok: javascript-sql-injection-ide
  connection.query("SELECT * FROM users WHERE id = ?", [userId], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Good case 2: Parameterized query with multiple parameters
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
  const username = req.body.username;
  const email = req.body.email;
  
  // ok: javascript-sql-injection-ide
  connection.query(
    "SELECT * FROM users WHERE username = ? OR email = ?",
    [username, email],
    (error, results) => {
      if (error) throw error;
      res.json(results);
    }
  );
}
// {/fact}

// Good case 3: Sequelize with replacements
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
  const role = req.query.role;
  
  // ok: javascript-sql-injection-ide
  sequelize.query(
    "SELECT * FROM users WHERE role = :role",
    {
      replacements: { role: role },
      type: Sequelize.QueryTypes.SELECT
    }
  ).then(users => {
    res.json(users);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
}
// {/fact}

// Good case 4: Knex parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
  const category = req.params.category;
  
  // ok: javascript-sql-injection-ide
  knexDb.raw("SELECT * FROM products WHERE category = ?", [category])
    .then(result => {
      res.json(result[0]);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Good case 5: Sequelize model query (ORM)
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
  const userId = req.query.id;
  
  const User = sequelize.define('User', {
    name: DataTypes.STRING,
    email: DataTypes.STRING
  });
  
  // ok: javascript-sql-injection-ide
  User.findByPk(userId)
    .then(user => {
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Good case 6: Knex query builder
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
  const minAge = req.query.minAge;
  const maxAge = req.query.maxAge;
  
  // ok: javascript-sql-injection-ide
  knexDb('users')
    .whereBetween('age', [minAge, maxAge])
    .select('*')
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Good case 7: SQLite with parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
  const db = new sqlite3.Database(':memory:');
  const productId = req.query.id;
  
  // ok: javascript-sql-injection-ide
  db.all("SELECT * FROM products WHERE id = ?", [productId], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
}
// {/fact}

// Good case 8: PostgreSQL with parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
  const status = req.query.status;
  
  // ok: javascript-sql-injection-ide
  pgClient.query("SELECT * FROM orders WHERE status = $1", [status], (err, result) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(result.rows);
  });
}
// {/fact}

// Good case 9: MongoDB query (NoSQL - not vulnerable to SQL injection)
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
  const userId = req.query.id;
  
  // ok: javascript-sql-injection-ide
  mongoClient.connect()
    .then(client => {
      const db = client.db('testdb');
      return db.collection('users').findOne({ _id: userId });
    })
    .then(user => {
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Good case 10: Input validation before using in query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
  const id = req.query.id;
  
  // Validate that id is numeric
  if (!validator.isNumeric(id)) {
    return res.status(400).json({ error: 'Invalid ID format' });
  }
  
  // ok: javascript-sql-injection-ide
  connection.query("SELECT * FROM users WHERE id = " + id, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Good case 11: Prepared statement with named parameters
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
  const filters = req.body.filters;
  
  // ok: javascript-sql-injection-ide
  connection.query(
    "SELECT * FROM products WHERE category = :category",
    { category: filters.category },
    (error, results) => {
      if (error) throw error;
      res.json(results);
    }
  );
}
// {/fact}

// Good case 12: Knex with multiple parameters
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
  const searchTerms = req.body.terms;
  
  // ok: javascript-sql-injection-ide
  knexDb('articles')
    .where('title', 'like', `%${knexDb.raw('?', [searchTerms[0]])}%`)
    .select('*')
    .then(articles => {
      res.json(articles);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Good case 13: Sequelize with bind parameters
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
  const clientId = req.headers['x-client-id'];
  
  // ok: javascript-sql-injection-ide
  sequelize.query(
    "SELECT * FROM clients WHERE id = $clientId",
    {
      bind: { clientId },
      type: Sequelize.QueryTypes.SELECT
    }
  ).then(clients => {
    res.json(clients);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
}
// {/fact}

// Good case 14: MySQL with object format for parameterized queries
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
  const sortField = req.query.sort || 'id';
  const sortOrder = req.query.order || 'ASC';
  
  // Whitelist validation for sort field and order
  const allowedFields = ['id', 'name', 'price', 'created_at'];
  const allowedOrders = ['ASC', 'DESC'];
  
  if (!allowedFields.includes(sortField) || !allowedOrders.includes(sortOrder.toUpperCase())) {
    return res.status(400).json({ error: 'Invalid sort parameters' });
  }
  
  // ok: javascript-sql-injection-ide
  connection.query(
    `SELECT * FROM products ORDER BY ${sortField} ${sortOrder}`,
    (error, results) => {
      if (error) throw error;
      res.json(results);
    }
  );
}
// {/fact}

// Good case 15: Complex query with proper parameterization
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
  const category = req.query.category;
  const minPrice = req.query.minPrice || '0';
  const maxPrice = req.query.maxPrice || '1000';
  
  const query = `
    SELECT p.*, c.name as category_name 
    FROM products p
    JOIN categories c ON p.category_id = c.id
    WHERE c.slug = ?
    AND p.price BETWEEN ? AND ?
    ORDER BY p.created_at DESC
  `;
  
  // ok: javascript-sql-injection-ide
  connection.query(query, [category, minPrice, maxPrice], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Export the app for testing
module.exports = app;