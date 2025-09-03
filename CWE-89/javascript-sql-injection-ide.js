const express = require('express');
const mysql = require('mysql');
const { Sequelize, QueryTypes } = require('sequelize');
const knex = require('knex');
const sqlite3 = require('sqlite3');
const mongodb = require('mongodb');
const pg = require('pg');
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

const sequelize = new Sequelize('database', 'username', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

const knexClient = knex({
  client: 'mysql',
  connection: {
    host: 'localhost',
    user: 'user',
    password: 'password',
    database: 'mydb'
  }
});

const pgClient = new pg.Client({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'mydb'
});

// True Positive Cases (Vulnerable Code)

// Case 1: Direct injection in MySQL query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
  const userId = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Case 2: String concatenation in prepared statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
  const username = req.body.username;
  
  // ruleid: javascript-sql-injection-ide
  connection.query('SELECT * FROM users WHERE username = "' + username + '"', (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Case 3: Template literal with user input in Sequelize raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
  const category = req.query.category;
  
  // ruleid: javascript-sql-injection-ide
  sequelize.query(`SELECT * FROM products WHERE category = '${category}'`, {
    type: QueryTypes.SELECT
  }).then(products => {
    res.json(products);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
}
// {/fact}

// Case 4: Knex.js raw query with string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
  const searchTerm = req.query.search;
  
  // ruleid: javascript-sql-injection-ide
  knexClient.raw('SELECT * FROM products WHERE name LIKE "%' + searchTerm + '%"')
    .then(result => {
      res.json(result[0]);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 5: SQLite with string interpolation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
  const db = new sqlite3.Database('./database.sqlite');
  const minPrice = req.query.minPrice;
  
  // ruleid: javascript-sql-injection-ide
  db.all(`SELECT * FROM products WHERE price > ${minPrice}`, (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
    db.close();
  });
}
// {/fact}

// Case 6: Multiple user inputs in one query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
  const name = req.query.name;
  const age = req.query.age;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`SELECT * FROM users WHERE name = '${name}' AND age > ${age}`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Case 7: User input in ORDER BY clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
  const sortColumn = req.query.sort;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`SELECT * FROM products ORDER BY ${sortColumn}`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Case 8: User input in LIMIT clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
  const limit = req.query.limit;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`SELECT * FROM products LIMIT ${limit}`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Case 9: User input in INSERT statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
  const username = req.body.username;
  const email = req.body.email;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`INSERT INTO users (username, email) VALUES ('${username}', '${email}')`, (error, results) => {
    if (error) throw error;
    res.json({ success: true, id: results.insertId });
  });
}
// {/fact}

// Case 10: User input in UPDATE statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
  const userId = req.params.id;
  const newStatus = req.body.status;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`UPDATE users SET status = '${newStatus}' WHERE id = ${userId}`, (error, results) => {
    if (error) throw error;
    res.json({ success: true, affected: results.affectedRows });
  });
}
// {/fact}

// Case 11: User input in DELETE statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
  const productId = req.params.id;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`DELETE FROM products WHERE id = ${productId}`, (error, results) => {
    if (error) throw error;
    res.json({ success: true, affected: results.affectedRows });
  });
}
// {/fact}

// Case 12: User input in JOIN condition
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
  const categoryId = req.query.category;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`
    SELECT p.*, c.name as category_name 
    FROM products p 
    JOIN categories c ON p.category_id = c.id 
    WHERE c.id = ${categoryId}
  `, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Case 13: PostgreSQL client with template literals
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
  const userId = req.query.id;
  
  pgClient.connect();
  // ruleid: javascript-sql-injection-ide
  pgClient.query(`SELECT * FROM users WHERE id = ${userId}`, (err, result) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json(result.rows);
    }
    pgClient.end();
  });
}
// {/fact}

// Case 14: Sequelize query with object and raw where condition
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
  const status = req.query.status;
  
  // ruleid: javascript-sql-injection-ide
  sequelize.query(`SELECT * FROM orders WHERE status = '${status}'`, {
    type: QueryTypes.SELECT
  }).then(orders => {
    res.json(orders);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
}
// {/fact}

// Case 15: User input in GROUP BY clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
  const groupField = req.query.group;
  
  // ruleid: javascript-sql-injection-ide
  connection.query(`SELECT ${groupField}, COUNT(*) as count FROM visits GROUP BY ${groupField}`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// True Negative Cases (Secure Code)

// Case 1: Parameterized query with MySQL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
  const userId = req.query.id;
  
  // ok: javascript-sql-injection-ide
  connection.query('SELECT * FROM users WHERE id = ?', [userId], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Case 2: Multiple parameters in MySQL query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
  const username = req.body.username;
  const status = req.body.status;
  
  // ok: javascript-sql-injection-ide
  connection.query('SELECT * FROM users WHERE username = ? AND status = ?', [username, status], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// Case 3: Sequelize query with replacements
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
  const category = req.query.category;
  
  // ok: javascript-sql-injection-ide
  sequelize.query('SELECT * FROM products WHERE category = :category', {
    replacements: { category: category },
    type: QueryTypes.SELECT
  }).then(products => {
    res.json(products);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
}
// {/fact}

// Case 4: Knex.js raw query with bindings
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
  const searchTerm = req.query.search;
  
  // ok: javascript-sql-injection-ide
  knexClient.raw('SELECT * FROM products WHERE name LIKE ?', [`%${searchTerm}%`])
    .then(result => {
      res.json(result[0]);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 5: SQLite with parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
  const db = new sqlite3.Database('./database.sqlite');
  const minPrice = req.query.minPrice;
  
  // ok: javascript-sql-injection-ide
  db.all('SELECT * FROM products WHERE price > ?', [minPrice], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
    db.close();
  });
}
// {/fact}

// Case 6: Knex.js query builder (safe by design)
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
  const name = req.query.name;
  const age = req.query.age;
  
  // ok: javascript-sql-injection-ide
  knexClient('users')
    .where('name', name)
    .where('age', '>', age)
    .select('*')
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 7: Sequelize ORM (safe by design)
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
  const User = sequelize.define('user', {
    username: Sequelize.STRING,
    email: Sequelize.STRING
  });
  
  const username = req.query.username;
  
  // ok: javascript-sql-injection-ide
  User.findAll({
    where: {
      username: username
    }
  }).then(users => {
    res.json(users);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
}
// {/fact}

// Case 8: PostgreSQL parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
  const userId = req.query.id;
  
  pgClient.connect();
  // ok: javascript-sql-injection-ide
  pgClient.query('SELECT * FROM users WHERE id = $1', [userId], (err, result) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json(result.rows);
    }
    pgClient.end();
  });
}
// {/fact}

// Case 9: MySQL multiple parameters in INSERT
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
  const username = req.body.username;
  const email = req.body.email;
  
  // ok: javascript-sql-injection-ide
  connection.query('INSERT INTO users (username, email) VALUES (?, ?)', [username, email], (error, results) => {
    if (error) throw error;
    res.json({ success: true, id: results.insertId });
  });
}
// {/fact}

// Case 10: MySQL parameterized UPDATE
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
  const userId = req.params.id;
  const newStatus = req.body.status;
  
  // ok: javascript-sql-injection-ide
  connection.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId], (error, results) => {
    if (error) throw error;
    res.json({ success: true, affected: results.affectedRows });
  });
}
// {/fact}

// Case 11: Knex.js delete operation (safe by design)
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
  const productId = req.params.id;
  
  // ok: javascript-sql-injection-ide
  knexClient('products')
    .where('id', productId)
    .del()
    .then(count => {
      res.json({ success: true, affected: count });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 12: Sequelize query with bind parameters
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
  const status = req.query.status;
  
  // ok: javascript-sql-injection-ide
  sequelize.query('SELECT * FROM orders WHERE status = $status', {
    bind: { status: status },
    type: QueryTypes.SELECT
  }).then(orders => {
    res.json(orders);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
}
// {/fact}

// Case 13: MongoDB query (NoSQL, not vulnerable to SQL injection)
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
  const userId = req.query.id;
  
  const MongoClient = mongodb.MongoClient;
  const url = 'mongodb://localhost:27017';
  
  // ok: javascript-sql-injection-ide
  MongoClient.connect(url, (err, client) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    const db = client.db('mydb');
    db.collection('users').findOne({ _id: userId }, (err, result) => {
      if (err) {
        res.status(500).json({ error: err.message });
      } else {
        res.json(result);
      }
      client.close();
    });
  });
}
// {/fact}

// Case 14: MySQL named placeholders
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
  const minAge = req.query.minAge;
  const maxAge = req.query.maxAge;
  
  // ok: javascript-sql-injection-ide
  connection.query('SELECT * FROM users WHERE age BETWEEN :minAge AND :maxAge', 
    { minAge: minAge, maxAge: maxAge }, 
    (error, results) => {
      if (error) throw error;
      res.json(results);
    }
  );
}
// {/fact}

// Case 15: Knex.js query builder with multiple conditions
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
  const category = req.query.category;
  const minPrice = req.query.minPrice;
  const sortBy = req.query.sortBy || 'name';
  
  // ok: javascript-sql-injection-ide
  knexClient('products')
    .where('category', category)
    .where('price', '>=', minPrice)
    .orderBy(sortBy)
    .select('*')
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});