const express = require('express');
const mysql = require('mysql');
const sqlite3 = require('sqlite3');
const { Client } = require('pg');
const mssql = require('mssql');
const app = express();

// Database connection setup
const mysqlConnection = mysql.createConnection({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'testdb'
});

const sqliteDb = new sqlite3.Database(':memory:');

const pgClient = new Client({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'testdb'
});

// Configure express to parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  
  // ruleid: javascript-sql-string-concatenation
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
  const username = req.body.username;
  
  // ruleid: javascript-sql-string-concatenation
  sqliteDb.all("SELECT * FROM users WHERE username = '" + username + "'", (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
  const productId = req.params.id;
  const category = req.query.category;
  const query = `SELECT * FROM products WHERE id = ${productId} AND category = '${category}'`;
  
  // ruleid: javascript-sql-string-concatenation
  pgClient.query(query)
    .then(result => res.json(result.rows))
    .catch(err => res.status(500).send('Error executing query'));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
  const searchTerm = req.query.search;
  const limit = req.query.limit || 10;
  
  // ruleid: javascript-sql-string-concatenation
  mysqlConnection.query("SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%' LIMIT " + limit, 
    (err, results) => {
      if (err) {
        res.status(500).send('Error executing query');
      } else {
        res.json(results);
      }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
  const userId = req.cookies.userId;
  const role = req.body.role;
  
  // ruleid: javascript-sql-string-concatenation
  sqliteDb.get(`SELECT * FROM users WHERE id = ${userId} AND role = '${role}'`, (err, row) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(row);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
  const orderBy = req.query.sort || 'id';
  const direction = req.query.dir || 'ASC';
  
  // ruleid: javascript-sql-string-concatenation
  mysqlConnection.query(`SELECT * FROM products ORDER BY ${orderBy} ${direction}`, 
    (err, results) => {
      if (err) {
        res.status(500).send('Error executing query');
      } else {
        res.json(results);
      }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
  const table = req.params.table;
  const id = req.query.id;
  
  // ruleid: javascript-sql-string-concatenation
  pgClient.query(`SELECT * FROM ${table} WHERE id = ${id}`)
    .then(result => res.json(result.rows))
    .catch(err => res.status(500).send('Error executing query'));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
  const email = req.body.email;
  let query = "UPDATE users SET verified = true WHERE email = '" + email + "'";
  
  // ruleid: javascript-sql-string-concatenation
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ success: true });
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
  const ids = req.body.ids.join(','); // Assuming ids is an array
  
  // ruleid: javascript-sql-string-concatenation
  sqliteDb.all(`SELECT * FROM products WHERE id IN (${ids})`, (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
  const startDate = req.query.start;
  const endDate = req.query.end;
  
  // ruleid: javascript-sql-string-concatenation
  pgClient.query("SELECT * FROM orders WHERE order_date BETWEEN '" + startDate + "' AND '" + endDate + "'")
    .then(result => res.json(result.rows))
    .catch(err => res.status(500).send('Error executing query'));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
  const userId = req.headers['x-user-id'];
  
  // ruleid: javascript-sql-string-concatenation
  mssql.query`SELECT * FROM users WHERE id = ${userId}`.then(result => {
    res.json(result.recordset);
  }).catch(err => {
    res.status(500).send('Error executing query');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
  const category = req.query.category;
  const minPrice = req.query.minPrice || 0;
  const maxPrice = req.query.maxPrice || 1000;
  
  // ruleid: javascript-sql-string-concatenation
  mysqlConnection.query("SELECT * FROM products WHERE category = '" + category + 
                       "' AND price BETWEEN " + minPrice + " AND " + maxPrice, 
    (err, results) => {
      if (err) {
        res.status(500).send('Error executing query');
      } else {
        res.json(results);
      }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
  const searchFields = ['name', 'description', 'category'];
  const searchTerm = req.query.q;
  let query = "SELECT * FROM products WHERE ";
  
  searchFields.forEach((field, index) => {
    if (index > 0) query += " OR ";
    query += field + " LIKE '%" + searchTerm + "%'";
  });
  
  // ruleid: javascript-sql-string-concatenation
  sqliteDb.all(query, (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
  const userId = req.query.id;
  const action = req.query.action || 'view';
  let query;
  
  if (action === 'delete') {
    query = "DELETE FROM users WHERE id = " + userId;
  } else {
    query = "SELECT * FROM users WHERE id = " + userId;
  }
  
  // ruleid: javascript-sql-string-concatenation
  pgClient.query(query)
    .then(result => res.json({ success: true }))
    .catch(err => res.status(500).send('Error executing query'));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
  const userInput = req.body.data;
  const processedInput = userInput.replace(/['"]/g, ''); // Insufficient sanitization
  
  // ruleid: javascript-sql-string-concatenation
  mysqlConnection.query(`SELECT * FROM users WHERE username = '${processedInput}'`, 
    (err, results) => {
      if (err) {
        res.status(500).send('Error executing query');
      } else {
        res.json(results);
      }
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
  const userId = req.query.id;
  
  // ok: javascript-sql-string-concatenation
  mysqlConnection.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
  const username = req.body.username;
  
  // ok: javascript-sql-string-concatenation
  sqliteDb.all("SELECT * FROM users WHERE username = ?", [username], (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
  const productId = req.params.id;
  const category = req.query.category;
  
  // ok: javascript-sql-string-concatenation
  pgClient.query("SELECT * FROM products WHERE id = $1 AND category = $2", [productId, category])
    .then(result => res.json(result.rows))
    .catch(err => res.status(500).send('Error executing query'));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
  const searchTerm = req.query.search;
  const limit = req.query.limit || 10;
  
  // ok: javascript-sql-string-concatenation
  mysqlConnection.query("SELECT * FROM products WHERE name LIKE ? LIMIT ?", 
    ['%' + searchTerm + '%', parseInt(limit, 10)], 
    (err, results) => {
      if (err) {
        res.status(500).send('Error executing query');
      } else {
        res.json(results);
      }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
  const userId = req.cookies.userId;
  const role = req.body.role;
  
  // ok: javascript-sql-string-concatenation
  sqliteDb.get("SELECT * FROM users WHERE id = ? AND role = ?", [userId, role], (err, row) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(row);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
  // For column names that can't be parameterized, use a whitelist approach
  const allowedColumns = ['id', 'name', 'price', 'created_at'];
  const allowedDirections = ['ASC', 'DESC'];
  
  const orderBy = req.query.sort || 'id';
  const direction = req.query.dir || 'ASC';
  
  if (!allowedColumns.includes(orderBy) || !allowedDirections.includes(direction.toUpperCase())) {
    return res.status(400).send('Invalid sort parameters');
  }
  
  // ok: javascript-sql-string-concatenation
  const query = `SELECT * FROM products ORDER BY ${orderBy} ${direction}`;
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
  // For table names that can't be parameterized, use a whitelist approach
  const allowedTables = ['products', 'categories', 'tags'];
  const table = req.params.table;
  const id = req.query.id;
  
  if (!allowedTables.includes(table)) {
    return res.status(400).send('Invalid table name');
  }
  
  // ok: javascript-sql-string-concatenation
  const query = `SELECT * FROM ${table} WHERE id = $1`;
  pgClient.query(query, [id])
    .then(result => res.json(result.rows))
    .catch(err => res.status(500).send('Error executing query'));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
  const email = req.body.email;
  
  // ok: javascript-sql-string-concatenation
  mysqlConnection.query("UPDATE users SET verified = true WHERE email = ?", [email], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ success: true });
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
  const ids = req.body.ids; // Array of IDs
  
  // ok: javascript-sql-string-concatenation
  const placeholders = ids.map((_, index) => '?').join(',');
  sqliteDb.all(`SELECT * FROM products WHERE id IN (${placeholders})`, ids, (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
  const startDate = req.query.start;
  const endDate = req.query.end;
  
  // ok: javascript-sql-string-concatenation
  pgClient.query("SELECT * FROM orders WHERE order_date BETWEEN $1 AND $2", [startDate, endDate])
    .then(result => res.json(result.rows))
    .catch(err => res.status(500).send('Error executing query'));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
  const userId = req.headers['x-user-id'];
  
  // ok: javascript-sql-string-concatenation
  const request = new mssql.Request();
  request.input('userId', mssql.Int, userId);
  request.query("SELECT * FROM users WHERE id = @userId").then(result => {
    res.json(result.recordset);
  }).catch(err => {
    res.status(500).send('Error executing query');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
  const category = req.query.category;
  const minPrice = req.query.minPrice || 0;
  const maxPrice = req.query.maxPrice || 1000;
  
  // ok: javascript-sql-string-concatenation
  mysqlConnection.query("SELECT * FROM products WHERE category = ? AND price BETWEEN ? AND ?", 
    [category, minPrice, maxPrice], 
    (err, results) => {
      if (err) {
        res.status(500).send('Error executing query');
      } else {
        res.json(results);
      }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
  const searchFields = ['name', 'description', 'category'];
  const searchTerm = req.query.q;
  
  // ok: javascript-sql-string-concatenation
  const placeholders = searchFields.map((field) => `${field} LIKE ?`).join(' OR ');
  const params = searchFields.map(() => `%${searchTerm}%`);
  
  sqliteDb.all(`SELECT * FROM products WHERE ${placeholders}`, params, (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
  const userId = req.query.id;
  const action = req.query.action || 'view';
  
  if (action === 'delete') {
    // ok: javascript-sql-string-concatenation
    pgClient.query("DELETE FROM users WHERE id = $1", [userId])
      .then(result => res.json({ success: true }))
      .catch(err => res.status(500).send('Error executing query'));
  } else {
    // ok: javascript-sql-string-concatenation
    pgClient.query("SELECT * FROM users WHERE id = $1", [userId])
      .then(result => res.json(result.rows))
      .catch(err => res.status(500).send('Error executing query'));
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
  const userInput = req.body.data;
  
  // ok: javascript-sql-string-concatenation
  const query = {
    text: 'SELECT * FROM users WHERE username = $1',
    values: [userInput]
  };
  
  pgClient.query(query)
    .then(result => res.json(result.rows))
    .catch(err => res.status(500).send('Error executing query'));
}
// {/fact}

// Start the server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});