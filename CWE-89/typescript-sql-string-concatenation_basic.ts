import * as mysql from 'mysql';
import * as pg from 'pg';
import * as sqlite3 from 'sqlite3';
import * as express from 'express';
import * as mssql from 'mssql';
import * as http from 'http';
import { Request, Response } from 'express';

// Database connection setup
const mysqlConnection = mysql.createConnection({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'mydb'
});

const pgPool = new pg.Pool({
  user: 'user',
  host: 'localhost',
  database: 'mydb',
  password: 'password',
  port: 5432,
});

const sqliteDb = new sqlite3.Database(':memory:');

const mssqlConfig = {
  user: 'user',
  password: 'password',
  server: 'localhost',
  database: 'mydb'
};

const app = express();
app.use(express.json());

// TRUE POSITIVES (Vulnerable code examples)

// Example 1: Basic string concatenation with MySQL
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
  const userId = req.query.id;
  
  // ruleid: typescript-sql-string-concatenation
  const query = "SELECT * FROM users WHERE id = " + userId;
  
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// Example 2: Template literals with PostgreSQL
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
  const username = req.params.username;
  
  // ruleid: typescript-sql-string-concatenation
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  
  pgPool.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results.rows);
    }
  });
}
// {/fact}

// Example 3: Multiple concatenations with SQLite
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
  const minAge = req.query.minAge;
  const maxAge = req.query.maxAge;
  
  // ruleid: typescript-sql-string-concatenation
  const query = "SELECT * FROM users WHERE age >= " + minAge + " AND age <= " + maxAge;
  
  sqliteDb.all(query, (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// Example 4: String concatenation with MSSQL
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
  const productId = req.query.productId;
  
  // ruleid: typescript-sql-string-concatenation
  const query = "SELECT * FROM products WHERE id = " + productId;
  
  mssql.connect(mssqlConfig).then(() => {
    return mssql.query(query);
  }).then(result => {
    res.json(result.recordset);
  }).catch(err => {
    res.status(500).send('Error executing query');
  });
}
// {/fact}

// Example 5: Concatenation with conditional logic
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
  const category = req.query.category;
  const minPrice = req.query.minPrice || '0';
  
  let query = "SELECT * FROM products WHERE 1=1";
  
  if (category) {
    // ruleid: typescript-sql-string-concatenation
    query += " AND category = '" + category + "'";
  }
  
  // ruleid: typescript-sql-string-concatenation
  query += " AND price >= " + minPrice;
  
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// Example 6: Concatenation with HTTP headers
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
  const userAgent = req.headers['user-agent'];
  
  // ruleid: typescript-sql-string-concatenation
  const query = "INSERT INTO user_agents (agent) VALUES ('" + userAgent + "')";
  
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ success: true });
    }
  });
}
// {/fact}

// Example 7: Concatenation with POST body data
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
  const { email, name } = req.body;
  
  // ruleid: typescript-sql-string-concatenation
  const query = `INSERT INTO subscribers (email, name) VALUES ('${email}', '${name}')`;
  
  pgPool.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ success: true });
    }
  });
}
// {/fact}

// Example 8: Concatenation with cookies
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
  const sessionId = req.cookies.sessionId;
  
  // ruleid: typescript-sql-string-concatenation
  const query = "SELECT * FROM sessions WHERE id = '" + sessionId + "'";
  
  sqliteDb.get(query, (err, row) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(row);
    }
  });
}
// {/fact}

// Example 9: Concatenation with string manipulation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
  let searchTerm = req.query.search as string;
  searchTerm = searchTerm.toLowerCase().trim();
  
  // ruleid: typescript-sql-string-concatenation
  const query = "SELECT * FROM products WHERE LOWER(name) LIKE '%" + searchTerm + "%'";
  
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// Example 10: Concatenation with URL parameters in complex query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
  const orderId = req.params.orderId;
  const status = req.query.status;
  
  // ruleid: typescript-sql-string-concatenation
  const query = `
    UPDATE orders 
    SET status = '${status}', 
        updated_at = NOW() 
    WHERE id = ${orderId}
  `;
  
  pgPool.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ success: true });
    }
  });
}
// {/fact}

// Example 11: Concatenation with multiple template literals
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
  const { firstName, lastName, age } = req.body;
  
  // ruleid: typescript-sql-string-concatenation
  const query = `
    INSERT INTO users (first_name, last_name, age) 
    VALUES ('${firstName}', '${lastName}', ${age})
  `;
  
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ id: results.insertId });
    }
  });
}
// {/fact}

// Example 12: Concatenation with array join
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
  const tagIds = req.query.tags as string[];
  
  // ruleid: typescript-sql-string-concatenation
  const query = "SELECT * FROM posts WHERE tag_id IN (" + tagIds.join(',') + ")";
  
  sqliteDb.all(query, (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// Example 13: Concatenation with Node.js http module
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '', `http://${req.headers.host}`);
    const userId = url.searchParams.get('userId');
    
    // ruleid: typescript-sql-string-concatenation
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    mysqlConnection.query(query, (err, results) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(err ? { error: err.message } : results));
    });
  });
  
  server.listen(3000);
}
// {/fact}

// Example 14: Concatenation with variable reassignment
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
  let query = "SELECT * FROM products WHERE 1=1";
  const filters = req.query;
  
  if (filters.category) {
    // ruleid: typescript-sql-string-concatenation
    query += " AND category = '" + filters.category + "'";
  }
  
  if (filters.minPrice) {
    // ruleid: typescript-sql-string-concatenation
    query += " AND price >= " + filters.minPrice;
  }
  
  if (filters.maxPrice) {
    // ruleid: typescript-sql-string-concatenation
    query += " AND price <= " + filters.maxPrice;
  }
  
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// Example 15: Concatenation with ternary operator
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
  const sortField = req.query.sortField || 'created_at';
  const sortOrder = req.query.sortOrder === 'asc' ? 'ASC' : 'DESC';
  
  // ruleid: typescript-sql-string-concatenation
  const query = "SELECT * FROM posts ORDER BY " + sortField + " " + sortOrder;
  
  pgPool.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results.rows);
    }
  });
}
// {/fact}

// TRUE NEGATIVES (Safe code examples)

// Example 1: Using parameterized queries with MySQL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
  const userId = req.query.id;
  
  // ok: typescript-sql-string-concatenation
  const query = "SELECT * FROM users WHERE id = ?";
  
  mysqlConnection.query(query, [userId], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// Example 2: Using parameterized queries with PostgreSQL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
  const username = req.params.username;
  
  // ok: typescript-sql-string-concatenation
  const query = "SELECT * FROM users WHERE username = $1";
  
  pgPool.query(query, [username], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results.rows);
    }
  });
}
// {/fact}

// Example 3: Using multiple parameters with SQLite
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
  const minAge = req.query.minAge;
  const maxAge = req.query.maxAge;
  
  // ok: typescript-sql-string-concatenation
  const query = "SELECT * FROM users WHERE age >= ? AND age <= ?";
  
  sqliteDb.all(query, [minAge, maxAge], (err, rows) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(rows);
    }
  });
}
// {/fact}

// Example 4: Using parameterized queries with MSSQL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
  const productId = req.query.productId;
  
  // ok: typescript-sql-string-concatenation
  const request = new mssql.Request();
  request.input('productId', productId);
  const query = "SELECT * FROM products WHERE id = @productId";
  
  mssql.connect(mssqlConfig).then(() => {
    return request.query(query);
  }).then(result => {
    res.json(result.recordset);
  }).catch(err => {
    res.status(500).send('Error executing query');
  });
}
// {/fact}

// Example 5: Using parameterized queries with conditional logic
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
  const category = req.query.category;
  const minPrice = req.query.minPrice || '0';
  
  let query = "SELECT * FROM products WHERE 1=1";
  const params: any[] = [];
  
  if (category) {
    query += " AND category = ?";
    params.push(category);
  }
  
  query += " AND price >= ?";
  params.push(minPrice);
  
  // ok: typescript-sql-string-concatenation
  mysqlConnection.query(query, params, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// Example 6: Using parameterized queries with HTTP headers
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
  const userAgent = req.headers['user-agent'];
  
  // ok: typescript-sql-string-concatenation
  const query = "INSERT INTO user_agents (agent) VALUES ($1)";
  
  pgPool.query(query, [userAgent], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ success: true });
    }
  });
}
// {/fact}

// Example 7: Using parameterized queries with POST body data
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
  const { email, name } = req.body;
  
  // ok: typescript-sql-string-concatenation
  const query = "INSERT INTO subscribers (email, name) VALUES (?, ?)";
  
  mysqlConnection.query(query, [email, name], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ success: true });
    }
  });
}
// {/fact}

// Example 8: Using parameterized queries with cookies
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
  const sessionId = req.cookies.sessionId;
  
  // ok: typescript-sql-string-concatenation
  const query = "SELECT * FROM sessions WHERE id = ?";
  
  sqliteDb.get(query, [sessionId], (err, row) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(row);
    }
  });
}
// {/fact}

// Example 9: Using parameterized queries with string manipulation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
  let searchTerm = req.query.search as string;
  searchTerm = searchTerm.toLowerCase().trim();
  
  // ok: typescript-sql-string-concatenation
  const query = "SELECT * FROM products WHERE LOWER(name) LIKE $1";
  
  pgPool.query(query, ['%' + searchTerm + '%'], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results.rows);
    }
  });
}
// {/fact}

// Example 10: Using parameterized queries with URL parameters in complex query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
  const orderId = req.params.orderId;
  const status = req.query.status;
  
  // ok: typescript-sql-string-concatenation
  const query = `
    UPDATE orders 
    SET status = $1, 
        updated_at = NOW() 
    WHERE id = $2
  `;
  
  pgPool.query(query, [status, orderId], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ success: true });
    }
  });
}
// {/fact}

// Example 11: Using parameterized queries with multiple values
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
  const { firstName, lastName, age } = req.body;
  
  // ok: typescript-sql-string-concatenation
  const query = `
    INSERT INTO users (first_name, last_name, age) 
    VALUES (?, ?, ?)
  `;
  
  mysqlConnection.query(query, [firstName, lastName, age], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json({ id: results.insertId });
    }
  });
}
// {/fact}

// Example 12: Using parameterized queries with array
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
  const tagIds = req.query.tags as string[];
  const placeholders = tagIds.map((_, index) => `$${index + 1}`).join(',');
  
  // ok: typescript-sql-string-concatenation
  const query = `SELECT * FROM posts WHERE tag_id IN (${placeholders})`;
  
  pgPool.query(query, tagIds, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results.rows);
    }
  });
}
// {/fact}

// Example 13: Using parameterized queries with Node.js http module
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '', `http://${req.headers.host}`);
    const userId = url.searchParams.get('userId');
    
    // ok: typescript-sql-string-concatenation
    const query = "SELECT * FROM users WHERE id = ?";
    
    mysqlConnection.query(query, [userId], (err, results) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(err ? { error: err.message } : results));
    });
  });
  
  server.listen(3000);
}
// {/fact}

// Example 14: Using parameterized queries with multiple conditions
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
  const filters = req.query;
  let query = "SELECT * FROM products WHERE 1=1";
  const params: any[] = [];
  
  if (filters.category) {
    query += " AND category = ?";
    params.push(filters.category);
  }
  
  if (filters.minPrice) {
    query += " AND price >= ?";
    params.push(filters.minPrice);
  }
  
  if (filters.maxPrice) {
    query += " AND price <= ?";
    params.push(filters.maxPrice);
  }
  
  // ok: typescript-sql-string-concatenation
  mysqlConnection.query(query, params, (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results);
    }
  });
}
// {/fact}

// Example 15: Using parameterized queries with dynamic sorting
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
  const sortField = req.query.sortField || 'created_at';
  const sortOrder = req.query.sortOrder === 'asc' ? 'ASC' : 'DESC';
  
  // Whitelist allowed sort fields to prevent injection
  const allowedSortFields = ['created_at', 'title', 'author', 'price'];
  const actualSortField = allowedSortFields.includes(sortField as string) 
    ? sortField 
    : 'created_at';
  
  // ok: typescript-sql-string-concatenation
  const query = `SELECT * FROM posts ORDER BY ${actualSortField} ${sortOrder}`;
  
  pgPool.query(query, [], (err, results) => {
    if (err) {
      res.status(500).send('Error executing query');
    } else {
      res.json(results.rows);
    }
  });
}
// {/fact}

// Start the server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});