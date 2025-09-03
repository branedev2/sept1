// File: knex_sqli_test_cases.ts
import express from 'express';
import knex from 'knex';
import { Request, Response } from 'express';
import * as validator from 'validator';
import { sanitizeInput } from './sanitizer';
import { EventEmitter } from 'events';

// Database connection setup
const db = knex({
  client: 'mysql',
  connection: {
    host: 'localhost',
    user: 'user',
    password: 'password',
    database: 'test_db'
  }
});

const app = express();
app.use(express.json());

// Event emitter for testing event-based inputs
const eventEmitter = new EventEmitter();

// ==================== TRUE POSITIVES (VULNERABLE CODE) ====================

// Case 1: Direct use of request parameter in SQL query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
  const userId = req.params.id;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM users WHERE id = ${userId}`)
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 2: Using request body in SQL query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
  const { username } = req.body;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM users WHERE username = '${username}'`)
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 3: Using request query parameter in SQL query with string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  
  // ruleid: knex-sqli-ts-rule
  db.raw(query)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 4: Using request header in SQL query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
  const apiKey = req.headers['x-api-key'] as string;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM api_users WHERE api_key = '${apiKey}'`)
    .then(user => {
      res.json(user);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 5: Using request cookie in SQL query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
  const userToken = req.cookies.userToken;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM sessions WHERE token = '${userToken}'`)
    .then(session => {
      res.json(session);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 6: Using request parameter with template literals
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
  const category = req.params.category;
  const minPrice = req.query.minPrice as string;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM products WHERE category = '${category}' AND price > ${minPrice}`)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 7: Using event data in SQL query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  eventEmitter.on('user-search', (searchData) => {
    const { term } = searchData;
    
    // ruleid: knex-sqli-ts-rule
    db.raw(`SELECT * FROM search_history WHERE term = '${term}'`)
      .then(results => {
        console.log(results);
      })
      .catch(err => {
        console.error(err);
      });
  });
}
// {/fact}

// Case 8: Using request data with minimal processing
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
  const userId = req.params.id.trim();
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`DELETE FROM users WHERE id = ${userId}`)
    .then(() => {
      res.json({ success: true });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 9: Using request data in a complex query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
  const { column, order, limit } = req.query as { column: string, order: string, limit: string };
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM products ORDER BY ${column} ${order} LIMIT ${limit}`)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 10: Using request data in a subquery
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
  const categoryId = req.params.categoryId;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM products WHERE category_id IN (SELECT id FROM categories WHERE parent_id = ${categoryId})`)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 11: Using request data in an INSERT statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
  const { username, email } = req.body;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`INSERT INTO users (username, email) VALUES ('${username}', '${email}')`)
    .then(() => {
      res.json({ success: true });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 12: Using request data in an UPDATE statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
  const { id, status } = req.body;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`UPDATE orders SET status = '${status}' WHERE id = ${id}`)
    .then(() => {
      res.json({ success: true });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 13: Using event data with string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  eventEmitter.on('log-action', (actionData) => {
    const { userId, action, timestamp } = actionData;
    const query = "INSERT INTO activity_logs (user_id, action, timestamp) VALUES (" + 
                  userId + ", '" + action + "', '" + timestamp + "')";
    
    // ruleid: knex-sqli-ts-rule
    db.raw(query)
      .then(() => {
        console.log('Activity logged');
      })
      .catch(err => {
        console.error('Failed to log activity:', err);
      });
  });
}
// {/fact}

// Case 14: Using request data in multiple places in a query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
  const { startDate, endDate, userId } = req.query as { startDate: string, endDate: string, userId: string };
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM orders WHERE user_id = ${userId} AND order_date BETWEEN '${startDate}' AND '${endDate}'`)
    .then(orders => {
      res.json(orders);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 15: Using request data in a JOIN clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
  const tablePrefix = req.query.prefix as string;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT u.*, p.* FROM users u JOIN ${tablePrefix}_profiles p ON u.id = p.user_id`)
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// ==================== TRUE NEGATIVES (SAFE CODE) ====================

// Case 1: Using parameterized query with knex
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
  const userId = req.params.id;
  
  // ok: knex-sqli-ts-rule
  db.select('*').from('users').where('id', userId)
    .then(user => {
      res.json(user);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 2: Using knex query builder with request body
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
  const { username } = req.body;
  
  // ok: knex-sqli-ts-rule
  db.select('*').from('users').where({ username })
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 3: Using parameterized raw query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  
  // ok: knex-sqli-ts-rule
  db.raw('SELECT * FROM products WHERE name LIKE ?', [`%${searchTerm}%`])
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 4: Using knex query builder with request header
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
  const apiKey = req.headers['x-api-key'] as string;
  
  // ok: knex-sqli-ts-rule
  db.select('*').from('api_users').where('api_key', apiKey)
    .then(user => {
      res.json(user);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 5: Using parameterized query with request cookie
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
  const userToken = req.cookies.userToken;
  
  // ok: knex-sqli-ts-rule
  db.select('*').from('sessions').where('token', userToken)
    .then(session => {
      res.json(session);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 6: Using knex query builder with multiple conditions
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
  const category = req.params.category;
  const minPrice = parseFloat(req.query.minPrice as string);
  
  // ok: knex-sqli-ts-rule
  db.select('*').from('products')
    .where('category', category)
    .where('price', '>', minPrice)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 7: Using knex query builder with event data
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  eventEmitter.on('user-search', (searchData) => {
    const { term } = searchData;
    
    // ok: knex-sqli-ts-rule
    db.select('*').from('search_history').where('term', term)
      .then(results => {
        console.log(results);
      })
      .catch(err => {
        console.error(err);
      });
  });
}
// {/fact}

// Case 8: Using knex query builder for delete operation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
  const userId = req.params.id;
  
  // ok: knex-sqli-ts-rule
  db('users').where('id', userId).del()
    .then(() => {
      res.json({ success: true });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 9: Using knex query builder for ordering and limiting
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
  const column = req.query.column as string;
  const order = req.query.order as string;
  const limit = parseInt(req.query.limit as string);
  
  // Validate column name against allowed list
  const allowedColumns = ['id', 'name', 'price', 'created_at'];
  const safeColumn = allowedColumns.includes(column) ? column : 'id';
  
  // Validate order direction
  const safeOrder = order === 'desc' ? 'desc' : 'asc';
  
  // ok: knex-sqli-ts-rule
  db.select('*').from('products')
    .orderBy(safeColumn, safeOrder)
    .limit(limit)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 10: Using knex query builder with subquery
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
  const categoryId = req.params.categoryId;
  
  // ok: knex-sqli-ts-rule
  db.select('*').from('products')
    .whereIn('category_id', function() {
      this.select('id').from('categories').where('parent_id', categoryId);
    })
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 11: Using knex query builder for insert operation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
  const { username, email } = req.body;
  
  // ok: knex-sqli-ts-rule
  db('users').insert({ username, email })
    .then(() => {
      res.json({ success: true });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 12: Using knex query builder for update operation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
  const { id, status } = req.body;
  
  // ok: knex-sqli-ts-rule
  db('orders').where('id', id).update({ status })
    .then(() => {
      res.json({ success: true });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 13: Using knex query builder with event data for logging
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  eventEmitter.on('log-action', (actionData) => {
    const { userId, action, timestamp } = actionData;
    
    // ok: knex-sqli-ts-rule
    db('activity_logs').insert({
      user_id: userId,
      action: action,
      timestamp: timestamp
    })
    .then(() => {
      console.log('Activity logged');
    })
    .catch(err => {
      console.error('Failed to log activity:', err);
    });
  });
}
// {/fact}

// Case 14: Using knex query builder with date range
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
  const { startDate, endDate, userId } = req.query as { startDate: string, endDate: string, userId: string };
  
  // ok: knex-sqli-ts-rule
  db.select('*').from('orders')
    .where('user_id', userId)
    .whereBetween('order_date', [startDate, endDate])
    .then(orders => {
      res.json(orders);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 15: Using knex query builder with join
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
  const tablePrefix = req.query.prefix as string;
  
  // Validate table prefix against allowed list
  const allowedPrefixes = ['user', 'customer', 'admin'];
  
  if (!allowedPrefixes.includes(tablePrefix)) {
    return res.status(400).json({ error: 'Invalid table prefix' });
  }
  
  const profileTable = `${tablePrefix}_profiles`;
  
  // ok: knex-sqli-ts-rule
  db.select('u.*', 'p.*')
    .from('users as u')
    .join(`${profileTable} as p`, 'u.id', 'p.user_id')
    .then(results => {
      res.json(results);
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