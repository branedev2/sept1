import express from 'express';
import knex from 'knex';
import { Request, Response } from 'express';
import * as http from 'http';
import * as url from 'url';
import { EventEmitter } from 'events';

// Database connection setup
const db = knex({
  client: 'mysql',
  connection: {
    host: 'localhost',
    user: 'user',
    password: 'password',
    database: 'mydb'
  }
});

// True Positive Cases (Vulnerable Code)

// Case 1: Direct use of query parameter in raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
  const userId = req.query.id;
  
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

// Case 2: Using request body in raw query
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

// Case 3: Using request header in raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
  const apiKey = req.headers['x-api-key'];
  
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

// Case 4: Using request parameter in raw query with string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
  const productId = req.params.id;
  const query = "SELECT * FROM products WHERE id = '" + productId + "'";
  
  // ruleid: knex-sqli-ts-rule
  db.raw(query)
    .then(product => {
      res.json(product);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 5: Using request parameter in whereRaw
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
  const category = req.query.category;
  
  // ruleid: knex-sqli-ts-rule
  db.select('*')
    .from('products')
    .whereRaw(`category = '${category}'`)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 6: Using request cookie in raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
  const sessionId = req.cookies.sessionId;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM sessions WHERE id = '${sessionId}'`)
    .then(session => {
      res.json(session);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 7: Using request parameter in orderByRaw
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
  const sortColumn = req.query.sort;
  
  // ruleid: knex-sqli-ts-rule
  db.select('*')
    .from('users')
    .orderByRaw(`${sortColumn} ASC`)
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 8: Using request parameter in joinRaw
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
  const joinCondition = req.query.join;
  
  // ruleid: knex-sqli-ts-rule
  db.select('*')
    .from('orders')
    .joinRaw(`INNER JOIN products ON ${joinCondition}`)
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 9: Using request parameter in groupByRaw
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
  const groupField = req.query.group;
  
  // ruleid: knex-sqli-ts-rule
  db.select('*')
    .from('sales')
    .groupByRaw(`${groupField}`)
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 10: Using request parameter in havingRaw
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
  const havingCondition = req.query.having;
  
  // ruleid: knex-sqli-ts-rule
  db.select('category', db.raw('SUM(amount) as total'))
    .from('sales')
    .groupBy('category')
    .havingRaw(`SUM(amount) > ${havingCondition}`)
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 11: Using event data in raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  const eventEmitter = new EventEmitter();
  
  eventEmitter.on('search', (event) => {
    const searchTerm = event.query;
    
    // ruleid: knex-sqli-ts-rule
    db.raw(`SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`)
      .then(results => {
        console.log(results);
      })
      .catch(err => {
        console.error(err);
      });
  });
  
  // Simulate event emission
  eventEmitter.emit('search', { query: 'test' });
}
// {/fact}

// Case 12: Using HTTP request data directly in raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const searchTerm = parsedUrl.query.search as string;
    
    // ruleid: knex-sqli-ts-rule
    db.raw(`SELECT * FROM articles WHERE title LIKE '%${searchTerm}%'`)
      .then(results => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(results));
      })
      .catch(err => {
        res.writeHead(500);
        res.end(err.message);
      });
  });
  
  server.listen(3000);
}
// {/fact}

// Case 13: Using multiple request parameters in raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
  const { minPrice, maxPrice } = req.query;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM products WHERE price >= ${minPrice} AND price <= ${maxPrice}`)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 14: Using request parameter with string manipulation in raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const formattedSearch = searchTerm.toLowerCase().trim();
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`SELECT * FROM products WHERE LOWER(name) LIKE '%${formattedSearch}%'`)
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 15: Using request parameter in complex raw query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
  const userId = req.query.id;
  const startDate = req.query.start;
  
  // ruleid: knex-sqli-ts-rule
  db.raw(`
    SELECT o.id, o.date, p.name, p.price 
    FROM orders o 
    JOIN order_items oi ON o.id = oi.order_id 
    JOIN products p ON oi.product_id = p.id 
    WHERE o.user_id = ${userId} 
    AND o.date >= '${startDate}'
  `)
    .then(orders => {
      res.json(orders);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// True Negative Cases (Safe Code)

// Case 1: Using parameterized query with question mark placeholders
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
  const userId = req.query.id;
  
  // ok: knex-sqli-ts-rule
  db.raw('SELECT * FROM users WHERE id = ?', [userId])
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 2: Using parameterized query with named placeholders
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
  const { username } = req.body;
  
  // ok: knex-sqli-ts-rule
  db.raw('SELECT * FROM users WHERE username = :username', { username })
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 3: Using Knex query builder with where clause
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
  const apiKey = req.headers['x-api-key'];
  
  // ok: knex-sqli-ts-rule
  db('api_users')
    .where('api_key', apiKey)
    .select('*')
    .then(user => {
      res.json(user);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 4: Using Knex query builder with multiple conditions
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
  const productId = req.params.id;
  const category = req.query.category;
  
  // ok: knex-sqli-ts-rule
  db('products')
    .where({
      id: productId,
      category: category
    })
    .select('*')
    .then(product => {
      res.json(product);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 5: Using Knex query builder with whereIn
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
  const categories = req.query.categories as string[];
  
  // ok: knex-sqli-ts-rule
  db('products')
    .whereIn('category', categories)
    .select('*')
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 6: Using Knex query builder with orderBy
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
  const sortColumn = req.query.sort as string;
  const sortOrder = req.query.order as string;
  
  // Validate sort column to prevent injection
  const allowedColumns = ['id', 'name', 'price', 'created_at'];
  const column = allowedColumns.includes(sortColumn) ? sortColumn : 'id';
  const order = sortOrder === 'desc' ? 'desc' : 'asc';
  
  // ok: knex-sqli-ts-rule
  db('products')
    .orderBy(column, order)
    .select('*')
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 7: Using Knex query builder with join
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
  const orderId = req.query.id;
  
  // ok: knex-sqli-ts-rule
  db('orders')
    .join('order_items', 'orders.id', '=', 'order_items.order_id')
    .join('products', 'order_items.product_id', '=', 'products.id')
    .where('orders.id', orderId)
    .select('orders.*', 'products.name', 'products.price')
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 8: Using Knex query builder with groupBy
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
  const groupField = req.query.group as string;
  
  // Validate group field to prevent injection
  const allowedFields = ['category', 'brand', 'supplier'];
  const field = allowedFields.includes(groupField) ? groupField : 'category';
  
  // ok: knex-sqli-ts-rule
  db('sales')
    .select(field, db.raw('SUM(amount) as total'))
    .groupBy(field)
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 9: Using Knex query builder with having
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
  const minTotal = req.query.minTotal;
  
  // ok: knex-sqli-ts-rule
  db('sales')
    .select('category')
    .sum('amount as total')
    .groupBy('category')
    .having('total', '>', minTotal)
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 10: Using event data with parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  const eventEmitter = new EventEmitter();
  
  eventEmitter.on('search', (event) => {
    const searchTerm = event.query;
    
    // ok: knex-sqli-ts-rule
    db.raw('SELECT * FROM products WHERE name LIKE ?', [`%${searchTerm}%`])
      .then(results => {
        console.log(results);
      })
      .catch(err => {
        console.error(err);
      });
  });
  
  // Simulate event emission
  eventEmitter.emit('search', { query: 'test' });
}
// {/fact}

// Case 11: Using HTTP request data with parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '', true);
    const searchTerm = parsedUrl.query.search as string;
    
    // ok: knex-sqli-ts-rule
    db.raw('SELECT * FROM articles WHERE title LIKE ?', [`%${searchTerm}%`])
      .then(results => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(results));
      })
      .catch(err => {
        res.writeHead(500);
        res.end(err.message);
      });
  });
  
  server.listen(3000);
}
// {/fact}

// Case 12: Using multiple request parameters with parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
  const { minPrice, maxPrice } = req.query;
  
  // ok: knex-sqli-ts-rule
  db.raw('SELECT * FROM products WHERE price >= ? AND price <= ?', [minPrice, maxPrice])
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 13: Using request parameter with string manipulation in parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const formattedSearch = searchTerm.toLowerCase().trim();
  
  // ok: knex-sqli-ts-rule
  db.raw('SELECT * FROM products WHERE LOWER(name) LIKE ?', [`%${formattedSearch}%`])
    .then(products => {
      res.json(products);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 14: Using request parameter in complex parameterized query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
  const userId = req.query.id;
  const startDate = req.query.start;
  
  // ok: knex-sqli-ts-rule
  db.raw(`
    SELECT o.id, o.date, p.name, p.price 
    FROM orders o 
    JOIN order_items oi ON o.id = oi.order_id 
    JOIN products p ON oi.product_id = p.id 
    WHERE o.user_id = ? 
    AND o.date >= ?
  `, [userId, startDate])
    .then(orders => {
      res.json(orders);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Case 15: Using request parameter with input validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
  const userId = req.query.id;
  
  // Input validation
  if (!/^\d+$/.test(userId as string)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  // ok: knex-sqli-ts-rule
  db('users')
    .where('id', userId)
    .select('*')
    .then(user => {
      res.json(user);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
// {/fact}

// Export functions for testing
export {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};