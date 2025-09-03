// File: oracle_sql_injection_examples.ts

import * as express from 'express';
import * as oracledb from 'oracledb';
import { Request, Response } from 'express';

// Database connection setup
async function getConnection() {
  return await oracledb.getConnection({
    user: 'admin',
    password: 'password',
    connectString: 'localhost:1521/XE'
  });
}

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Direct injection in WHERE clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_1(req: Request, res: Response) {
  const userId = req.query.id as string;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM users WHERE id = ${userId}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 2: Injection in ORDER BY clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_2(req: Request, res: Response) {
  const sortColumn = req.query.sort as string;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM products ORDER BY ${sortColumn}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 3: Injection in LIKE clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_3(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM customers WHERE name LIKE '%${searchTerm}%'`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 4: Injection in INSERT statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_4(req: Request, res: Response) {
  const username = req.body.username;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `INSERT INTO users (username) VALUES ('${username}')`
    );
    res.json({ success: true, rowsAffected: result.rowsAffected });
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 5: Injection in UPDATE statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_5(req: Request, res: Response) {
  const userId = req.params.id;
  const newStatus = req.body.status;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `UPDATE users SET status = '${newStatus}' WHERE id = ${userId}`
    );
    res.json({ success: true, rowsAffected: result.rowsAffected });
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 6: Injection in DELETE statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_6(req: Request, res: Response) {
  const productId = req.params.id;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `DELETE FROM products WHERE id = ${productId}`
    );
    res.json({ success: true, rowsAffected: result.rowsAffected });
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 7: Injection in multiple parameters
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_7(req: Request, res: Response) {
  const minPrice = req.query.min as string;
  const maxPrice = req.query.max as string;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM products WHERE price >= ${minPrice} AND price <= ${maxPrice}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 8: Injection with string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_8(req: Request, res: Response) {
  const category = req.query.category as string;
  const connection = await getConnection();
  
  const query = "SELECT * FROM products WHERE category = '" + category + "'";
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 9: Injection with template literals
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_9(req: Request, res: Response) {
  const email = req.body.email;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(`
      SELECT * FROM users 
      WHERE email = '${email}'
    `);
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 10: Injection in JOIN clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_10(req: Request, res: Response) {
  const tableName = req.query.table as string;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT orders.*, ${tableName}.name FROM orders JOIN ${tableName} ON orders.product_id = ${tableName}.id`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 11: Injection with minimal processing
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_11(req: Request, res: Response) {
  let userId = req.query.id as string;
  userId = userId.trim();
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM users WHERE id = ${userId}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 12: Injection in GROUP BY clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_12(req: Request, res: Response) {
  const groupField = req.query.group as string;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT ${groupField}, COUNT(*) as count FROM orders GROUP BY ${groupField}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 13: Injection in HAVING clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_13(req: Request, res: Response) {
  const condition = req.query.condition as string;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT department, AVG(salary) as avg_salary FROM employees GROUP BY department HAVING ${condition}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 14: Injection with header data
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_14(req: Request, res: Response) {
  const apiKey = req.headers['x-api-key'] as string;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM api_users WHERE api_key = '${apiKey}'`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 15: Injection with cookie data
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_15(req: Request, res: Response) {
  const userToken = req.cookies.userToken;
  const connection = await getConnection();
  
  try {
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM sessions WHERE token = '${userToken}'`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// TRUE NEGATIVES (Safe Code Examples)

// Example 1: Using bind variables for WHERE clause
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_1(req: Request, res: Response) {
  const userId = req.query.id as string;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM users WHERE id = :id`,
      { id: userId }
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 2: Using bind variables for ORDER BY with whitelist
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_2(req: Request, res: Response) {
  const sortColumn = req.query.sort as string;
  const connection = await getConnection();
  
  // Validate sort column against whitelist
  const validColumns = ['name', 'price', 'created_at'];
  const column = validColumns.includes(sortColumn) ? sortColumn : 'created_at';
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM products ORDER BY ${column}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 3: Using bind variables for LIKE clause
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_3(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM customers WHERE name LIKE :search`,
      { search: `%${searchTerm}%` }
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 4: Using bind variables for INSERT statement
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_4(req: Request, res: Response) {
  const username = req.body.username;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `INSERT INTO users (username) VALUES (:username)`,
      { username: username }
    );
    res.json({ success: true, rowsAffected: result.rowsAffected });
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 5: Using bind variables for UPDATE statement
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_5(req: Request, res: Response) {
  const userId = req.params.id;
  const newStatus = req.body.status;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `UPDATE users SET status = :status WHERE id = :id`,
      { status: newStatus, id: userId }
    );
    res.json({ success: true, rowsAffected: result.rowsAffected });
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 6: Using bind variables for DELETE statement
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_6(req: Request, res: Response) {
  const productId = req.params.id;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `DELETE FROM products WHERE id = :id`,
      { id: productId }
    );
    res.json({ success: true, rowsAffected: result.rowsAffected });
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 7: Using bind variables for multiple parameters
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_7(req: Request, res: Response) {
  const minPrice = req.query.min as string;
  const maxPrice = req.query.max as string;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM products WHERE price >= :min AND price <= :max`,
      { min: minPrice, max: maxPrice }
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 8: Using bind variables with string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_8(req: Request, res: Response) {
  const category = req.query.category as string;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM products WHERE category = :category`,
      { category: category }
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 9: Using bind variables with template literals
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_9(req: Request, res: Response) {
  const email = req.body.email;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(`
      SELECT * FROM users 
      WHERE email = :email
    `, { email: email });
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 10: Safe handling of table names with whitelist
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_10(req: Request, res: Response) {
  const tableName = req.query.table as string;
  const connection = await getConnection();
  
  // Validate table name against whitelist
  const validTables = ['products', 'categories', 'suppliers'];
  if (!validTables.includes(tableName)) {
    return res.status(400).json({ error: 'Invalid table name' });
  }
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT orders.*, ${tableName}.name FROM orders JOIN ${tableName} ON orders.product_id = ${tableName}.id`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 11: Using numeric validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_11(req: Request, res: Response) {
  let userId = req.query.id as string;
  const connection = await getConnection();
  
  // Validate that userId is a number
  if (!/^\d+$/.test(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM users WHERE id = ${userId}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 12: Safe handling of GROUP BY with whitelist
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_12(req: Request, res: Response) {
  const groupField = req.query.group as string;
  const connection = await getConnection();
  
  // Validate group field against whitelist
  const validFields = ['product_id', 'customer_id', 'order_date'];
  if (!validFields.includes(groupField)) {
    return res.status(400).json({ error: 'Invalid group field' });
  }
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT ${groupField}, COUNT(*) as count FROM orders GROUP BY ${groupField}`
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 13: Using bind variables for HAVING clause
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_13(req: Request, res: Response) {
  const minAvgSalary = req.query.minSalary as string;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT department, AVG(salary) as avg_salary FROM employees GROUP BY department HAVING AVG(salary) > :minSalary`,
      { minSalary: minAvgSalary }
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 14: Using bind variables with header data
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_14(req: Request, res: Response) {
  const apiKey = req.headers['x-api-key'] as string;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM api_users WHERE api_key = :apiKey`,
      { apiKey: apiKey }
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Example 15: Using bind variables with cookie data
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_15(req: Request, res: Response) {
  const userToken = req.cookies.userToken;
  const connection = await getConnection();
  
  try {
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(
      `SELECT * FROM sessions WHERE token = :token`,
      { token: userToken }
    );
    res.json(result.rows);
  } finally {
    await connection.close();
  }
}
// {/fact}

// Set up Express server
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/users', bad_case_1);
app.get('/products', bad_case_2);
app.get('/customers/search', bad_case_3);
app.post('/users', bad_case_4);
app.put('/users/:id', bad_case_5);
app.delete('/products/:id', bad_case_6);
app.get('/products/filter', bad_case_7);
app.get('/products/by-category', bad_case_8);
app.post('/users/find-by-email', bad_case_9);
app.get('/orders/with-details', bad_case_10);
app.get('/users/find', bad_case_11);
app.get('/orders/stats', bad_case_12);
app.get('/employees/salary-stats', bad_case_13);
app.get('/api/validate', bad_case_14);
app.get('/sessions/check', bad_case_15);

// Safe routes
app.get('/safe/users', good_case_1);
app.get('/safe/products', good_case_2);
app.get('/safe/customers/search', good_case_3);
app.post('/safe/users', good_case_4);
app.put('/safe/users/:id', good_case_5);
app.delete('/safe/products/:id', good_case_6);
app.get('/safe/products/filter', good_case_7);
app.get('/safe/products/by-category', good_case_8);
app.post('/safe/users/find-by-email', good_case_9);
app.get('/safe/orders/with-details', good_case_10);
app.get('/safe/users/find', good_case_11);
app.get('/safe/orders/stats', good_case_12);
app.get('/safe/employees/salary-stats', good_case_13);
app.get('/safe/api/validate', good_case_14);
app.get('/safe/sessions/check', good_case_15);

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});