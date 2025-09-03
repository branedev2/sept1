import * as express from 'express';
import * as oracledb from 'oracledb';
import * as http from 'http';
import * as url from 'url';

// Configuration for Oracle DB connection
const dbConfig = {
  user: 'dbuser',
  password: process.env.DB_PASSWORD,
  connectString: 'localhost:1521/XEPDB1'
};

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Direct injection in WHERE clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_1(req: express.Request, res: express.Response) {
  const userId = req.query.id as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Direct concatenation of user input in SQL query
    const query = `SELECT * FROM users WHERE user_id = '${userId}'`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
}
// {/fact}

// Example 2: Injection in ORDER BY clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_2(req: express.Request, res: express.Response) {
  const sortColumn = req.query.sort as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Vulnerable ORDER BY clause
    const query = `SELECT * FROM products ORDER BY ${sortColumn}`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 3: Injection in LIKE clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_3(req: express.Request, res: express.Response) {
  const searchTerm = req.query.search as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Vulnerable LIKE clause
    const query = `SELECT * FROM products WHERE product_name LIKE '%${searchTerm}%'`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 4: Injection in INSERT statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_4(req: express.Request, res: express.Response) {
  const username = req.body.username;
  const email = req.body.email;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Vulnerable INSERT statement
    const query = `INSERT INTO users (username, email) VALUES ('${username}', '${email}')`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json({ success: true, id: result.lastRowid });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 5: Injection in UPDATE statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_5(req: express.Request, res: express.Response) {
  const userId = req.params.id;
  const newStatus = req.body.status;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Vulnerable UPDATE statement
    const query = `UPDATE users SET status = '${newStatus}' WHERE user_id = ${userId}`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    await connection.execute(query);
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 6: Injection in DELETE statement
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_6(req: express.Request, res: express.Response) {
  const productId = req.params.id;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Vulnerable DELETE statement
    const query = `DELETE FROM products WHERE product_id = ${productId}`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    await connection.execute(query);
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 7: Injection with template literals and multiple inputs
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_7(req: express.Request, res: express.Response) {
  const minPrice = req.query.min as string;
  const maxPrice = req.query.max as string;
  const category = req.query.category as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Multiple vulnerable inputs in query
    const query = `SELECT * FROM products 
                   WHERE price BETWEEN ${minPrice} AND ${maxPrice} 
                   AND category = '${category}'`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 8: Injection in JOIN clause
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_8(req: express.Request, res: express.Response) {
  const tableName = req.query.table as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Vulnerable JOIN clause
    const query = `SELECT * FROM users JOIN ${tableName} ON users.id = ${tableName}.user_id`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 9: Injection with HTTP POST data
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_9(req: express.Request, res: express.Response) {
  const searchFilters = req.body.filters;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Vulnerable query with POST data
    const query = `SELECT * FROM inventory WHERE category = '${searchFilters.category}' AND quantity > ${searchFilters.minQuantity}`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 10: Injection with HTTP headers
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_10(req: express.Request, res: express.Response) {
  const userAgent = req.headers['user-agent'] as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Logging user agent to database with vulnerability
    const query = `INSERT INTO access_logs (user_agent, access_time) VALUES ('${userAgent}', CURRENT_TIMESTAMP)`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    await connection.execute(query);
    
    res.send('Access logged');
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 11: Injection with minimal processing of input
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_11(req: express.Request, res: express.Response) {
  let userId = req.query.id as string;
  userId = userId.trim(); // Minimal processing doesn't prevent injection
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 12: Injection with string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_12(req: express.Request, res: express.Response) {
  const startDate = req.query.start as string;
  const endDate = req.query.end as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // String concatenation doesn't prevent injection
    let query = "SELECT * FROM orders WHERE order_date >= '" + startDate + "'";
    query += " AND order_date <= '" + endDate + "'";
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 13: Injection with cookies
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_13(req: express.Request, res: express.Response) {
  const userPreference = req.cookies.preference;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Using cookie value in query
    const query = `SELECT * FROM products WHERE category = '${userPreference}'`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 14: Injection with URL parameters in a more complex query
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_14(req: express.Request, res: express.Response) {
  const parsedUrl = url.parse(req.url, true);
  const region = parsedUrl.query.region as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Complex query with URL parameter
    const query = `
      SELECT p.product_name, c.category_name, s.stock_level
      FROM products p
      JOIN categories c ON p.category_id = c.id
      JOIN stock s ON p.id = s.product_id
      WHERE s.region = '${region}'
      ORDER BY s.stock_level DESC
    `;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 15: Injection with dynamic table name
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_15(req: express.Request, res: express.Response) {
  const year = req.query.year as string;
  const month = req.query.month as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Dynamic table name based on user input
    const tableName = `sales_${year}_${month}`;
    const query = `SELECT * FROM ${tableName} WHERE amount > 1000`;
    
    // ruleid: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// Example 1: Using bind variables for WHERE clause
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_1(req: express.Request, res: express.Response) {
  const userId = req.query.id as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `SELECT * FROM users WHERE user_id = :id`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, { id: userId });
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 2: Using bind variables for ORDER BY clause with whitelist validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_2(req: express.Request, res: express.Response) {
  let sortColumn = req.query.sort as string;
  
  // Whitelist validation for column names
  const allowedColumns = ['product_name', 'price', 'created_at'];
  if (!allowedColumns.includes(sortColumn)) {
    sortColumn = 'created_at'; // Default safe value
  }
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Using the validated column name
    const query = `SELECT * FROM products ORDER BY ${sortColumn}`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 3: Using bind variables for LIKE clause
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_3(req: express.Request, res: express.Response) {
  const searchTerm = req.query.search as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `SELECT * FROM products WHERE product_name LIKE :search`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, { search: `%${searchTerm}%` });
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 4: Using bind variables for INSERT statement
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_4(req: express.Request, res: express.Response) {
  const username = req.body.username;
  const email = req.body.email;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `INSERT INTO users (username, email) VALUES (:username, :email)`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, { username, email });
    
    res.json({ success: true, id: result.lastRowid });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 5: Using bind variables for UPDATE statement
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_5(req: express.Request, res: express.Response) {
  const userId = req.params.id;
  const newStatus = req.body.status;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `UPDATE users SET status = :status WHERE user_id = :id`;
    
    // ok: typescript-oracle-sql-injection-ide
    await connection.execute(query, { status: newStatus, id: userId });
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 6: Using bind variables for DELETE statement
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_6(req: express.Request, res: express.Response) {
  const productId = req.params.id;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `DELETE FROM products WHERE product_id = :id`;
    
    // ok: typescript-oracle-sql-injection-ide
    await connection.execute(query, { id: productId });
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 7: Using bind variables with multiple inputs
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_7(req: express.Request, res: express.Response) {
  const minPrice = req.query.min as string;
  const maxPrice = req.query.max as string;
  const category = req.query.category as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `SELECT * FROM products 
                   WHERE price BETWEEN :min AND :max 
                   AND category = :category`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, {
      min: minPrice,
      max: maxPrice,
      category: category
    });
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 8: Secure handling of dynamic table names with whitelist
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_8(req: express.Request, res: express.Response) {
  const tableName = req.query.table as string;
  
  // Whitelist validation for table names
  const allowedTables = ['orders', 'customers', 'products'];
  if (!allowedTables.includes(tableName)) {
    return res.status(400).send('Invalid table name');
  }
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Using validated table name
    const query = `SELECT * FROM users JOIN ${tableName} ON users.id = ${tableName}.user_id`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 9: Using bind variables with HTTP POST data
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_9(req: express.Request, res: express.Response) {
  const searchFilters = req.body.filters;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `SELECT * FROM inventory WHERE category = :category AND quantity > :minQuantity`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, {
      category: searchFilters.category,
      minQuantity: searchFilters.minQuantity
    });
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 10: Secure handling of HTTP headers
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_10(req: express.Request, res: express.Response) {
  const userAgent = req.headers['user-agent'] as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `INSERT INTO access_logs (user_agent, access_time) VALUES (:userAgent, CURRENT_TIMESTAMP)`;
    
    // ok: typescript-oracle-sql-injection-ide
    await connection.execute(query, { userAgent });
    
    res.send('Access logged');
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 11: Using numeric validation before query
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_11(req: express.Request, res: express.Response) {
  let userId = req.query.id as string;
  
  // Validate that userId is numeric
  if (!/^\d+$/.test(userId)) {
    return res.status(400).send('Invalid user ID');
  }
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Since we've validated userId is numeric, this is safe
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 12: Using bind variables with date ranges
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_12(req: express.Request, res: express.Response) {
  const startDate = req.query.start as string;
  const endDate = req.query.end as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `SELECT * FROM orders WHERE order_date >= :startDate AND order_date <= :endDate`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, { startDate, endDate });
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 13: Secure handling of cookies
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_13(req: express.Request, res: express.Response) {
  const userPreference = req.cookies.preference;
  
  // Whitelist validation for category values
  const validCategories = ['electronics', 'books', 'clothing', 'food'];
  if (!validCategories.includes(userPreference)) {
    return res.status(400).send('Invalid category preference');
  }
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `SELECT * FROM products WHERE category = :category`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, { category: userPreference });
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 14: Secure handling of URL parameters in a complex query
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_14(req: express.Request, res: express.Response) {
  const parsedUrl = url.parse(req.url, true);
  const region = parsedUrl.query.region as string;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    const query = `
      SELECT p.product_name, c.category_name, s.stock_level
      FROM products p
      JOIN categories c ON p.category_id = c.id
      JOIN stock s ON p.id = s.product_id
      WHERE s.region = :region
      ORDER BY s.stock_level DESC
    `;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, { region });
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Example 15: Secure handling of dynamic table names with validation and prepared statements
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_15(req: express.Request, res: express.Response) {
  const year = req.query.year as string;
  const month = req.query.month as string;
  
  // Validate year and month format
  if (!/^\d{4}$/.test(year) || !/^(0[1-9]|1[0-2])$/.test(month)) {
    return res.status(400).send('Invalid year or month format');
  }
  
  // Construct table name after validation
  const tableName = `sales_${year}_${month}`;
  
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    
    // Using validated table name
    const query = `SELECT * FROM ${tableName} WHERE amount > :minAmount`;
    
    // ok: typescript-oracle-sql-injection-ide
    const result = await connection.execute(query, { minAmount: 1000 });
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}
// {/fact}

// Create and start the server
const app = express();
app.use(express.json());
app.listen(3000, () => {
  console.log('Server running on port 3000');
});