// Import necessary modules for examples
import express from 'express';
import mysql from 'mysql';
import { Connection, createConnection } from 'typeorm';
import { Sequelize } from 'sequelize';
import knex from 'knex';
import { PrismaClient } from '@prisma/client';
import { escape, sanitize } from 'sql-sanitizer'; // Example sanitizer library

// MySQL examples
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.get('/users', (req, res) => {
    const userId = req.query.id;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ruleid: typescript-sql-injection-ide
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/users', (req, res) => {
    const userId = req.query.id;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ok: typescript-sql-injection-ide
    connection.query('SELECT * FROM users WHERE id = ?', [userId], (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.post('/update-user', (req, res) => {
    const { name, id } = req.body;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ruleid: typescript-sql-injection-ide
    const query = `UPDATE users SET name = '${name}' WHERE id = ${id}`;
    connection.query(query, (error, results) => {
      if (error) throw error;
      res.json({ success: true });
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/update-user', (req, res) => {
    const { name, id } = req.body;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ok: typescript-sql-injection-ide
    connection.query('UPDATE users SET name = ? WHERE id = ?', [name, id], (error, results) => {
      if (error) throw error;
      res.json({ success: true });
    });
  });
}
// {/fact}

// TypeORM examples
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/products', async (req, res) => {
    const category = req.query.category;
    const connection = await createConnection({
      type: 'mysql',
      host: 'localhost',
      username: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ruleid: typescript-sql-injection-ide
    const products = await connection.query(`SELECT * FROM products WHERE category = '${category}'`);
    res.json(products);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/products', async (req, res) => {
    const category = req.query.category;
    const connection = await createConnection({
      type: 'mysql',
      host: 'localhost',
      username: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ok: typescript-sql-injection-ide
    const products = await connection.query('SELECT * FROM products WHERE category = ?', [category]);
    res.json(products);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.get('/orders', async (req, res) => {
    const status = req.query.status;
    const connection = await createConnection({
      type: 'mysql',
      host: 'localhost',
      username: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ruleid: typescript-sql-injection-ide
    const orders = await connection.manager.query(`
      SELECT * FROM orders 
      WHERE status = '${status}' 
      ORDER BY created_at DESC
    `);
    res.json(orders);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.get('/orders', async (req, res) => {
    const status = req.query.status;
    const connection = await createConnection({
      type: 'mysql',
      host: 'localhost',
      username: 'user',
      password: 'password',
      database: 'db'
    });
    
    // Using QueryBuilder with parameter binding
    // ok: typescript-sql-injection-ide
    const orders = await connection
      .createQueryBuilder()
      .select('orders')
      .from('orders', 'orders')
      .where('orders.status = :status', { status })
      .orderBy('orders.created_at', 'DESC')
      .getMany();
    
    res.json(orders);
  });
}
// {/fact}

// Sequelize examples
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/search', async (req, res) => {
    const keyword = req.query.keyword as string;
    const sequelize = new Sequelize('db', 'user', 'password', {
      host: 'localhost',
      dialect: 'mysql'
    });
    
    // ruleid: typescript-sql-injection-ide
    const results = await sequelize.query(`
      SELECT * FROM products 
      WHERE name LIKE '%${keyword}%' OR description LIKE '%${keyword}%'
    `);
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/search', async (req, res) => {
    const keyword = req.query.keyword as string;
    const sequelize = new Sequelize('db', 'user', 'password', {
      host: 'localhost',
      dialect: 'mysql'
    });
    
    // ok: typescript-sql-injection-ide
    const results = await sequelize.query(
      'SELECT * FROM products WHERE name LIKE :search OR description LIKE :search',
      {
        replacements: { search: `%${keyword}%` },
        type: sequelize.QueryTypes.SELECT
      }
    );
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.post('/filter-users', async (req, res) => {
    const { role, active } = req.body;
    const sequelize = new Sequelize('db', 'user', 'password', {
      host: 'localhost',
      dialect: 'mysql'
    });
    
    // ruleid: typescript-sql-injection-ide
    const users = await sequelize.query(`
      SELECT * FROM users 
      WHERE role = '${role}' 
      AND active = ${active}
    `);
    res.json(users);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.post('/filter-users', async (req, res) => {
    const { role, active } = req.body;
    const sequelize = new Sequelize('db', 'user', 'password', {
      host: 'localhost',
      dialect: 'mysql'
    });
    
    // ok: typescript-sql-injection-ide
    const users = await sequelize.query(
      'SELECT * FROM users WHERE role = :role AND active = :active',
      {
        replacements: { role, active },
        type: sequelize.QueryTypes.SELECT
      }
    );
    res.json(users);
  });
}
// {/fact}

// Knex.js examples
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/posts', (req, res) => {
    const authorId = req.query.author;
    const db = knex({
      client: 'mysql',
      connection: {
        host: 'localhost',
        user: 'user',
        password: 'password',
        database: 'db'
      }
    });
    
    // ruleid: typescript-sql-injection-ide
    db.raw(`SELECT * FROM posts WHERE author_id = ${authorId}`)
      .then(posts => {
        res.json(posts);
      })
      .catch(error => {
        res.status(500).json({ error });
      });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/posts', (req, res) => {
    const authorId = req.query.author;
    const db = knex({
      client: 'mysql',
      connection: {
        host: 'localhost',
        user: 'user',
        password: 'password',
        database: 'db'
      }
    });
    
    // ok: typescript-sql-injection-ide
    db.raw('SELECT * FROM posts WHERE author_id = ?', [authorId])
      .then(posts => {
        res.json(posts);
      })
      .catch(error => {
        res.status(500).json({ error });
      });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/comments', (req, res) => {
    const postId = req.query.post;
    const sort = req.query.sort || 'created_at';
    const db = knex({
      client: 'mysql',
      connection: {
        host: 'localhost',
        user: 'user',
        password: 'password',
        database: 'db'
      }
    });
    
    // ruleid: typescript-sql-injection-ide
    db.raw(`
      SELECT * FROM comments 
      WHERE post_id = ? 
      ORDER BY ${sort} DESC
    `, [postId])
      .then(comments => {
        res.json(comments);
      })
      .catch(error => {
        res.status(500).json({ error });
      });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/comments', (req, res) => {
    const postId = req.query.post;
    const sort = req.query.sort as string || 'created_at';
    const db = knex({
      client: 'mysql',
      connection: {
        host: 'localhost',
        user: 'user',
        password: 'password',
        database: 'db'
      }
    });
    
    // Validate sort parameter against allowed columns
    const allowedSortColumns = ['created_at', 'likes', 'author_id'];
    const safeSort = allowedSortColumns.includes(sort) ? sort : 'created_at';
    
    // ok: typescript-sql-injection-ide
    db.select('*')
      .from('comments')
      .where('post_id', postId)
      .orderBy(safeSort, 'desc')
      .then(comments => {
        res.json(comments);
      })
      .catch(error => {
        res.status(500).json({ error });
      });
  });
}
// {/fact}

// Complex examples with different input sources
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/api/data', (req, res) => {
    const table = req.headers['x-table-name'] as string;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ruleid: typescript-sql-injection-ide
    connection.query(`SELECT * FROM ${table}`, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/api/data', (req, res) => {
    const requestedTable = req.headers['x-table-name'] as string;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // Whitelist allowed tables
    const allowedTables = ['users', 'products', 'orders'];
    if (!allowedTables.includes(requestedTable)) {
      return res.status(403).json({ error: 'Access denied to requested table' });
    }
    
    // ok: typescript-sql-injection-ide
    connection.query(`SELECT * FROM ${requestedTable}`, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/api/query', (req, res) => {
    const { field, value, limit } = req.body;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    let query = `SELECT * FROM users WHERE ${field} = '${value}'`;
    if (limit) {
      query += ` LIMIT ${limit}`;
    }
    
    // ruleid: typescript-sql-injection-ide
    connection.query(query, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/api/query', (req, res) => {
    const { field, value, limit } = req.body;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // Whitelist allowed fields
    const allowedFields = ['username', 'email', 'status'];
    if (!allowedFields.includes(field)) {
      return res.status(400).json({ error: 'Invalid field' });
    }
    
    // Validate limit is a number
    const safeLimit = limit && !isNaN(Number(limit)) ? Number(limit) : 10;
    
    // ok: typescript-sql-injection-ide
    connection.query(
      'SELECT * FROM users WHERE ?? = ? LIMIT ?',
      [field, value, safeLimit],
      (error, results) => {
        if (error) throw error;
        res.json(results);
      }
    );
  });
}
// {/fact}

// Prisma examples
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const prisma = new PrismaClient();
  
  app.get('/users/search', async (req, res) => {
    const searchTerm = req.query.q as string;
    
    // ruleid: typescript-sql-injection-ide
    const users = await prisma.$queryRaw`
      SELECT * FROM User 
      WHERE name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%'
    `;
    
    res.json(users);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const prisma = new PrismaClient();
  
  app.get('/users/search', async (req, res) => {
    const searchTerm = req.query.q as string;
    
    // ok: typescript-sql-injection-ide
    const users = await prisma.user.findMany({
      where: {
        OR: [
          { name: { contains: searchTerm } },
          { email: { contains: searchTerm } }
        ]
      }
    });
    
    res.json(users);
  });
}
// {/fact}

// Template literals with expressions
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.get('/products/filter', (req, res) => {
    const minPrice = req.query.min;
    const maxPrice = req.query.max;
    const category = req.query.category;
    
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    let conditions = [];
    if (minPrice) conditions.push(`price >= ${minPrice}`);
    if (maxPrice) conditions.push(`price <= ${maxPrice}`);
    if (category) conditions.push(`category = '${category}'`);
    
    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    
    // ruleid: typescript-sql-injection-ide
    connection.query(`SELECT * FROM products ${whereClause}`, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/products/filter', (req, res) => {
    const minPrice = req.query.min ? Number(req.query.min) : null;
    const maxPrice = req.query.max ? Number(req.query.max) : null;
    const category = req.query.category as string;
    
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    let conditions = [];
    let params = [];
    
    if (minPrice !== null && !isNaN(minPrice)) {
      conditions.push('price >= ?');
      params.push(minPrice);
    }
    
    if (maxPrice !== null && !isNaN(maxPrice)) {
      conditions.push('price <= ?');
      params.push(maxPrice);
    }
    
    if (category) {
      conditions.push('category = ?');
      params.push(category);
    }
    
    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    
    // ok: typescript-sql-injection-ide
    connection.query(`SELECT * FROM products ${whereClause}`, params, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// Using sanitization functions
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/articles', (req, res) => {
    const author = req.query.author;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // Incorrect sanitization - still vulnerable
    const sanitizedAuthor = author?.toString().replace(/'/g, "''");
    
    // ruleid: typescript-sql-injection-ide
    connection.query(`SELECT * FROM articles WHERE author = '${sanitizedAuthor}'`, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/articles', (req, res) => {
    const author = req.query.author;
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ok: typescript-sql-injection-ide
    connection.query('SELECT * FROM articles WHERE author = ?', [author], (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// Dynamic table/column names
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/data', (req, res) => {
    const table = req.query.table as string;
    const column = req.query.column as string;
    const value = req.query.value as string;
    
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ruleid: typescript-sql-injection-ide
    connection.query(`SELECT * FROM ${table} WHERE ${column} = '${value}'`, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/data', (req, res) => {
    const requestedTable = req.query.table as string;
    const requestedColumn = req.query.column as string;
    const value = req.query.value as string;
    
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // Whitelist allowed tables and columns
    const allowedTables = {
      users: ['id', 'name', 'email'],
      products: ['id', 'name', 'price'],
      orders: ['id', 'user_id', 'status']
    };
    
    if (!Object.keys(allowedTables).includes(requestedTable)) {
      return res.status(400).json({ error: 'Invalid table' });
    }
    
    if (!allowedTables[requestedTable as keyof typeof allowedTables].includes(requestedColumn)) {
      return res.status(400).json({ error: 'Invalid column' });
    }
    
    // ok: typescript-sql-injection-ide
    connection.query(
      `SELECT * FROM ?? WHERE ?? = ?`,
      [requestedTable, requestedColumn, value],
      (error, results) => {
        if (error) throw error;
        res.json(results);
      }
    );
  });
}
// {/fact}

// Cookie-based injection
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/user-preferences', (req, res) => {
    const userId = req.cookies.userId;
    
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ruleid: typescript-sql-injection-ide
    connection.query(`SELECT * FROM preferences WHERE user_id = ${userId}`, (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/user-preferences', (req, res) => {
    const userId = req.cookies.userId;
    
    const connection = mysql.createConnection({
      host: 'localhost',
      user: 'user',
      password: 'password',
      database: 'db'
    });
    
    // ok: typescript-sql-injection-ide
    connection.query('SELECT * FROM preferences WHERE user_id = ?', [userId], (error, results) => {
      if (error) throw error;
      res.json(results);
    });
  });
}
// {/fact}