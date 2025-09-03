import express from 'express';
import mysql from 'mysql';
import { Request, Response } from 'express';
import * as typeorm from 'typeorm';
import { Sequelize } from 'sequelize';
import knex from 'knex';
import { PrismaClient } from '@prisma/client';

// MySQL Connection Setup
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'test'
});

// TypeORM Connection Setup
const dataSource = new typeorm.DataSource({
  type: "mysql",
  host: "localhost",
  port: 3306,
  username: "user",
  password: "password",
  database: "test"
});

// Sequelize Connection Setup
const sequelize = new Sequelize('test', 'user', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

// Knex Connection Setup
const knexClient = knex({
  client: 'mysql',
  connection: {
    host: 'localhost',
    user: 'user',
    password: 'password',
    database: 'test'
  }
});

// Prisma Client Setup
const prisma = new PrismaClient();

// True Positive Cases (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
  const userId = req.query.id;
  
  // ruleid: typescript-sql-injection-ide
  connection.query(`SELECT * FROM users WHERE id = ${userId}`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
  const username = req.body.username;
  
  // ruleid: typescript-sql-injection-ide
  connection.query("SELECT * FROM users WHERE username = '" + username + "'", (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const limit = req.query.limit || 10;
  
  // ruleid: typescript-sql-injection-ide
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%' LIMIT ${limit}`;
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_4(req: Request, res: Response) {
  const category = req.params.category;
  
  try {
    // ruleid: typescript-sql-injection-ide
    const result = await dataSource.query(`SELECT * FROM products WHERE category = '${category}'`);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_5(req: Request, res: Response) {
  const orderId = req.query.id;
  const userId = req.session?.userId;
  
  try {
    // ruleid: typescript-sql-injection-ide
    const result = await dataSource.query(
      `SELECT * FROM orders WHERE id = ${orderId} AND user_id = ${userId}`
    );
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_6(req: Request, res: Response) {
  const table = req.query.table as string;
  const column = req.query.column as string;
  
  try {
    // ruleid: typescript-sql-injection-ide
    const [results] = await sequelize.query(`SELECT ${column} FROM ${table}`);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_7(req: Request, res: Response) {
  const productId = req.params.id;
  const sort = req.query.sort || 'price';
  const order = req.query.order || 'ASC';
  
  try {
    // ruleid: typescript-sql-injection-ide
    const [reviews] = await sequelize.query(
      `SELECT * FROM reviews WHERE product_id = ${productId} ORDER BY ${sort} ${order}`
    );
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_8(req: Request, res: Response) {
  const userId = req.query.userId;
  
  try {
    // ruleid: typescript-sql-injection-ide
    const result = await knexClient.raw(`SELECT * FROM users WHERE id = ${userId}`);
    res.json(result[0]);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_9(req: Request, res: Response) {
  const startDate = req.query.start as string;
  const endDate = req.query.end as string;
  
  try {
    // ruleid: typescript-sql-injection-ide
    const result = await knexClient.raw(
      `SELECT * FROM orders WHERE created_at BETWEEN '${startDate}' AND '${endDate}'`
    );
    res.json(result[0]);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
  const fields = req.query.fields as string;
  const table = req.query.table as string;
  
  // ruleid: typescript-sql-injection-ide
  const query = `SELECT ${fields} FROM ${table}`;
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
  const id = req.params.id;
  const updates = req.body;
  
  let setClause = '';
  for (const [key, value] of Object.entries(updates)) {
    setClause += `${key} = '${value}', `;
  }
  setClause = setClause.slice(0, -2); // Remove trailing comma and space
  
  // ruleid: typescript-sql-injection-ide
  connection.query(`UPDATE users SET ${setClause} WHERE id = ${id}`, (error, results) => {
    if (error) throw error;
    res.json({ updated: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_12(req: Request, res: Response) {
  const conditions = req.query.conditions as string;
  
  try {
    // ruleid: typescript-sql-injection-ide
    const [results] = await sequelize.query(`SELECT * FROM products WHERE ${conditions}`);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
  const userInput = req.query.input as string;
  const sanitized = userInput.replace(/'/g, "''"); // Insufficient sanitization
  
  // ruleid: typescript-sql-injection-ide
  connection.query(`SELECT * FROM users WHERE name LIKE '%${sanitized}%'`, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_14(req: Request, res: Response) {
  const ids = req.query.ids as string; // Comma-separated list of IDs
  
  try {
    // ruleid: typescript-sql-injection-ide
    const result = await dataSource.query(`SELECT * FROM products WHERE id IN (${ids})`);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const tableName = req.query.table || 'products';
  
  // ruleid: typescript-sql-injection-ide
  const sql = `
    SELECT * FROM ${tableName}
    WHERE name LIKE '%${searchTerm}%'
    OR description LIKE '%${searchTerm}%'
  `;
  
  connection.query(sql, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// True Negative Cases (Secure Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
  const userId = req.query.id;
  
  // ok: typescript-sql-injection-ide
  connection.query('SELECT * FROM users WHERE id = ?', [userId], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
  const username = req.body.username;
  
  // ok: typescript-sql-injection-ide
  connection.query("SELECT * FROM users WHERE username = ?", [username], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  const limit = Number(req.query.limit) || 10;
  
  // ok: typescript-sql-injection-ide
  const query = 'SELECT * FROM products WHERE name LIKE ? LIMIT ?';
  connection.query(query, [`%${searchTerm}%`, limit], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_4(req: Request, res: Response) {
  const category = req.params.category;
  
  try {
    // ok: typescript-sql-injection-ide
    const result = await dataSource.query(
      'SELECT * FROM products WHERE category = ?',
      [category]
    );
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_5(req: Request, res: Response) {
  const orderId = req.query.id;
  const userId = req.session?.userId;
  
  try {
    // ok: typescript-sql-injection-ide
    const result = await dataSource
      .createQueryBuilder()
      .select('order')
      .from('orders', 'order')
      .where('order.id = :id', { id: orderId })
      .andWhere('order.user_id = :userId', { userId: userId })
      .getMany();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_6(req: Request, res: Response) {
  const table = req.query.table as string;
  const column = req.query.column as string;
  
  // Validate against allowed tables and columns
  const allowedTables = ['products', 'categories'];
  const allowedColumns = ['id', 'name', 'price', 'description'];
  
  if (!allowedTables.includes(table) || !allowedColumns.includes(column)) {
    return res.status(400).json({ error: 'Invalid table or column' });
  }
  
  try {
    // ok: typescript-sql-injection-ide
    const [results] = await sequelize.query(
      `SELECT ${column} FROM ${table}`,
      { type: sequelize.QueryTypes.SELECT }
    );
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_7(req: Request, res: Response) {
  const productId = req.params.id;
  const sort = req.query.sort as string || 'price';
  const order = req.query.order as string || 'ASC';
  
  // Validate sort and order parameters
  const allowedSortFields = ['price', 'created_at', 'rating'];
  const allowedOrderDirections = ['ASC', 'DESC'];
  
  if (!allowedSortFields.includes(sort) || !allowedOrderDirections.includes(order.toUpperCase())) {
    return res.status(400).json({ error: 'Invalid sort parameters' });
  }
  
  try {
    // ok: typescript-sql-injection-ide
    const [reviews] = await sequelize.query(
      'SELECT * FROM reviews WHERE product_id = ? ORDER BY ' + sort + ' ' + order,
      {
        replacements: [productId],
        type: sequelize.QueryTypes.SELECT
      }
    );
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_8(req: Request, res: Response) {
  const userId = req.query.userId;
  
  try {
    // ok: typescript-sql-injection-ide
    const result = await knexClient.raw('SELECT * FROM users WHERE id = ?', [userId]);
    res.json(result[0]);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_9(req: Request, res: Response) {
  const startDate = req.query.start as string;
  const endDate = req.query.end as string;
  
  try {
    // ok: typescript-sql-injection-ide
    const result = await knexClient.raw(
      'SELECT * FROM orders WHERE created_at BETWEEN ? AND ?',
      [startDate, endDate]
    );
    res.json(result[0]);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
  const fields = req.query.fields as string;
  const table = req.query.table as string;
  
  // Validate fields and table
  const allowedTables = ['products', 'categories', 'users'];
  const allowedFields = ['id', 'name', 'email', 'price', 'description'];
  
  const requestedFields = fields.split(',');
  const isValidFields = requestedFields.every(field => allowedFields.includes(field.trim()));
  
  if (!allowedTables.includes(table) || !isValidFields) {
    return res.status(400).json({ error: 'Invalid table or fields' });
  }
  
  // ok: typescript-sql-injection-ide
  const query = `SELECT ${fields} FROM ${table}`;
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
  const id = req.params.id;
  const updates = req.body;
  
  const params: any[] = [];
  const setStatements: string[] = [];
  
  for (const [key, value] of Object.entries(updates)) {
    setStatements.push(`${key} = ?`);
    params.push(value);
  }
  
  params.push(id);
  
  // ok: typescript-sql-injection-ide
  connection.query(
    `UPDATE users SET ${setStatements.join(', ')} WHERE id = ?`,
    params,
    (error, results) => {
      if (error) throw error;
      res.json({ updated: true });
    }
  );
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_12(req: Request, res: Response) {
  const minPrice = req.query.minPrice ? Number(req.query.minPrice) : 0;
  const maxPrice = req.query.maxPrice ? Number(req.query.maxPrice) : 1000;
  const category = req.query.category as string;
  
  try {
    // ok: typescript-sql-injection-ide
    const [results] = await sequelize.query(
      'SELECT * FROM products WHERE price BETWEEN ? AND ? AND category = ?',
      {
        replacements: [minPrice, maxPrice, category],
        type: sequelize.QueryTypes.SELECT
      }
    );
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_13(req: Request, res: Response) {
  const userInput = req.query.input as string;
  
  try {
    // ok: typescript-sql-injection-ide
    const users = await prisma.user.findMany({
      where: {
        name: {
          contains: userInput
        }
      }
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_14(req: Request, res: Response) {
  const idString = req.query.ids as string;
  const ids = idString.split(',').map(id => parseInt(id, 10));
  
  try {
    // ok: typescript-sql-injection-ide
    const result = await dataSource.query(
      'SELECT * FROM products WHERE id IN (?)',
      [ids]
    );
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
  const searchTerm = req.query.search as string;
  
  // ok: typescript-sql-injection-ide
  const sql = `
    SELECT * FROM products
    WHERE name LIKE ?
    OR description LIKE ?
  `;
  
  connection.query(sql, [`%${searchTerm}%`, `%${searchTerm}%`], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
}
// {/fact}