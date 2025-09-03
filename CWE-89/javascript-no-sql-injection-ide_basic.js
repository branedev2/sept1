// Filename: nosql_injection_examples.js

const express = require('express');
const app = express();
const { MongoClient, ObjectId } = require('mongodb');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB connection setup
const uri = "mongodb://localhost:27017";
const client = new MongoClient(uri);
let db;

async function connectToDatabase() {
  await client.connect();
  db = client.db("testDB");
  console.log("Connected to MongoDB");
}

// Mongoose setup
mongoose.connect('mongodb://localhost:27017/testDB', { useNewUrlParser: true, useUnifiedTopology: true });
const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: String
}));

// TRUE POSITIVES (Vulnerable Code)

// Bad Case 1: Direct use of user input in find query
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_1(req, res) {
  const username = req.query.username;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const users = await db.collection('users').find({ username: username }).toArray();
    res.json(users);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 2: Using user input in a complex query object
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_2(req, res) {
  const searchTerm = req.query.search;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const results = await db.collection('products').find({
      $or: [
        { name: searchTerm },
        { description: searchTerm }
      ]
    }).toArray();
    res.json(results);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 3: Using user input in updateOne
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_3(req, res) {
  const userId = req.params.id;
  const userData = req.body;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const result = await db.collection('users').updateOne(
      { _id: userId },
      { $set: userData }
    );
    res.json({ success: true, modified: result.modifiedCount });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 4: Using user input in deleteOne
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_4(req, res) {
  const filter = req.body.filter;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const result = await db.collection('comments').deleteOne(filter);
    res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 5: Using user input in aggregation pipeline
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_5(req, res) {
  const matchStage = req.body.match;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const results = await db.collection('orders').aggregate([
      { $match: matchStage },
      { $group: { _id: "$status", count: { $sum: 1 } } }
    ]).toArray();
    res.json(results);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 6: Using user input in findOne with Mongoose
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_6(req, res) {
  const email = req.query.email;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const user = await User.findOne({ email: email });
    res.json(user);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 7: Using user input in complex query with string interpolation
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_7(req, res) {
  const role = req.query.role;
  const status = req.query.status;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const query = { role: role, status: status };
    const users = await db.collection('users').find(query).toArray();
    res.json(users);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 8: Using header data in query
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_8(req, res) {
  const apiKey = req.headers['x-api-key'];
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const apiUser = await db.collection('api_users').findOne({ apiKey: apiKey });
    res.json(apiUser);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 9: Using cookie data in query
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_9(req, res) {
  const sessionId = req.cookies.sessionId;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const session = await db.collection('sessions').findOne({ id: sessionId });
    res.json(session);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 10: Using user input in findOneAndUpdate with Mongoose
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_10(req, res) {
  const username = req.params.username;
  const updates = req.body;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const result = await User.findOneAndUpdate(
      { username: username },
      { $set: updates },
      { new: true }
    );
    res.json(result);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 11: Using user input in deleteMany
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_11(req, res) {
  const category = req.query.category;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const result = await db.collection('products').deleteMany({ category: category });
    res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 12: Using user input in distinct
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_12(req, res) {
  const field = req.query.field;
  const query = { active: true };
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const values = await db.collection('users').distinct(field, query);
    res.json(values);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 13: Using user input in countDocuments
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_13(req, res) {
  const status = req.query.status;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const count = await db.collection('orders').countDocuments({ status: status });
    res.json({ count });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 14: Using user input in findOneAndDelete
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_14(req, res) {
  const id = req.params.id;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const result = await db.collection('tasks').findOneAndDelete({ _id: id });
    res.json({ success: true, deleted: result.value });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Bad Case 15: Using user input in bulkWrite operations
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_15(req, res) {
  const operations = req.body.operations;
  
  try {
    // ruleid: javascript-no-sql-injection-ide
    const result = await db.collection('inventory').bulkWrite(operations);
    res.json({ success: true, modified: result.modifiedCount });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Good Case 1: Validating and sanitizing input before using in find query
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_1(req, res) {
  let username = req.query.username;
  
  // Validate input
  if (typeof username !== 'string' || !username.match(/^[a-zA-Z0-9_]{3,30}$/)) {
    return res.status(400).send('Invalid username format');
  }
  
  try {
    // ok: javascript-no-sql-injection-ide
    const users = await db.collection('users').find({ username: username }).toArray();
    res.json(users);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 2: Using ObjectId for ID validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_2(req, res) {
  const id = req.params.id;
  
  try {
    // ok: javascript-no-sql-injection-ide
    const objectId = new ObjectId(id);
    const user = await db.collection('users').findOne({ _id: objectId });
    res.json(user);
  } catch (err) {
    res.status(400).send('Invalid ID format');
  }
}
// {/fact}

// Good Case 3: Whitelisting fields for update
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_3(req, res) {
  const userId = req.params.id;
  const rawData = req.body;
  
  try {
    const objectId = new ObjectId(userId);
    
    // Whitelist allowed fields
    const safeUpdate = {};
    const allowedFields = ['name', 'email', 'age'];
    
    for (const field of allowedFields) {
      if (rawData[field] !== undefined) {
        safeUpdate[field] = rawData[field];
      }
    }
    
    // ok: javascript-no-sql-injection-ide
    const result = await db.collection('users').updateOne(
      { _id: objectId },
      { $set: safeUpdate }
    );
    
    res.json({ success: true, modified: result.modifiedCount });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 4: Using schema validation with Mongoose
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_4(req, res) {
  try {
    const userData = req.body;
    
    // ok: javascript-no-sql-injection-ide
    const newUser = new User(userData);
    await newUser.validate(); // Mongoose will validate against schema
    await newUser.save();
    
    res.json({ success: true, user: newUser });
  } catch (err) {
    res.status(400).send(err.message);
  }
}
// {/fact}

// Good Case 5: Using predefined query options
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_5(req, res) {
  const status = req.query.status;
  
  // Validate against allowed values
  const allowedStatuses = ['active', 'pending', 'completed', 'cancelled'];
  if (!allowedStatuses.includes(status)) {
    return res.status(400).send('Invalid status');
  }
  
  try {
    // ok: javascript-no-sql-injection-ide
    const orders = await db.collection('orders').find({ status: status }).toArray();
    res.json(orders);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 6: Using numeric validation for query parameters
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_6(req, res) {
  let minPrice = req.query.minPrice;
  let maxPrice = req.query.maxPrice;
  
  // Validate and convert to numbers
  minPrice = Number(minPrice);
  maxPrice = Number(maxPrice);
  
  if (isNaN(minPrice) || isNaN(maxPrice) || minPrice < 0 || maxPrice < minPrice) {
    return res.status(400).send('Invalid price range');
  }
  
  try {
    // ok: javascript-no-sql-injection-ide
    const products = await db.collection('products').find({
      price: { $gte: minPrice, $lte: maxPrice }
    }).toArray();
    
    res.json(products);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 7: Using regex pattern validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_7(req, res) {
  const email = req.query.email;
  
  // Validate email format
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).send('Invalid email format');
  }
  
  try {
    // ok: javascript-no-sql-injection-ide
    const user = await db.collection('users').findOne({ email: email });
    res.json(user || { message: 'User not found' });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 8: Using a sanitization library
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_8(req, res) {
  const searchTerm = req.query.search;
  
  // Simple sanitization function (in real code, use a proper library)
  function sanitize(input) {
    if (typeof input !== 'string') return '';
    return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // Escape special characters
  }
  
  const sanitizedTerm = sanitize(searchTerm);
  
  try {
    // ok: javascript-no-sql-injection-ide
    const results = await db.collection('products').find({
      name: { $regex: sanitizedTerm, $options: 'i' }
    }).toArray();
    
    res.json(results);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 9: Using parameterized query with fixed structure
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_9(req, res) {
  const category = req.query.category;
  const minRating = Number(req.query.minRating) || 0;
  
  // Validate category
  if (typeof category !== 'string' || category.length > 50) {
    return res.status(400).send('Invalid category');
  }
  
  // Validate rating
  if (minRating < 0 || minRating > 5) {
    return res.status(400).send('Rating must be between 0 and 5');
  }
  
  try {
    // ok: javascript-no-sql-injection-ide
    const query = {
      category: category,
      rating: { $gte: minRating }
    };
    
    const products = await db.collection('products').find(query).toArray();
    res.json(products);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 10: Using type checking and validation for array inputs
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_10(req, res) {
  let tags = req.query.tags;
  
  // Ensure tags is an array
  if (typeof tags === 'string') {
    tags = [tags];
  } else if (!Array.isArray(tags)) {
    return res.status(400).send('Tags must be a string or array');
  }
  
  // Validate each tag
  for (const tag of tags) {
    if (typeof tag !== 'string' || tag.length > 50) {
      return res.status(400).send('Invalid tag format');
    }
  }
  
  try {
    // ok: javascript-no-sql-injection-ide
    const articles = await db.collection('articles').find({
      tags: { $in: tags }
    }).toArray();
    
    res.json(articles);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 11: Using a validation middleware
function validateUserInput(req, res, next) {
  const { username, email } = req.body;
  
  if (!username || typeof username !== 'string' || username.length < 3) {
    return res.status(400).send('Invalid username');
  }
  
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!email || !emailRegex.test(email)) {
    return res.status(400).send('Invalid email');
  }
  
  next();
}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_11(req, res) {
  // Assume validateUserInput middleware has already run
  const { username, email } = req.body;
  
  try {
    // ok: javascript-no-sql-injection-ide
    const existingUser = await db.collection('users').findOne({
      $or: [{ username }, { email }]
    });
    
    if (existingUser) {
      return res.status(409).send('Username or email already exists');
    }
    
    const result = await db.collection('users').insertOne({
      username,
      email,
      createdAt: new Date()
    });
    
    res.status(201).json({ success: true, id: result.insertedId });
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 12: Using projection to limit returned fields
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_12(req, res) {
  const username = req.params.username;
  
  // Validate username format
  if (typeof username !== 'string' || !username.match(/^[a-zA-Z0-9_]{3,30}$/)) {
    return res.status(400).send('Invalid username format');
  }
  
  try {
    // ok: javascript-no-sql-injection-ide
    const user = await db.collection('users').findOne(
      { username: username },
      { projection: { password: 0, securityQuestions: 0 } } // Exclude sensitive fields
    );
    
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    res.json(user);
  } catch (err) {
    res.status(500).send(err.message);
  }
}
// {/fact}

// Good Case 13: Using a data access layer with validation
const dataAccessLayer = {
  async findUserByEmail(email) {
    // Validate email format
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      throw new Error('Invalid email format');
    }
    
    return await db.collection('users').findOne({ email });
  }
};

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_13(req, res) {
  const email = req.query.email;
  
  try {
    // ok: javascript-no-sql-injection-ide
    const user = await dataAccessLayer.findUserByEmail(email);
    res.json(user || { message: 'User not found' });
  } catch (err) {
    res.status(400).send(err.message);
  }
}
// {/fact}

// Good Case 14: Using a query builder with validation
class QueryBuilder {
  constructor(collection) {
    this.collection = collection;
    this.queryObj = {};
  }
  
  withStatus(status) {
    const validStatuses = ['active', 'inactive', 'pending'];
    if (!validStatuses.includes(status)) {
      throw new Error('Invalid status');
    }
    this.queryObj.status = status;
    return this;
  }
  
  withCategory(category) {
    if (typeof category !== 'string' || category.length > 50) {
      throw new Error('Invalid category');
    }
    this.queryObj.category = category;
    return this;
  }
  
  async execute() {
    return await this.collection.find(this.queryObj).toArray();
  }
}

// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_14(req, res) {
  const status = req.query.status;
  const category = req.query.category;
  
  try {
    const queryBuilder = new QueryBuilder(db.collection('products'));
    
    if (status) {
      queryBuilder.withStatus(status);
    }
    
    if (category) {
      queryBuilder.withCategory(category);
    }
    
    // ok: javascript-no-sql-injection-ide
    const products = await queryBuilder.execute();
    res.json(products);
  } catch (err) {
    res.status(400).send(err.message);
  }
}
// {/fact}

// Good Case 15: Using JSON schema validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_15(req, res) {
  const userData = req.body;
  
  // Define schema for validation
  const userSchema = {
    type: 'object',
    required: ['username', 'email'],
    properties: {
      username: { type: 'string', minLength: 3, maxLength: 30, pattern: '^[a-zA-Z0-9_]+$' },
      email: { type: 'string', format: 'email' },
      age: { type: 'number', minimum: 18, maximum: 120 }
    },
    additionalProperties: false
  };
  
  // Simple schema validator (in real code, use a library like ajv)
  function validateSchema(data, schema) {
    // This is a simplified validator - in real code use a proper library
    if (schema.type === 'object' && typeof data !== 'object') {
      throw new Error('Expected object');
    }
    
    if (schema.required) {
      for (const field of schema.required) {
        if (data[field] === undefined) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
    }
    
    for (const [key, value] of Object.entries(data)) {
      const propSchema = schema.properties[key];
      if (!propSchema) {
        if (schema.additionalProperties === false) {
          throw new Error(`Unknown property: ${key}`);
        }
        continue;
      }
      
      if (propSchema.type === 'string' && typeof value !== 'string') {
        throw new Error(`${key} must be a string`);
      }
      
      if (propSchema.type === 'number' && typeof value !== 'number') {
        throw new Error(`${key} must be a number`);
      }
      
      if (propSchema.minLength && value.length < propSchema.minLength) {
        throw new Error(`${key} is too short`);
      }
      
      if (propSchema.maxLength && value.length > propSchema.maxLength) {
        throw new Error(`${key} is too long`);
      }
    }
    
    return true;
  }
  
  try {
    validateSchema(userData, userSchema);
    
    // ok: javascript-no-sql-injection-ide
    const result = await db.collection('users').insertOne(userData);
    res.status(201).json({ success: true, id: result.insertedId });
  } catch (err) {
    res.status(400).send(err.message);
  }
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await connectToDatabase();
  console.log(`Server running on port ${PORT}`);
});