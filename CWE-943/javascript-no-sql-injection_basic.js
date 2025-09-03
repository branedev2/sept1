const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const mongoose = require('mongoose');
const sanitize = require('mongo-sanitize');
const app = express();
app.use(express.json());

// MongoDB connection setup
const uri = "mongodb://localhost:27017";
const client = new MongoClient(uri);
let db;

// Connect to MongoDB
async function connectToMongo() {
  try {
    await client.connect();
    db = client.db("testdb");
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error);
  }
}
connectToMongo();

// Mongoose setup
mongoose.connect('mongodb://localhost:27017/testdb');
const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: String
}));

// BAD CASES (True Positives)

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_1(req, res) {
  const username = req.query.username;
  
  // ruleid: javascript-no-sql-injection
  db.collection('users').find({
    username: username
  }).toArray((err, users) => {
    if (err) return res.status(500).send(err);
    res.json(users);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_2(req, res) {
  const userId = req.params.id;
  const userInput = req.body;
  
  // ruleid: javascript-no-sql-injection
  db.collection('users').updateOne(
    { _id: userId },
    { $set: userInput },
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json(result);
    }
  );
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_3(req, res) {
  const query = {};
  query[req.query.field] = req.query.value;
  
  // ruleid: javascript-no-sql-injection
  db.collection('products').find(query).toArray((err, products) => {
    if (err) return res.status(500).send(err);
    res.json(products);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_4(req, res) {
  const searchTerm = req.query.search;
  const query = { $where: `this.description.includes("${searchTerm}")` };
  
  // ruleid: javascript-no-sql-injection
  db.collection('products').find(query).toArray((err, products) => {
    if (err) return res.status(500).send(err);
    res.json(products);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_5(req, res) {
  const username = req.body.username;
  const password = req.body.password;
  
  // ruleid: javascript-no-sql-injection
  User.findOne({ username: username, password: password }, (err, user) => {
    if (err) return res.status(500).send(err);
    if (!user) return res.status(401).send('Invalid credentials');
    res.json(user);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_6(req, res) {
  const userRole = req.query.role;
  const sortField = req.query.sort;
  
  // ruleid: javascript-no-sql-injection
  db.collection('users').find({ role: userRole }).sort({ [sortField]: 1 }).toArray((err, users) => {
    if (err) return res.status(500).send(err);
    res.json(users);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_7(req, res) {
  const filter = JSON.parse(req.query.filter);
  
  // ruleid: javascript-no-sql-injection
  db.collection('orders').find(filter).toArray((err, orders) => {
    if (err) return res.status(500).send(err);
    res.json(orders);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_8(req, res) {
  const email = req.body.email;
  
  // ruleid: javascript-no-sql-injection
  db.collection('users').deleteMany({ email: { $regex: email } }, (err, result) => {
    if (err) return res.status(500).send(err);
    res.json(result);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_9(req, res) {
  const pipeline = [
    { $match: { category: req.query.category } },
    { $group: { _id: "$" + req.query.groupBy, count: { $sum: 1 } } }
  ];
  
  // ruleid: javascript-no-sql-injection
  db.collection('products').aggregate(pipeline).toArray((err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_10(req, res) {
  const username = req.cookies.username;
  
  // ruleid: javascript-no-sql-injection
  User.findOneAndUpdate(
    { username: username },
    { $set: { lastLogin: new Date() } },
    { new: true },
    (err, user) => {
      if (err) return res.status(500).send(err);
      res.json(user);
    }
  );
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_11(req, res) {
  const searchQuery = {};
  
  if (req.query.name) {
    searchQuery.name = { $regex: req.query.name, $options: 'i' };
  }
  
  if (req.query.minPrice) {
    searchQuery.price = { $gte: parseFloat(req.query.minPrice) };
  }
  
  // ruleid: javascript-no-sql-injection
  db.collection('products').find(searchQuery).toArray((err, products) => {
    if (err) return res.status(500).send(err);
    res.json(products);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_12(req, res) {
  const userInput = req.body.query;
  const query = { $text: { $search: userInput } };
  
  // ruleid: javascript-no-sql-injection
  db.collection('articles').find(query).toArray((err, articles) => {
    if (err) return res.status(500).send(err);
    res.json(articles);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_13(req, res) {
  const field = req.query.field || 'username';
  const value = req.query.value || '';
  
  // ruleid: javascript-no-sql-injection
  User.find().where(field).equals(value).exec((err, users) => {
    if (err) return res.status(500).send(err);
    res.json(users);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_14(req, res) {
  const operations = req.body.operations.map(op => {
    return {
      updateOne: {
        filter: { _id: op.id },
        update: { $set: op.changes }
      }
    };
  });
  
  // ruleid: javascript-no-sql-injection
  db.collection('products').bulkWrite(operations, (err, result) => {
    if (err) return res.status(500).send(err);
    res.json(result);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_15(req, res) {
  const mapFunction = `function() { 
    if(this.category === "${req.query.category}") {
      emit(this._id, this.price);
    }
  }`;
  
  const reduceFunction = 'function(key, values) { return Array.sum(values); }';
  
  // ruleid: javascript-no-sql-injection
  db.collection('products').mapReduce(
    mapFunction,
    reduceFunction,
    { out: { inline: 1 } },
    (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results);
    }
  );
}
// {/fact}

// GOOD CASES (True Negatives)

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_1(req, res) {
  const username = req.query.username;
  
  // ok: javascript-no-sql-injection
  db.collection('users').find({
    username: sanitize(username)
  }).toArray((err, users) => {
    if (err) return res.status(500).send(err);
    res.json(users);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_2(req, res) {
  const userId = req.params.id;
  const userInput = req.body;
  const sanitizedInput = sanitize(userInput);
  
  // ok: javascript-no-sql-injection
  db.collection('users').updateOne(
    { _id: ObjectId(userId) },
    { $set: sanitizedInput },
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json(result);
    }
  );
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_3(req, res) {
  const field = req.query.field;
  const value = req.query.value;
  
  // Validate field against whitelist
  const allowedFields = ['name', 'category', 'price'];
  if (!allowedFields.includes(field)) {
    return res.status(400).send('Invalid field');
  }
  
  const query = {};
  // ok: javascript-no-sql-injection
  query[sanitize(field)] = sanitize(value);
  
  db.collection('products').find(query).toArray((err, products) => {
    if (err) return res.status(500).send(err);
    res.json(products);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_4(req, res) {
  const searchTerm = req.query.search;
  
  // ok: javascript-no-sql-injection
  db.collection('products').find({ 
    description: { $regex: sanitize(searchTerm), $options: 'i' } 
  }).toArray((err, products) => {
    if (err) return res.status(500).send(err);
    res.json(products);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_5(req, res) {
  const username = req.body.username;
  const password = req.body.password;
  
  // ok: javascript-no-sql-injection
  User.findOne({ 
    username: sanitize(username)
  }, (err, user) => {
    if (err) return res.status(500).send(err);
    if (!user) return res.status(401).send('Invalid credentials');
    
    // Compare password hash instead of storing plaintext
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) return res.status(401).send('Invalid credentials');
      res.json(user);
    });
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_6(req, res) {
  const userRole = req.query.role;
  const sortField = req.query.sort;
  
  // Validate sort field against whitelist
  const allowedSortFields = ['name', 'email', 'createdAt'];
  if (!allowedSortFields.includes(sortField)) {
    return res.status(400).send('Invalid sort field');
  }
  
  // ok: javascript-no-sql-injection
  db.collection('users').find({ 
    role: sanitize(userRole) 
  }).sort({ 
    [sortField]: 1 
  }).toArray((err, users) => {
    if (err) return res.status(500).send(err);
    res.json(users);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_7(req, res) {
  try {
    const filter = JSON.parse(req.query.filter);
    const sanitizedFilter = sanitize(filter);
    
    // ok: javascript-no-sql-injection
    db.collection('orders').find(sanitizedFilter).toArray((err, orders) => {
      if (err) return res.status(500).send(err);
      res.json(orders);
    });
  } catch (e) {
    res.status(400).send('Invalid filter format');
  }
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_8(req, res) {
  const email = req.body.email;
  
  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).send('Invalid email format');
  }
  
  // ok: javascript-no-sql-injection
  db.collection('users').deleteMany({ 
    email: sanitize(email) 
  }, (err, result) => {
    if (err) return res.status(500).send(err);
    res.json(result);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_9(req, res) {
  const category = req.query.category;
  
  // Validate groupBy against whitelist
  const allowedGroupByFields = ['category', 'manufacturer', 'year'];
  const groupBy = req.query.groupBy;
  
  if (!allowedGroupByFields.includes(groupBy)) {
    return res.status(400).send('Invalid groupBy field');
  }
  
  const pipeline = [
    { $match: { category: sanitize(category) } },
    { $group: { _id: "$" + groupBy, count: { $sum: 1 } } }
  ];
  
  // ok: javascript-no-sql-injection
  db.collection('products').aggregate(pipeline).toArray((err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_10(req, res) {
  const username = req.cookies.username;
  
  // ok: javascript-no-sql-injection
  User.findOneAndUpdate(
    { username: sanitize(username) },
    { $set: { lastLogin: new Date() } },
    { new: true },
    (err, user) => {
      if (err) return res.status(500).send(err);
      res.json(user);
    }
  );
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_11(req, res) {
  const searchQuery = {};
  
  if (req.query.name) {
    // ok: javascript-no-sql-injection
    searchQuery.name = { $regex: sanitize(req.query.name), $options: 'i' };
  }
  
  if (req.query.minPrice) {
    const minPrice = parseFloat(req.query.minPrice);
    if (isNaN(minPrice)) {
      return res.status(400).send('Invalid price format');
    }
    searchQuery.price = { $gte: minPrice };
  }
  
  db.collection('products').find(searchQuery).toArray((err, products) => {
    if (err) return res.status(500).send(err);
    res.json(products);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_12(req, res) {
  const userInput = req.body.query;
  
  // ok: javascript-no-sql-injection
  db.collection('articles').find({ 
    $text: { $search: sanitize(userInput) } 
  }).toArray((err, articles) => {
    if (err) return res.status(500).send(err);
    res.json(articles);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_13(req, res) {
  const field = req.query.field || 'username';
  const value = req.query.value || '';
  
  // Validate field against whitelist
  const allowedFields = ['username', 'email', 'role'];
  if (!allowedFields.includes(field)) {
    return res.status(400).send('Invalid field');
  }
  
  // ok: javascript-no-sql-injection
  User.find().where(field).equals(sanitize(value)).exec((err, users) => {
    if (err) return res.status(500).send(err);
    res.json(users);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_14(req, res) {
  const operations = req.body.operations.map(op => {
    // Validate ID format
    if (!ObjectId.isValid(op.id)) {
      throw new Error('Invalid ID format');
    }
    
    return {
      updateOne: {
        filter: { _id: ObjectId(op.id) },
        update: { $set: sanitize(op.changes) }
      }
    };
  });
  
  // ok: javascript-no-sql-injection
  db.collection('products').bulkWrite(operations, (err, result) => {
    if (err) return res.status(500).send(err);
    res.json(result);
  });
}
// {/fact}

// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_15(req, res) {
  const category = req.query.category;
  
  // Validate category against whitelist
  const allowedCategories = ['electronics', 'books', 'clothing'];
  if (!allowedCategories.includes(category)) {
    return res.status(400).send('Invalid category');
  }
  
  // ok: javascript-no-sql-injection
  db.collection('products').find({ 
    category: category 
  }).toArray((err, products) => {
    if (err) return res.status(500).send(err);
    
    // Process the data in JavaScript instead of using mapReduce
    const total = products.reduce((sum, product) => sum + product.price, 0);
    res.json({ category, total });
  });
}
// {/fact}

module.exports = app;