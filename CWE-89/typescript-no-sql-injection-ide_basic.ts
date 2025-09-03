// File: nosql_injection_test_cases.ts

import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import mongoose from 'mongoose';
import { Request, Response } from 'express';
import { Filter } from 'mongodb';
import * as validator from 'validator';
import { sanitize } from 'mongo-sanitize';

// MongoDB connection setup
const mongoUri = 'mongodb://localhost:27017/testdb';
let db: any;

// Connect to MongoDB
async function connectToMongo() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  db = client.db();
  return db;
}

// Mongoose setup
mongoose.connect(mongoUri);
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: String
});
const User = mongoose.model('User', UserSchema);

// Express app setup
const app = express();
app.use(express.json());

// ==================== VULNERABLE CASES (TRUE POSITIVES) ====================

// Case 1: Direct use of query parameter in find operation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
  const username = req.query.username as string;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('users').find({ username: username }).toArray((err: any, users: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(users);
    });
  });
}
// {/fact}

// Case 2: Using request body in update operation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
  const userId = req.params.id;
  const userInput = req.body;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('users').updateOne(
      { _id: userId },
      { $set: userInput },
      (err: any, result: any) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json(result);
      }
    );
  });
}
// {/fact}

// Case 3: Using string template for query construction
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
  const role = req.query.role as string;
  
  connectToMongo().then(db => {
    const query = { role: role };
    
    // ruleid: typescript-no-sql-injection-ide
    db.collection('users').find(query).toArray((err: any, users: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(users);
    });
  });
}
// {/fact}

// Case 4: Using JSON.parse with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
  const filterStr = req.query.filter as string;
  
  try {
    const filter = JSON.parse(filterStr);
    
    connectToMongo().then(db => {
      // ruleid: typescript-no-sql-injection-ide
      db.collection('users').find(filter).toArray((err: any, users: any[]) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json(users);
      });
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
}
// {/fact}

// Case 5: Using mongoose with direct query parameter
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
  const email = req.query.email as string;
  
  // ruleid: typescript-no-sql-injection-ide
  User.findOne({ email: email }, (err: any, user: any) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  });
}
// {/fact}

// Case 6: Using request header in query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
  const apiKey = req.headers['x-api-key'] as string;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('api_keys').findOne({ key: apiKey }, (err: any, result: any) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (!result) {
        return res.status(401).json({ message: 'Invalid API key' });
      }
      res.json({ valid: true });
    });
  });
}
// {/fact}

// Case 7: Using cookie value in query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
  const sessionId = req.cookies.sessionId;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('sessions').findOne({ id: sessionId }, (err: any, session: any) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (!session) {
        return res.status(401).json({ message: 'Invalid session' });
      }
      res.json({ valid: true });
    });
  });
}
// {/fact}

// Case 8: Using dynamic property name from user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
  const field = req.query.field as string;
  const value = req.query.value as string;
  
  const query: any = {};
  query[field] = value;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('users').find(query).toArray((err: any, users: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(users);
    });
  });
}
// {/fact}

// Case 9: Using request parameters in aggregation pipeline
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
  const minAge = req.query.minAge as string;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('users').aggregate([
      { $match: { age: { $gte: minAge } } },
      { $group: { _id: "$city", count: { $sum: 1 } } }
    ]).toArray((err: any, results: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(results);
    });
  });
}
// {/fact}

// Case 10: Using request body in deleteMany operation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
  const criteria = req.body.criteria;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('logs').deleteMany(criteria, (err: any, result: any) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ deletedCount: result.deletedCount });
    });
  });
}
// {/fact}

// Case 11: Using query parameter in findOneAndUpdate
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
  const username = req.query.username as string;
  const newEmail = req.body.email;
  
  // ruleid: typescript-no-sql-injection-ide
  User.findOneAndUpdate(
    { username: username },
    { $set: { email: newEmail } },
    { new: true },
    (err: any, user: any) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    }
  );
}
// {/fact}

// Case 12: Using request parameter in complex query
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
  const status = req.query.status as string;
  const category = req.query.category as string;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('products').find({
      status: status,
      category: category,
      inStock: true
    }).toArray((err: any, products: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(products);
    });
  });
}
// {/fact}

// Case 13: Using request body in bulkWrite operation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
  const operations = req.body.operations;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('inventory').bulkWrite(operations, (err: any, result: any) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Case 14: Using query parameter in distinct operation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
  const field = req.query.field as string;
  const query = req.query.query ? JSON.parse(req.query.query as string) : {};
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('products').distinct(field, query, (err: any, values: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(values);
    });
  });
}
// {/fact}

// Case 15: Using request parameter in countDocuments
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
  const department = req.query.department as string;
  
  connectToMongo().then(db => {
    // ruleid: typescript-no-sql-injection-ide
    db.collection('employees').countDocuments({ department: department }, (err: any, count: number) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ count });
    });
  });
}
// {/fact}

// ==================== SAFE CASES (TRUE NEGATIVES) ====================

// Case 1: Using sanitized input in find operation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
  const username = req.query.username as string;
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('users').find({ username: sanitize(username) }).toArray((err: any, users: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(users);
    });
  });
}
// {/fact}

// Case 2: Using validated ObjectId for queries
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
  const userId = req.params.id;
  
  if (!ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('users').findOne({ _id: new ObjectId(userId) }, (err: any, user: any) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    });
  });
}
// {/fact}

// Case 3: Using schema validation before update
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
  const userId = req.params.id;
  const userInput = req.body;
  
  // Validate input against schema
  const allowedFields = ['name', 'email', 'age'];
  const sanitizedInput: Record<string, any> = {};
  
  for (const field of allowedFields) {
    if (userInput[field] !== undefined) {
      sanitizedInput[field] = userInput[field];
    }
  }
  
  if (!ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: sanitizedInput },
      (err: any, result: any) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json(result);
      }
    );
  });
}
// {/fact}

// Case 4: Using whitelisted values for query
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
  const role = req.query.role as string;
  const allowedRoles = ['admin', 'user', 'guest'];
  
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('users').find({ role: role }).toArray((err: any, users: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(users);
    });
  });
}
// {/fact}

// Case 5: Using type checking and validation for numeric values
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
  const ageStr = req.query.age as string;
  let age: number;
  
  if (!ageStr || isNaN(age = parseInt(ageStr))) {
    return res.status(400).json({ error: 'Invalid age parameter' });
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('users').find({ age: { $gte: age } }).toArray((err: any, users: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(users);
    });
  });
}
// {/fact}

// Case 6: Using regex validation for email
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
  const email = req.query.email as string;
  
  if (!email || !validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  
  // ok: typescript-no-sql-injection-ide
  User.findOne({ email: email }, (err: any, user: any) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  });
}
// {/fact}

// Case 7: Using hardcoded query with parameterized user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
  const username = req.query.username as string;
  
  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Invalid username parameter' });
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('users').find({ 
      username: sanitize(username),
      active: true,
      verified: true
    }).toArray((err: any, users: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(users);
    });
  });
}
// {/fact}

// Case 8: Using validated and sanitized input in aggregation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
  const minAgeStr = req.query.minAge as string;
  let minAge: number;
  
  if (!minAgeStr || isNaN(minAge = parseInt(minAgeStr)) || minAge < 0) {
    return res.status(400).json({ error: 'Invalid minimum age' });
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('users').aggregate([
      { $match: { age: { $gte: minAge } } },
      { $group: { _id: "$city", count: { $sum: 1 } } }
    ]).toArray((err: any, results: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(results);
    });
  });
}
// {/fact}

// Case 9: Using predefined query patterns with user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
  const searchTerm = req.query.q as string;
  
  if (!searchTerm || typeof searchTerm !== 'string') {
    return res.status(400).json({ error: 'Invalid search term' });
  }
  
  const sanitizedTerm = sanitize(searchTerm);
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('products').find({
      $or: [
        { name: { $regex: sanitizedTerm, $options: 'i' } },
        { description: { $regex: sanitizedTerm, $options: 'i' } }
      ]
    }).toArray((err: any, products: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(products);
    });
  });
}
// {/fact}

// Case 10: Using validated input with mongoose
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
  const username = req.query.username as string;
  
  if (!username || typeof username !== 'string' || username.length < 3) {
    return res.status(400).json({ error: 'Invalid username' });
  }
  
  // ok: typescript-no-sql-injection-ide
  User.findOne({ username: sanitize(username) })
    .select('-password')
    .exec((err: any, user: any) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    });
}
// {/fact}

// Case 11: Using type-safe query construction
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
  const status = req.query.status as string;
  const category = req.query.category as string;
  
  const validStatuses = ['active', 'pending', 'archived'];
  const validCategories = ['electronics', 'clothing', 'books', 'home'];
  
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Invalid category' });
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('products').find({
      status: status,
      category: category,
      inStock: true
    }).toArray((err: any, products: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(products);
    });
  });
}
// {/fact}

// Case 12: Using strict schema validation for bulk operations
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
  const rawOperations = req.body.operations;
  
  if (!Array.isArray(rawOperations)) {
    return res.status(400).json({ error: 'Operations must be an array' });
  }
  
  const validatedOperations = [];
  
  for (const op of rawOperations) {
    if (!op.type || !['insert', 'update', 'delete'].includes(op.type)) {
      return res.status(400).json({ error: 'Invalid operation type' });
    }
    
    if (op.type === 'insert' && typeof op.document === 'object') {
      // Sanitize and validate insert document
      const sanitizedDoc = sanitize(op.document);
      validatedOperations.push({ insertOne: { document: sanitizedDoc } });
    } else if (op.type === 'update' && op.filter && op.update) {
      // Validate ID and sanitize update
      if (!ObjectId.isValid(op.filter.id)) {
        return res.status(400).json({ error: 'Invalid ID in update operation' });
      }
      const sanitizedUpdate = sanitize(op.update);
      validatedOperations.push({
        updateOne: {
          filter: { _id: new ObjectId(op.filter.id) },
          update: { $set: sanitizedUpdate }
        }
      });
    }
    // Add more validation for other operation types
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('inventory').bulkWrite(validatedOperations, (err: any, result: any) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Case 13: Using validated field name for distinct operation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
  const field = req.query.field as string;
  
  const allowedFields = ['category', 'brand', 'color', 'size'];
  
  if (!allowedFields.includes(field)) {
    return res.status(400).json({ error: 'Invalid field name' });
  }
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('products').distinct(field, { active: true }, (err: any, values: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(values);
    });
  });
}
// {/fact}

// Case 14: Using parameterized query with mongoose
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
  const departmentId = req.query.departmentId as string;
  
  if (!ObjectId.isValid(departmentId)) {
    return res.status(400).json({ error: 'Invalid department ID' });
  }
  
  const department = new ObjectId(departmentId);
  
  // ok: typescript-no-sql-injection-ide
  mongoose.model('Employee').find({ department: department })
    .select('name position hireDate')
    .sort({ hireDate: -1 })
    .exec((err: any, employees: any[]) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(employees);
    });
}
// {/fact}

// Case 15: Using validated and sanitized input for countDocuments
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
  const department = req.query.department as string;
  
  if (!department || typeof department !== 'string') {
    return res.status(400).json({ error: 'Invalid department parameter' });
  }
  
  const sanitizedDepartment = sanitize(department);
  
  connectToMongo().then(db => {
    // ok: typescript-no-sql-injection-ide
    db.collection('employees').countDocuments(
      { department: sanitizedDepartment },
      (err: any, count: number) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ count });
      }
    );
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});