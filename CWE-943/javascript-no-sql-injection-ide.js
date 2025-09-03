// NoSQL Injection Test Cases
const express = require('express');
const mongodb = require('mongodb');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb');
const sanitize = require('mongo-sanitize');
const app = express();
app.use(express.json());

// MongoDB connection setup
const uri = "mongodb://localhost:27017";
const client = new MongoClient(uri);
const db = client.db("testdb");

// Mongoose setup
mongoose.connect('mongodb://localhost:27017/testdb');
const User = mongoose.model('User', { username: String, password: String });

// TRUE POSITIVES - Vulnerable code examples

// Bad case 1: Direct use of user input in find query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_1(req, res) {
    const username = req.query.username;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('users').find({ username: username }).toArray((err, users) => {
        if (err) {
            return res.status(500).send('Error fetching users');
        }
        res.json(users);
    });
}
// {/fact}

// Bad case 2: Using user input in query with operators
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_2(req, res) {
    const minAge = req.query.minAge;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('users').find({ age: { $gt: minAge } }).toArray((err, users) => {
        if (err) {
            return res.status(500).send('Error fetching users');
        }
        res.json(users);
    });
}
// {/fact}

// Bad case 3: Using user input in findOne query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_3(req, res) {
    const userId = req.params.id;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('users').findOne({ _id: userId }, (err, user) => {
        if (err) {
            return res.status(500).send('Error fetching user');
        }
        res.json(user);
    });
}
// {/fact}

// Bad case 4: Using user input in update query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_4(req, res) {
    const username = req.body.username;
    const newRole = req.body.role;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('users').updateOne(
        { username: username },
        { $set: { role: newRole } },
        (err, result) => {
            if (err) {
                return res.status(500).send('Error updating user');
            }
            res.json({ success: true });
        }
    );
}
// {/fact}

// Bad case 5: Using user input in delete query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_5(req, res) {
    const email = req.query.email;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('users').deleteMany({ email: email }, (err, result) => {
        if (err) {
            return res.status(500).send('Error deleting users');
        }
        res.json({ deleted: result.deletedCount });
    });
}
// {/fact}

// Bad case 6: Using JSON.parse on user input for query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_6(req, res) {
    const queryString = req.query.filter;
    const filter = JSON.parse(queryString);
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('products').find(filter).toArray((err, products) => {
        if (err) {
            return res.status(500).send('Error fetching products');
        }
        res.json(products);
    });
}
// {/fact}

// Bad case 7: Using user input in aggregation pipeline
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_7(req, res) {
    const category = req.query.category;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('products').aggregate([
        { $match: { category: category } },
        { $group: { _id: "$brand", count: { $sum: 1 } } }
    ]).toArray((err, results) => {
        if (err) {
            return res.status(500).send('Error aggregating products');
        }
        res.json(results);
    });
}
// {/fact}

// Bad case 8: Using user input in mongoose query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_8(req, res) {
    const username = req.query.username;
    
    // ruleid: javascript-no-sql-injection-ide
    User.find({ username: username }, (err, users) => {
        if (err) {
            return res.status(500).send('Error finding users');
        }
        res.json(users);
    });
}
// {/fact}

// Bad case 9: Using template literals with user input
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_9(req, res) {
    const status = req.query.status;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('orders').find({ status: `${status}` }).toArray((err, orders) => {
        if (err) {
            return res.status(500).send('Error fetching orders');
        }
        res.json(orders);
    });
}
// {/fact}

// Bad case 10: Using user input in complex query object
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_10(req, res) {
    const searchTerm = req.query.search;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('products').find({
        $or: [
            { name: searchTerm },
            { description: searchTerm }
        ]
    }).toArray((err, products) => {
        if (err) {
            return res.status(500).send('Error searching products');
        }
        res.json(products);
    });
}
// {/fact}

// Bad case 11: Using user input in distinct query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_11(req, res) {
    const field = req.query.field;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('products').distinct(field, (err, values) => {
        if (err) {
            return res.status(500).send('Error getting distinct values');
        }
        res.json(values);
    });
}
// {/fact}

// Bad case 12: Using user input in findOneAndUpdate
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_12(req, res) {
    const userId = req.params.id;
    const updates = req.body;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('users').findOneAndUpdate(
        { _id: userId },
        { $set: updates },
        { returnOriginal: false },
        (err, result) => {
            if (err) {
                return res.status(500).send('Error updating user');
            }
            res.json(result.value);
        }
    );
}
// {/fact}

// Bad case 13: Using user input in count query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_13(req, res) {
    const status = req.query.status;
    
    // ruleid: javascript-no-sql-injection-ide
    db.collection('orders').countDocuments({ status: status }, (err, count) => {
        if (err) {
            return res.status(500).send('Error counting orders');
        }
        res.json({ count });
    });
}
// {/fact}

// Bad case 14: Using user input in bulkWrite operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_14(req, res) {
    const userIds = req.body.userIds;
    const operations = userIds.map(id => ({
        updateOne: {
            // ruleid: javascript-no-sql-injection-ide
            filter: { _id: id },
            update: { $set: { active: false } }
        }
    }));
    
    db.collection('users').bulkWrite(operations, (err, result) => {
        if (err) {
            return res.status(500).send('Error deactivating users');
        }
        res.json({ success: true });
    });
}
// {/fact}

// Bad case 15: Using user input in mongoose updateMany
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_15(req, res) {
    const role = req.query.role;
    const newPermission = req.body.permission;
    
    // ruleid: javascript-no-sql-injection-ide
    User.updateMany(
        { role: role },
        { $push: { permissions: newPermission } },
        (err, result) => {
            if (err) {
                return res.status(500).send('Error updating permissions');
            }
            res.json({ modified: result.nModified });
        }
    );
}
// {/fact}

// TRUE NEGATIVES - Safe code examples

// Good case 1: Sanitizing user input before using in find query
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_1(req, res) {
    const username = req.query.username;
    
    // ok: javascript-no-sql-injection-ide
    const sanitizedUsername = sanitize(username);
    db.collection('users').find({ username: sanitizedUsername }).toArray((err, users) => {
        if (err) {
            return res.status(500).send('Error fetching users');
        }
        res.json(users);
    });
}
// {/fact}

// Good case 2: Validating and converting user input to appropriate type
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_2(req, res) {
    let minAge = req.query.minAge;
    
    // ok: javascript-no-sql-injection-ide
    minAge = parseInt(minAge, 10);
    if (isNaN(minAge)) {
        return res.status(400).send('Invalid age parameter');
    }
    
    db.collection('users').find({ age: { $gt: minAge } }).toArray((err, users) => {
        if (err) {
            return res.status(500).send('Error fetching users');
        }
        res.json(users);
    });
}
// {/fact}

// Good case 3: Using MongoDB ObjectId for ID parameters
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_3(req, res) {
    const userId = req.params.id;
    
    try {
        // ok: javascript-no-sql-injection-ide
        const objectId = new mongodb.ObjectId(userId);
        db.collection('users').findOne({ _id: objectId }, (err, user) => {
            if (err) {
                return res.status(500).send('Error fetching user');
            }
            res.json(user);
        });
    } catch (e) {
        return res.status(400).send('Invalid user ID');
    }
}
// {/fact}

// Good case 4: Validating input against a whitelist
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_4(req, res) {
    const role = req.query.role;
    const validRoles = ['user', 'admin', 'editor'];
    
    // ok: javascript-no-sql-injection-ide
    if (!validRoles.includes(role)) {
        return res.status(400).send('Invalid role');
    }
    
    db.collection('users').find({ role: role }).toArray((err, users) => {
        if (err) {
            return res.status(500).send('Error fetching users');
        }
        res.json(users);
    });
}
// {/fact}

// Good case 5: Using schema validation with mongoose
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_5(req, res) {
    const userData = req.body;
    
    // ok: javascript-no-sql-injection-ide
    const newUser = new User(userData);
    newUser.validate((err) => {
        if (err) {
            return res.status(400).send('Invalid user data');
        }
        
        newUser.save((saveErr, savedUser) => {
            if (saveErr) {
                return res.status(500).send('Error saving user');
            }
            res.json(savedUser);
        });
    });
}
// {/fact}

// Good case 6: Using regex pattern matching for validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_6(req, res) {
    const email = req.query.email;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    // ok: javascript-no-sql-injection-ide
    if (!emailRegex.test(email)) {
        return res.status(400).send('Invalid email format');
    }
    
    db.collection('users').find({ email: email }).toArray((err, users) => {
        if (err) {
            return res.status(500).send('Error fetching users');
        }
        res.json(users);
    });
}
// {/fact}

// Good case 7: Using projection to limit returned fields
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_7(req, res) {
    const username = req.query.username;
    
    // ok: javascript-no-sql-injection-ide
    const sanitizedUsername = sanitize(username);
    db.collection('users').find(
        { username: sanitizedUsername },
        { projection: { password: 0, securityQuestions: 0 } }
    ).toArray((err, users) => {
        if (err) {
            return res.status(500).send('Error fetching users');
        }
        res.json(users);
    });
}
// {/fact}

// Good case 8: Using strict comparison for boolean values
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_8(req, res) {
    let isActive = req.query.active;
    
    // ok: javascript-no-sql-injection-ide
    isActive = isActive === 'true';
    
    db.collection('users').find({ active: isActive }).toArray((err, users) => {
        if (err) {
            return res.status(500).send('Error fetching users');
        }
        res.json(users);
    });
}
// {/fact}

// Good case 9: Using mongoose with proper validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_9(req, res) {
    const username = req.query.username;
    
    // ok: javascript-no-sql-injection-ide
    if (typeof username !== 'string' || username.length < 3 || username.length > 20) {
        return res.status(400).send('Invalid username');
    }
    
    User.find({ username: username }, (err, users) => {
        if (err) {
            return res.status(500).send('Error finding users');
        }
        res.json(users);
    });
}
// {/fact}

// Good case 10: Using parameterized query object
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_10(req, res) {
    const category = req.query.category;
    const minPrice = parseFloat(req.query.minPrice);
    const maxPrice = parseFloat(req.query.maxPrice);
    
    // ok: javascript-no-sql-injection-ide
    const query = {};
    
    if (category && typeof category === 'string') {
        query.category = sanitize(category);
    }
    
    if (!isNaN(minPrice) && !isNaN(maxPrice)) {
        query.price = { $gte: minPrice, $lte: maxPrice };
    }
    
    db.collection('products').find(query).toArray((err, products) => {
        if (err) {
            return res.status(500).send('Error fetching products');
        }
        res.json(products);
    });
}
// {/fact}

// Good case 11: Using a validation library
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_11(req, res) {
    const userData = req.body;
    
    // ok: javascript-no-sql-injection-ide
    const schema = {
        username: { type: 'string', min: 3, max: 20, pattern: '^[a-zA-Z0-9_]+$' },
        email: { type: 'email' },
        age: { type: 'number', integer: true, positive: true, optional: true }
    };
    
    const validator = require('fastest-validator');
    const v = new validator();
    const check = v.compile(schema);
    const validationResult = check(userData);
    
    if (validationResult !== true) {
        return res.status(400).json({ errors: validationResult });
    }
    
    db.collection('users').insertOne(userData, (err, result) => {
        if (err) {
            return res.status(500).send('Error creating user');
        }
        res.json({ success: true, id: result.insertedId });
    });
}
// {/fact}

// Good case 12: Using explicit field selection
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_12(req, res) {
    const sortField = req.query.sort;
    const allowedSortFields = ['name', 'price', 'date', 'rating'];
    
    // ok: javascript-no-sql-injection-ide
    const actualSortField = allowedSortFields.includes(sortField) ? sortField : 'name';
    const sortDirection = req.query.dir === 'desc' ? -1 : 1;
    
    const sortOptions = {};
    sortOptions[actualSortField] = sortDirection;
    
    db.collection('products').find().sort(sortOptions).toArray((err, products) => {
        if (err) {
            return res.status(500).send('Error fetching products');
        }
        res.json(products);
    });
}
// {/fact}

// Good case 13: Using aggregation with validated inputs
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_13(req, res) {
    let category = req.query.category;
    let minSales = parseInt(req.query.minSales, 10);
    
    // ok: javascript-no-sql-injection-ide
    category = sanitize(category);
    if (isNaN(minSales)) minSales = 0;
    
    db.collection('products').aggregate([
        { $match: { category: category, sales: { $gte: minSales } } },
        { $group: { _id: "$brand", totalSales: { $sum: "$sales" } } },
        { $sort: { totalSales: -1 } }
    ]).toArray((err, results) => {
        if (err) {
            return res.status(500).send('Error aggregating products');
        }
        res.json(results);
    });
}
// {/fact}

// Good case 14: Using a data access layer with validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_14(req, res) {
    const productId = req.params.id;
    
    // ok: javascript-no-sql-injection-ide
    function validateProductId(id) {
        try {
            return new mongodb.ObjectId(id);
        } catch (e) {
            return null;
        }
    }
    
    const validProductId = validateProductId(productId);
    if (!validProductId) {
        return res.status(400).send('Invalid product ID');
    }
    
    db.collection('products').findOne({ _id: validProductId }, (err, product) => {
        if (err) {
            return res.status(500).send('Error fetching product');
        }
        if (!product) {
            return res.status(404).send('Product not found');
        }
        res.json(product);
    });
}
// {/fact}

// Good case 15: Using a query builder with validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_15(req, res) {
    const filters = req.query.filters;
    
    // ok: javascript-no-sql-injection-ide
    function buildSafeQuery(filterParams) {
        const query = {};
        
        if (filterParams.category && typeof filterParams.category === 'string') {
            query.category = sanitize(filterParams.category);
        }
        
        if (filterParams.inStock === 'true') {
            query.stock = { $gt: 0 };
        }
        
        if (filterParams.minPrice && filterParams.maxPrice) {
            const minPrice = parseFloat(filterParams.minPrice);
            const maxPrice = parseFloat(filterParams.maxPrice);
            
            if (!isNaN(minPrice) && !isNaN(maxPrice)) {
                query.price = { $gte: minPrice, $lte: maxPrice };
            }
        }
        
        return query;
    }
    
    const safeQuery = buildSafeQuery(filters);
    
    db.collection('products').find(safeQuery).toArray((err, products) => {
        if (err) {
            return res.status(500).send('Error fetching products');
        }
        res.json(products);
    });
}
// {/fact}

// Start the server
app.listen(3000, () => {
    console.log('Server running on port 3000');
});