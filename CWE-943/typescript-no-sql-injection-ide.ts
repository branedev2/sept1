// typescript-no-sql-injection-examples.ts

import * as express from 'express';
import { Request, Response } from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import * as mongoose from 'mongoose';
import * as sanitize from 'mongo-sanitize';
import * as validator from 'validator';

// MongoDB connection setup
const mongoUri = 'mongodb://localhost:27017';
const dbName = 'testDatabase';

// ==================== TRUE POSITIVES (VULNERABLE CODE) ====================

// Bad Case 1: Direct use of query parameter in MongoDB find operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const username = req.query.username;
    
    MongoClient.connect(mongoUri, (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        // ruleid: typescript-no-sql-injection-ide
        db.collection('users').find({ username: username }).toArray((err, result) => {
            if (err) throw err;
            res.json(result);
            client.close();
        });
    });
}
// {/fact}

// Bad Case 2: Using request body data directly in query with object notation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userFilter = req.body.filter;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const users = await db.collection('users').find(userFilter).toArray();
            res.json(users);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Bad Case 3: Using string template with request parameter in query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const userId = req.params.id;
    
    mongoose.connect(mongoUri + '/' + dbName);
    const User = mongoose.model('User', new mongoose.Schema({
        name: String,
        email: String
    }));
    
    // ruleid: typescript-no-sql-injection-ide
    User.findOne({ _id: userId }, (err: any, user: any) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.json(user);
    });
}
// {/fact}

// Bad Case 4: Using request header in MongoDB query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const apiKey = req.headers['x-api-key'] as string;
    
    MongoClient.connect(mongoUri, (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        // ruleid: typescript-no-sql-injection-ide
        db.collection('api_users').findOne({ apiKey: apiKey }, (err, result) => {
            if (err) throw err;
            res.json(result ? { authorized: true } : { authorized: false });
            client.close();
        });
    });
}
// {/fact}

// Bad Case 5: Using cookie data in MongoDB update operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const sessionId = req.cookies.sessionId;
    const newData = req.body;
    
    MongoClient.connect(mongoUri, (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        // ruleid: typescript-no-sql-injection-ide
        db.collection('sessions').updateOne(
            { sessionId: sessionId },
            { $set: newData },
            (err, result) => {
                if (err) throw err;
                res.json({ updated: result.modifiedCount > 0 });
                client.close();
            }
        );
    });
}
// {/fact}

// Bad Case 6: Using query parameter in MongoDB deleteOne operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const documentId = req.query.id as string;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const result = await db.collection('documents').deleteOne({ _id: documentId });
            res.json({ deleted: result.deletedCount > 0 });
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Bad Case 7: Using request parameter in MongoDB aggregation pipeline
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const category = req.params.category;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const products = await db.collection('products').aggregate([
                { $match: { category: category } },
                { $group: { _id: "$brand", count: { $sum: 1 } } }
            ]).toArray();
            res.json(products);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Bad Case 8: Using request body in complex query with operators
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const minAge = req.body.minAge;
    const maxAge = req.body.maxAge;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const users = await db.collection('users').find({
                age: { $gte: minAge, $lte: maxAge }
            }).toArray();
            res.json(users);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Bad Case 9: Using request query in MongoDB distinct operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const field = req.query.field as string;
    const filter = { active: true };
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const distinctValues = await db.collection('products').distinct(field, filter);
            res.json(distinctValues);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Bad Case 10: Using request parameter in findOneAndUpdate operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const email = req.params.email;
    const updates = req.body;
    
    mongoose.connect(mongoUri + '/' + dbName);
    const User = mongoose.model('User', new mongoose.Schema({
        name: String,
        email: String,
        settings: Object
    }));
    
    // ruleid: typescript-no-sql-injection-ide
    User.findOneAndUpdate(
        { email: email },
        { $set: updates },
        { new: true },
        (err: any, user: any) => {
            if (err) return res.status(500).send(err);
            res.json(user);
        }
    );
}
// {/fact}

// Bad Case 11: Using request query in MongoDB countDocuments operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const status = req.query.status;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const count = await db.collection('orders').countDocuments({ status: status });
            res.json({ count });
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Bad Case 12: Using JSON.parse on request body for query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const queryString = req.body.query;
    let query;
    
    try {
        query = JSON.parse(queryString);
    } catch (e) {
        return res.status(400).json({ error: 'Invalid query format' });
    }
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const results = await db.collection('data').find(query).toArray();
            res.json(results);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Bad Case 13: Using request parameter in MongoDB replaceOne operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const documentId = req.params.id;
    const newDocument = req.body;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const result = await db.collection('documents').replaceOne(
                { _id: documentId },
                newDocument
            );
            res.json({ replaced: result.modifiedCount > 0 });
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Bad Case 14: Using request query in MongoDB findOneAndDelete operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const username = req.query.username as string;
    
    mongoose.connect(mongoUri + '/' + dbName);
    const User = mongoose.model('User', new mongoose.Schema({
        username: String,
        email: String
    }));
    
    // ruleid: typescript-no-sql-injection-ide
    User.findOneAndDelete({ username: username }, (err: any, user: any) => {
        if (err) return res.status(500).send(err);
        res.json({ deleted: !!user });
    });
}
// {/fact}

// Bad Case 15: Using request body in MongoDB bulkWrite operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const operations = req.body.operations;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ruleid: typescript-no-sql-injection-ide
            const result = await db.collection('inventory').bulkWrite(operations);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// ==================== TRUE NEGATIVES (SECURE CODE) ====================

// Good Case 1: Using MongoDB ObjectId for safe query
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const userId = req.params.id;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            let objectId;
            try {
                // ok: typescript-no-sql-injection-ide
                objectId = new ObjectId(userId);
            } catch (e) {
                return res.status(400).json({ error: 'Invalid ID format' });
            }
            
            const user = await db.collection('users').findOne({ _id: objectId });
            res.json(user);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 2: Using mongo-sanitize to clean input
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const userQuery = req.query;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            const cleanQuery = sanitize(userQuery);
            const users = await db.collection('users').find(cleanQuery).toArray();
            res.json(users);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 3: Validating and whitelisting query fields
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const sortField = req.query.sort as string;
    const allowedSortFields = ['name', 'date', 'price'];
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            const validSortField = allowedSortFields.includes(sortField) ? sortField : 'name';
            const sortOptions: any = {};
            sortOptions[validSortField] = 1;
            
            const products = await db.collection('products').find({}).sort(sortOptions).toArray();
            res.json(products);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 4: Using strict type checking and validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const status = req.query.status as string;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            const validStatus = ['active', 'pending', 'completed'].includes(status) ? status : 'active';
            const orders = await db.collection('orders').find({ status: validStatus }).toArray();
            res.json(orders);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 5: Using schema validation with mongoose
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const userData = req.body;
    
    mongoose.connect(mongoUri + '/' + dbName);
    const userSchema = new mongoose.Schema({
        name: { type: String, required: true },
        email: { type: String, required: true },
        age: { type: Number, min: 18, max: 100 }
    });
    
    const User = mongoose.model('User', userSchema);
    
    // ok: typescript-no-sql-injection-ide
    const newUser = new User(userData);
    newUser.validate((err) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        
        newUser.save((saveErr, savedUser) => {
            if (saveErr) return res.status(500).send(saveErr);
            res.json(savedUser);
        });
    });
}
// {/fact}

// Good Case 6: Using explicit query construction with validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const minAge = parseInt(req.query.minAge as string, 10);
    const maxAge = parseInt(req.query.maxAge as string, 10);
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            const query: any = {};
            if (!isNaN(minAge) && minAge > 0) {
                query.age = query.age || {};
                query.age.$gte = minAge;
            }
            if (!isNaN(maxAge) && maxAge > 0) {
                query.age = query.age || {};
                query.age.$lte = maxAge;
            }
            
            const users = await db.collection('users').find(query).toArray();
            res.json(users);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 7: Using parameterized queries with mongoose
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const email = req.params.email;
    
    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }
    
    mongoose.connect(mongoUri + '/' + dbName);
    const User = mongoose.model('User', new mongoose.Schema({
        name: String,
        email: String
    }));
    
    // ok: typescript-no-sql-injection-ide
    User.findOne({ email: email }, (err: any, user: any) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
}
// {/fact}

// Good Case 8: Using projection to limit returned fields
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const username = req.query.username as string;
    
    if (!username || username.length < 3) {
        return res.status(400).json({ error: 'Invalid username' });
    }
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            const user = await db.collection('users').findOne(
                { username: username },
                { projection: { password: 0, secretKey: 0 } }
            );
            res.json(user);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 9: Using regex validation before query
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const productCode = req.query.code as string;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            if (!productCode || !/^[A-Z0-9]{6}$/.test(productCode)) {
                return res.status(400).json({ error: 'Invalid product code format' });
            }
            
            const product = await db.collection('products').findOne({ code: productCode });
            res.json(product);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 10: Using type conversion for numeric fields
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const priceStr = req.query.price as string;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            const price = parseFloat(priceStr);
            if (isNaN(price) || price < 0) {
                return res.status(400).json({ error: 'Invalid price value' });
            }
            
            const products = await db.collection('products').find({ price: { $lte: price } }).toArray();
            res.json(products);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 11: Using predefined query templates
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const queryType = req.query.type as string;
    const value = req.query.value as string;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            let query: any = {};
            
            // ok: typescript-no-sql-injection-ide
            switch (queryType) {
                case 'active':
                    query = { status: 'active' };
                    break;
                case 'category':
                    if (['electronics', 'books', 'clothing'].includes(value)) {
                        query = { category: value };
                    } else {
                        query = { category: 'other' };
                    }
                    break;
                case 'inStock':
                    query = { quantity: { $gt: 0 } };
                    break;
                default:
                    query = { featured: true };
            }
            
            const products = await db.collection('products').find(query).toArray();
            res.json(products);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 12: Using a data access layer with validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const userId = req.params.id;
    
    // Data access layer with validation
    class UserRepository {
        static async findById(id: string) {
            if (!/^[0-9a-fA-F]{24}$/.test(id)) {
                throw new Error('Invalid user ID format');
            }
            
            const client = await MongoClient.connect(mongoUri);
            try {
                const db = client.db(dbName);
                return await db.collection('users').findOne({ _id: new ObjectId(id) });
            } finally {
                client.close();
            }
        }
    }
    
    // ok: typescript-no-sql-injection-ide
    UserRepository.findById(userId)
        .then(user => res.json(user))
        .catch(error => res.status(400).json({ error: error.message }));
}
// {/fact}

// Good Case 13: Using a validation library
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const email = req.body.email;
    const password = req.body.password;
    
    // Validate inputs
    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (!password || password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            const user = await db.collection('users').findOne({ email: email });
            
            if (!user) {
                return res.status(401).json({ error: 'Authentication failed' });
            }
            
            // In a real app, you would verify the password hash here
            res.json({ authenticated: true });
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 14: Using a query builder with validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const filters = req.query;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            const queryBuilder = {
                buildQuery: () => {
                    const query: any = {};
                    
                    if (filters.category && typeof filters.category === 'string') {
                        const validCategories = ['electronics', 'clothing', 'books'];
                        query.category = validCategories.includes(filters.category) 
                            ? filters.category 
                            : 'other';
                    }
                    
                    if (filters.minPrice && typeof filters.minPrice === 'string') {
                        const minPrice = parseFloat(filters.minPrice);
                        if (!isNaN(minPrice) && minPrice >= 0) {
                            query.price = query.price || {};
                            query.price.$gte = minPrice;
                        }
                    }
                    
                    if (filters.maxPrice && typeof filters.maxPrice === 'string') {
                        const maxPrice = parseFloat(filters.maxPrice);
                        if (!isNaN(maxPrice) && maxPrice >= 0) {
                            query.price = query.price || {};
                            query.price.$lte = maxPrice;
                        }
                    }
                    
                    return query;
                }
            };
            
            const query = queryBuilder.buildQuery();
            const products = await db.collection('products').find(query).toArray();
            res.json(products);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}

// Good Case 15: Using strict equality and type checking
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const productId = req.params.id;
    
    MongoClient.connect(mongoUri, async (err, client) => {
        if (err) throw err;
        const db = client.db(dbName);
        
        try {
            // ok: typescript-no-sql-injection-ide
            if (!/^[0-9a-fA-F]{24}$/.test(productId)) {
                return res.status(400).json({ error: 'Invalid product ID format' });
            }
            
            const objectId = new ObjectId(productId);
            const product = await db.collection('products').findOne({ _id: objectId });
            
            if (!product) {
                return res.status(404).json({ error: 'Product not found' });
            }
            
            res.json(product);
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        } finally {
            client.close();
        }
    });
}
// {/fact}