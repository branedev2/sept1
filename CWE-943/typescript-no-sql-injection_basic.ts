// Import necessary libraries for MongoDB and HTTP handling
import { MongoClient, ObjectId } from 'mongodb';
import express from 'express';
import { Request, Response } from 'express';
import * as mongoose from 'mongoose';
import { FilterQuery } from 'mongoose';

// Initialize MongoDB connection
const mongoUri = 'mongodb://localhost:27017';
const client = new MongoClient(mongoUri);
const app = express();
app.use(express.json());

// True Positive Examples (Vulnerable Code)

// Bad case 1: Direct use of request parameter in MongoDB query
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_1(req: Request, res: Response) {
    const username = req.query.username;
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ruleid: typescript-no-sql-injection
        const user = await users.findOne({ username: username });
        
        res.json(user);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 2: Using request body in MongoDB query with object notation
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_2(req: Request, res: Response) {
    const query = req.body.query;
    
    try {
        await client.connect();
        const database = client.db('productdb');
        const products = database.collection('products');
        
        // ruleid: typescript-no-sql-injection
        const result = await products.find(query).toArray();
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 3: Using request parameters to construct a query object
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_3(req: Request, res: Response) {
    const category = req.query.category;
    const minPrice = req.query.minPrice;
    
    try {
        await client.connect();
        const database = client.db('shopdb');
        const products = database.collection('products');
        
        const query = {
            category: category,
            price: { $gte: minPrice }
        };
        
        // ruleid: typescript-no-sql-injection
        const result = await products.find(query).toArray();
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 4: Using string template literals with user input in query
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_4(req: Request, res: Response) {
    const userId = req.params.id;
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ruleid: typescript-no-sql-injection
        const user = await users.findOne({ _id: `${userId}` });
        
        res.json(user);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 5: Using request headers in MongoDB query
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_5(req: Request, res: Response) {
    const apiKey = req.headers['x-api-key'];
    
    try {
        await client.connect();
        const database = client.db('apidb');
        const keys = database.collection('keys');
        
        // ruleid: typescript-no-sql-injection
        const keyData = await keys.findOne({ key: apiKey });
        
        res.json(keyData);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 6: Using request cookies in MongoDB query
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_6(req: Request, res: Response) {
    const sessionId = req.cookies.sessionId;
    
    try {
        await client.connect();
        const database = client.db('sessiondb');
        const sessions = database.collection('sessions');
        
        // ruleid: typescript-no-sql-injection
        const session = await sessions.findOne({ id: sessionId });
        
        res.json(session);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 7: Using request parameter in MongoDB update operation
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_7(req: Request, res: Response) {
    const userId = req.params.id;
    const userData = req.body;
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ruleid: typescript-no-sql-injection
        const result = await users.updateOne(
            { _id: userId },
            { $set: userData }
        );
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 8: Using request parameter in MongoDB delete operation
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_8(req: Request, res: Response) {
    const productId = req.query.id;
    
    try {
        await client.connect();
        const database = client.db('productdb');
        const products = database.collection('products');
        
        // ruleid: typescript-no-sql-injection
        const result = await products.deleteOne({ _id: productId });
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 9: Using Mongoose with user input directly in query
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_9(req: Request, res: Response) {
    const userRole = req.query.role;
    
    try {
        await mongoose.connect(mongoUri);
        const UserModel = mongoose.model('User', new mongoose.Schema({
            name: String,
            role: String,
            active: Boolean
        }));
        
        // ruleid: typescript-no-sql-injection
        const users = await UserModel.find({ role: userRole });
        
        res.json(users);
    } catch (error) {
        res.status(500).send('Error occurred');
    }
}
// {/fact}

// Bad case 10: Using request parameter in complex MongoDB query
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_10(req: Request, res: Response) {
    const searchTerm = req.query.search;
    
    try {
        await client.connect();
        const database = client.db('contentdb');
        const articles = database.collection('articles');
        
        // ruleid: typescript-no-sql-injection
        const results = await articles.find({
            $or: [
                { title: { $regex: searchTerm, $options: 'i' } },
                { content: { $regex: searchTerm, $options: 'i' } }
            ]
        }).toArray();
        
        res.json(results);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 11: Using Mongoose with user input in a filter query
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_11(req: Request, res: Response) {
    const status = req.query.status;
    const category = req.query.category;
    
    try {
        await mongoose.connect(mongoUri);
        const ProductModel = mongoose.model('Product', new mongoose.Schema({
            name: String,
            category: String,
            status: String,
            price: Number
        }));
        
        const filter: FilterQuery<any> = {
            status: status,
            category: category
        };
        
        // ruleid: typescript-no-sql-injection
        const products = await ProductModel.find(filter);
        
        res.json(products);
    } catch (error) {
        res.status(500).send('Error occurred');
    }
}
// {/fact}

// Bad case 12: Using MongoDB aggregation with user input
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_12(req: Request, res: Response) {
    const department = req.query.department;
    
    try {
        await client.connect();
        const database = client.db('employeedb');
        const employees = database.collection('employees');
        
        // ruleid: typescript-no-sql-injection
        const results = await employees.aggregate([
            { $match: { department: department } },
            { $group: { _id: "$position", count: { $sum: 1 } } }
        ]).toArray();
        
        res.json(results);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 13: Using MongoDB with dynamic field names from user input
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_13(req: Request, res: Response) {
    const field = req.query.field as string;
    const value = req.query.value;
    
    try {
        await client.connect();
        const database = client.db('datadb');
        const records = database.collection('records');
        
        const query: any = {};
        query[field] = value;
        
        // ruleid: typescript-no-sql-injection
        const results = await records.find(query).toArray();
        
        res.json(results);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 14: Using MongoDB with user input in projection
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_14(req: Request, res: Response) {
    const userId = req.params.id;
    const fields = req.query.fields as string;
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        const projection: any = {};
        fields.split(',').forEach(field => {
            projection[field.trim()] = 1;
        });
        
        // ruleid: typescript-no-sql-injection
        const user = await users.findOne({ _id: userId }, { projection });
        
        res.json(user);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Bad case 15: Using MongoDB with user input in sort parameter
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_15(req: Request, res: Response) {
    const sortField = req.query.sort as string;
    const sortOrder = req.query.order === 'desc' ? -1 : 1;
    
    try {
        await client.connect();
        const database = client.db('productdb');
        const products = database.collection('products');
        
        const sortOptions: any = {};
        sortOptions[sortField] = sortOrder;
        
        // ruleid: typescript-no-sql-injection
        const results = await products.find({}).sort(sortOptions).toArray();
        
        res.json(results);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// Good case 1: Using MongoDB ObjectId for ID parameters
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_1(req: Request, res: Response) {
    const userId = req.params.id;
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const user = await users.findOne({ _id: new ObjectId(userId) });
        
        res.json(user);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 2: Validating and sanitizing input before using in query
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_2(req: Request, res: Response) {
    const username = req.query.username as string;
    
    // Input validation
    if (!username || typeof username !== 'string' || username.length > 50) {
        return res.status(400).send('Invalid username');
    }
    
    // Sanitize input - only allow alphanumeric characters
    const sanitizedUsername = username.replace(/[^a-zA-Z0-9]/g, '');
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const user = await users.findOne({ username: sanitizedUsername });
        
        res.json(user);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 3: Using predefined query structure with validated parameters
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_3(req: Request, res: Response) {
    const minPrice = Number(req.query.minPrice) || 0;
    const maxPrice = Number(req.query.maxPrice) || 1000;
    const category = req.query.category as string;
    
    // Validate category from a list of allowed values
    const allowedCategories = ['electronics', 'clothing', 'books', 'furniture'];
    const validCategory = allowedCategories.includes(category) ? category : 'electronics';
    
    try {
        await client.connect();
        const database = client.db('shopdb');
        const products = database.collection('products');
        
        // ok: typescript-no-sql-injection
        const result = await products.find({
            category: validCategory,
            price: { $gte: minPrice, $lte: maxPrice }
        }).toArray();
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 4: Using type checking and validation for query parameters
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_4(req: Request, res: Response) {
    const status = req.query.status as string;
    
    // Validate status
    const validStatuses = ['active', 'inactive', 'pending'];
    if (!validStatuses.includes(status)) {
        return res.status(400).send('Invalid status');
    }
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const result = await users.find({ status: status }).toArray();
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 5: Using hardcoded query structure with numeric validation
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_5(req: Request, res: Response) {
    const ageParam = req.query.age;
    let age: number;
    
    // Validate age is a number
    if (typeof ageParam === 'string' && /^\d+$/.test(ageParam)) {
        age = parseInt(ageParam, 10);
        if (age < 0 || age > 120) {
            return res.status(400).send('Invalid age range');
        }
    } else {
        return res.status(400).send('Invalid age parameter');
    }
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const result = await users.find({ age: { $gte: age } }).toArray();
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 6: Using MongoDB with validated enum values
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_6(req: Request, res: Response) {
    const roleParam = req.query.role as string;
    
    // Define valid roles
    enum UserRole {
        ADMIN = 'admin',
        USER = 'user',
        GUEST = 'guest'
    }
    
    // Validate role
    let role: UserRole;
    if (Object.values(UserRole).includes(roleParam as UserRole)) {
        role = roleParam as UserRole;
    } else {
        role = UserRole.GUEST; // Default to guest if invalid
    }
    
    try {
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const result = await users.find({ role: role }).toArray();
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 7: Using MongoDB with whitelisted field names
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_7(req: Request, res: Response) {
    const sortField = req.query.sort as string;
    const sortOrder = req.query.order === 'desc' ? -1 : 1;
    
    // Whitelist of allowed sort fields
    const allowedSortFields = ['name', 'price', 'createdAt', 'rating'];
    const field = allowedSortFields.includes(sortField) ? sortField : 'createdAt';
    
    try {
        await client.connect();
        const database = client.db('productdb');
        const products = database.collection('products');
        
        const sortOptions: any = {};
        sortOptions[field] = sortOrder;
        
        // ok: typescript-no-sql-injection
        const results = await products.find({}).sort(sortOptions).toArray();
        
        res.json(results);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 8: Using MongoDB with validated projection fields
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_8(req: Request, res: Response) {
    const userId = req.params.id;
    const fieldsParam = req.query.fields as string;
    
    try {
        // Validate userId
        if (!ObjectId.isValid(userId)) {
            return res.status(400).send('Invalid user ID');
        }
        
        // Whitelist allowed projection fields
        const allowedFields = ['name', 'email', 'role', 'createdAt'];
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : [];
        
        const projection: any = {};
        requestedFields.forEach(field => {
            if (allowedFields.includes(field)) {
                projection[field] = 1;
            }
        });
        
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const user = await users.findOne(
            { _id: new ObjectId(userId) }, 
            { projection: Object.keys(projection).length ? projection : undefined }
        );
        
        res.json(user);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 9: Using Mongoose with schema validation
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_9(req: Request, res: Response) {
    const status = req.query.status as string;
    
    try {
        // Validate status
        const validStatuses = ['active', 'inactive', 'pending'];
        const validStatus = validStatuses.includes(status) ? status : 'active';
        
        await mongoose.connect(mongoUri);
        const TaskSchema = new mongoose.Schema({
            title: String,
            status: {
                type: String,
                enum: validStatuses,
                default: 'pending'
            },
            dueDate: Date
        });
        
        const TaskModel = mongoose.model('Task', TaskSchema);
        
        // ok: typescript-no-sql-injection
        const tasks = await TaskModel.find({ status: validStatus });
        
        res.json(tasks);
    } catch (error) {
        res.status(500).send('Error occurred');
    }
}
// {/fact}

// Good case 10: Using MongoDB with regex pattern validation
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_10(req: Request, res: Response) {
    const searchTerm = req.query.search as string;
    
    try {
        // Validate search term
        if (!searchTerm || typeof searchTerm !== 'string' || searchTerm.length > 100) {
            return res.status(400).send('Invalid search term');
        }
        
        // Escape regex special characters to prevent ReDoS attacks
        const escapedSearchTerm = searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        
        await client.connect();
        const database = client.db('contentdb');
        const articles = database.collection('articles');
        
        // ok: typescript-no-sql-injection
        const results = await articles.find({
            $or: [
                { title: { $regex: escapedSearchTerm, $options: 'i' } },
                { content: { $regex: escapedSearchTerm, $options: 'i' } }
            ]
        }).toArray();
        
        res.json(results);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 11: Using MongoDB with validated update operations
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_11(req: Request, res: Response) {
    const userId = req.params.id;
    const userData = req.body;
    
    try {
        // Validate userId
        if (!ObjectId.isValid(userId)) {
            return res.status(400).send('Invalid user ID');
        }
        
        // Whitelist allowed update fields
        const allowedFields = ['name', 'email', 'age', 'address'];
        const sanitizedUpdate: any = {};
        
        for (const field of allowedFields) {
            if (userData[field] !== undefined) {
                // Additional validation could be added here for each field
                sanitizedUpdate[field] = userData[field];
            }
        }
        
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const result = await users.updateOne(
            { _id: new ObjectId(userId) },
            { $set: sanitizedUpdate }
        );
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 12: Using MongoDB aggregation with validated parameters
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_12(req: Request, res: Response) {
    const departmentParam = req.query.department as string;
    
    try {
        // Validate department
        const allowedDepartments = ['engineering', 'marketing', 'sales', 'support'];
        const department = allowedDepartments.includes(departmentParam) ? 
            departmentParam : 'engineering';
        
        await client.connect();
        const database = client.db('employeedb');
        const employees = database.collection('employees');
        
        // ok: typescript-no-sql-injection
        const results = await employees.aggregate([
            { $match: { department: department } },
            { $group: { _id: "$position", count: { $sum: 1 } } }
        ]).toArray();
        
        res.json(results);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 13: Using MongoDB with parameter binding (simulated)
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_13(req: Request, res: Response) {
    const email = req.query.email as string;
    
    try {
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email || !emailRegex.test(email)) {
            return res.status(400).send('Invalid email format');
        }
        
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const user = await users.findOne({ email: email });
        
        if (!user) {
            return res.status(404).send('User not found');
        }
        
        res.json(user);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 14: Using MongoDB with strict type checking
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_14(req: Request, res: Response) {
    const minAge = parseInt(req.query.minAge as string, 10);
    const maxAge = parseInt(req.query.maxAge as string, 10);
    
    try {
        // Validate age parameters
        const validMinAge = !isNaN(minAge) && minAge >= 0 ? minAge : 0;
        const validMaxAge = !isNaN(maxAge) && maxAge > validMinAge ? maxAge : 100;
        
        await client.connect();
        const database = client.db('userdb');
        const users = database.collection('users');
        
        // ok: typescript-no-sql-injection
        const result = await users.find({
            age: { $gte: validMinAge, $lte: validMaxAge }
        }).toArray();
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Good case 15: Using MongoDB with hardcoded query and validated parameters
// {fact rule=nosql-injection@v1.0 defects=0}
async function good_case_15(req: Request, res: Response) {
    const category = req.query.category as string;
    const page = parseInt(req.query.page as string, 10) || 1;
    const limit = parseInt(req.query.limit as string, 10) || 10;
    
    try {
        // Validate category
        const allowedCategories = ['electronics', 'clothing', 'books', 'furniture'];
        const validCategory = allowedCategories.includes(category) ? category : null;
        
        // Validate pagination
        const validPage = page > 0 ? page : 1;
        const validLimit = limit > 0 && limit <= 100 ? limit : 10;
        const skip = (validPage - 1) * validLimit;
        
        await client.connect();
        const database = client.db('productdb');
        const products = database.collection('products');
        
        // Build query with validated parameters
        const query: any = {};
        if (validCategory) {
            query.category = validCategory;
        }
        
        // ok: typescript-no-sql-injection
        const result = await products.find(query)
            .skip(skip)
            .limit(validLimit)
            .toArray();
        
        res.json(result);
    } catch (error) {
        res.status(500).send('Error occurred');
    } finally {
        await client.close();
    }
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});