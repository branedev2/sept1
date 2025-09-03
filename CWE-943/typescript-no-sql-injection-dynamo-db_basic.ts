import * as AWS from 'aws-sdk';
import * as express from 'express';
import { Request, Response } from 'express';

const app = express();
app.use(express.json());

const dynamoDB = new AWS.DynamoDB.DocumentClient();

// True Positive Examples (Vulnerable Code)

// Bad Case 1: Direct use of query parameter in DynamoDB query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userId = req.query.userId as string;
    
    const params = {
        TableName: 'Users',
        KeyConditionExpression: 'userId = :userId',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':userId': userId
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 2: Using request body in DynamoDB scan
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const searchTerm = req.body.searchTerm;
    
    const params = {
        TableName: 'Products',
        FilterExpression: 'contains(productName, :term)',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':term': searchTerm
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 3: Using URL parameter in complex query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const category = req.params.category;
    const minPrice = req.query.minPrice as string;
    
    const params = {
        TableName: 'Products',
        KeyConditionExpression: 'category = :cat',
        FilterExpression: 'price >= :price',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':cat': category,
            ':price': minPrice
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 4: Using header value in scan operation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userRole = req.headers['user-role'] as string;
    
    const params = {
        TableName: 'Permissions',
        FilterExpression: 'role = :role',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':role': userRole
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 5: Using cookie value in query
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const sessionId = req.cookies.sessionId;
    
    const params = {
        TableName: 'Sessions',
        KeyConditionExpression: 'sessionId = :sid',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':sid': sessionId
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 6: Using multiple request inputs in complex scan
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const minAge = req.query.minAge as string;
    const maxAge = req.query.maxAge as string;
    const status = req.query.status as string;
    
    const params = {
        TableName: 'Users',
        FilterExpression: 'age BETWEEN :min AND :max AND status = :status',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':min': minAge,
            ':max': maxAge,
            ':status': status
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 7: Using request input in query with promise
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const email = req.body.email;
    
    const params = {
        TableName: 'Users',
        IndexName: 'EmailIndex',
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':email': email
        }
    };
    
    dynamoDB.query(params).promise()
        .then(data => {
            res.json(data.Items);
        })
        .catch(err => {
            res.status(500).send(err);
        });
}
// {/fact}

// Bad Case 8: Using request input in scan with async/await
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_8(req: Request, res: Response) {
    const department = req.query.dept as string;
    
    const params = {
        TableName: 'Employees',
        FilterExpression: 'department = :dept',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':dept': department
        }
    };
    
    try {
        const data = await dynamoDB.scan(params).promise();
        res.json(data.Items);
    } catch (err) {
        res.status(500).send(err);
    }
}
// {/fact}

// Bad Case 9: Using concatenated request inputs
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const firstName = req.query.firstName as string;
    const lastName = req.query.lastName as string;
    const fullName = firstName + ' ' + lastName;
    
    const params = {
        TableName: 'Customers',
        FilterExpression: 'fullName = :name',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':name': fullName
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 10: Using request input with conditional logic
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const status = req.query.status as string;
    let searchStatus = 'active';
    
    if (status && ['active', 'inactive', 'pending'].includes(status)) {
        searchStatus = status;
    }
    
    const params = {
        TableName: 'Orders',
        FilterExpression: 'orderStatus = :status',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':status': searchStatus
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 11: Using request input with template literals
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const productId = req.params.id;
    const category = req.query.category as string;
    
    const params = {
        TableName: 'ProductReviews',
        KeyConditionExpression: 'productId = :pid',
        FilterExpression: 'category = :cat',
        ExpressionAttributeValues: {
            ':pid': productId,
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':cat': `${category}-reviews`
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 12: Using request input with object destructuring
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const { region, productType } = req.query;
    
    const params = {
        TableName: 'Inventory',
        FilterExpression: 'region = :reg AND productType = :type',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':reg': region,
            ':type': productType
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 13: Using request input with array mapping
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const tagList = req.body.tags as string[];
    
    const params = {
        TableName: 'Articles',
        FilterExpression: 'contains(tags, :tag)',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':tag': tagList[0]
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 14: Using request input with ternary operator
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const sortBy = req.query.sortBy as string;
    const sortField = sortBy ? sortBy : 'createdAt';
    
    const params = {
        TableName: 'Posts',
        IndexName: `${sortField}-index`,
        KeyConditionExpression: 'status = :status',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':status': 'published'
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Bad Case 15: Using request input with string manipulation
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const searchTerm = req.query.search as string;
    const processedTerm = searchTerm ? searchTerm.toLowerCase().trim() : '';
    
    const params = {
        TableName: 'Products',
        FilterExpression: 'contains(searchableTerms, :term)',
        ExpressionAttributeValues: {
            // ruleid: typescript-no-sql-injection-dynamo-db
            ':term': processedTerm
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Good Case 1: Using validated input with type checking
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    let userId = req.query.userId as string;
    
    // Validate input
    if (typeof userId !== 'string' || !/^[a-zA-Z0-9-]+$/.test(userId)) {
        return res.status(400).send('Invalid user ID format');
    }
    
    const params = {
        TableName: 'Users',
        KeyConditionExpression: 'userId = :userId',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':userId': userId
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 2: Using hardcoded values instead of user input
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const params = {
        TableName: 'Products',
        FilterExpression: 'category = :cat',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':cat': 'electronics'
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 3: Using input validation with whitelist
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const status = req.query.status as string;
    const validStatuses = ['active', 'inactive', 'pending'];
    
    if (!status || !validStatuses.includes(status)) {
        return res.status(400).send('Invalid status value');
    }
    
    const params = {
        TableName: 'Orders',
        FilterExpression: 'orderStatus = :status',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':status': status
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 4: Using numeric validation for query parameters
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const minPriceStr = req.query.minPrice as string;
    const minPrice = Number(minPriceStr);
    
    if (isNaN(minPrice) || minPrice < 0) {
        return res.status(400).send('Invalid price value');
    }
    
    const params = {
        TableName: 'Products',
        FilterExpression: 'price >= :price',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':price': minPrice
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 5: Using environment variables instead of user input
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const companyId = process.env.COMPANY_ID;
    
    const params = {
        TableName: 'Employees',
        KeyConditionExpression: 'companyId = :cid',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':cid': companyId
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 6: Using UUID validation for IDs
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const productId = req.params.id;
    
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(productId)) {
        return res.status(400).send('Invalid product ID format');
    }
    
    const params = {
        TableName: 'Products',
        KeyConditionExpression: 'productId = :pid',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':pid': productId
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 7: Using input sanitization for string values
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    let searchTerm = req.query.search as string;
    
    // Sanitize input: remove special characters and limit length
    searchTerm = searchTerm ? searchTerm.replace(/[^\w\s]/gi, '').substring(0, 50) : '';
    
    const params = {
        TableName: 'Products',
        FilterExpression: 'contains(productName, :term)',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':term': searchTerm
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 8: Using numeric range validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const ageStr = req.query.age as string;
    const age = Number(ageStr);
    
    if (isNaN(age) || age < 0 || age > 120) {
        return res.status(400).send('Invalid age value');
    }
    
    const params = {
        TableName: 'Users',
        FilterExpression: 'age >= :age',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':age': age
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 9: Using date validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const dateStr = req.query.date as string;
    
    // Validate date format (YYYY-MM-DD)
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(dateStr)) {
        return res.status(400).send('Invalid date format. Use YYYY-MM-DD');
    }
    
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) {
        return res.status(400).send('Invalid date');
    }
    
    const params = {
        TableName: 'Events',
        FilterExpression: 'eventDate = :date',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':date': dateStr
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 10: Using boolean validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const isActiveStr = req.query.active as string;
    let isActive: boolean;
    
    if (isActiveStr === 'true') {
        isActive = true;
    } else if (isActiveStr === 'false') {
        isActive = false;
    } else {
        return res.status(400).send('Invalid boolean value. Use "true" or "false"');
    }
    
    const params = {
        TableName: 'Products',
        FilterExpression: 'isActive = :active',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':active': isActive
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 11: Using enum validation with switch statement
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const roleStr = req.query.role as string;
    let roleValue: string;
    
    switch (roleStr) {
        case 'admin':
            roleValue = 'ADMIN';
            break;
        case 'user':
            roleValue = 'USER';
            break;
        case 'guest':
            roleValue = 'GUEST';
            break;
        default:
            return res.status(400).send('Invalid role value');
    }
    
    const params = {
        TableName: 'Users',
        FilterExpression: 'userRole = :role',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':role': roleValue
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 12: Using array validation for multiple values
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const categoriesInput = req.body.categories as string[];
    const validCategories = ['books', 'electronics', 'clothing', 'food'];
    
    if (!Array.isArray(categoriesInput) || categoriesInput.length === 0) {
        return res.status(400).send('Categories must be a non-empty array');
    }
    
    const categories = categoriesInput.filter(cat => validCategories.includes(cat));
    
    if (categories.length === 0) {
        return res.status(400).send('No valid categories provided');
    }
    
    const params = {
        TableName: 'Products',
        FilterExpression: 'category IN (:cats)',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':cats': categories
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 13: Using object mapping for safe transformation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const sortDirection = req.query.sort as string;
    
    // Map user input to safe values
    const directionMap: {[key: string]: string} = {
        'asc': 'ASC',
        'desc': 'DESC'
    };
    
    const safeDirection = directionMap[sortDirection] || 'ASC';
    
    const params = {
        TableName: 'Products',
        IndexName: 'PriceIndex',
        ScanIndexForward: safeDirection === 'ASC',
        KeyConditionExpression: 'category = :cat',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':cat': 'electronics'
        }
    };
    
    dynamoDB.query(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 14: Using numeric parsing with fallback
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const limitStr = req.query.limit as string;
    const limit = parseInt(limitStr, 10);
    
    // Use safe default if parsing fails or value is out of range
    const safeLimit = (!isNaN(limit) && limit > 0 && limit <= 100) ? limit : 20;
    
    const params = {
        TableName: 'Products',
        Limit: safeLimit,
        FilterExpression: 'isActive = :active',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':active': true
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

// Good Case 15: Using JSON schema validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const filter = req.body.filter;
    
    // Simple schema validation
    if (!filter || typeof filter !== 'object') {
        return res.status(400).send('Invalid filter object');
    }
    
    if (filter.status && !['pending', 'completed', 'cancelled'].includes(filter.status)) {
        return res.status(400).send('Invalid status value');
    }
    
    if (filter.minPrice && (typeof filter.minPrice !== 'number' || filter.minPrice < 0)) {
        return res.status(400).send('Invalid minimum price');
    }
    
    const params = {
        TableName: 'Orders',
        FilterExpression: 'orderStatus = :status AND price >= :price',
        ExpressionAttributeValues: {
            // ok: typescript-no-sql-injection-dynamo-db
            ':status': filter.status || 'pending',
            ':price': filter.minPrice || 0
        }
    };
    
    dynamoDB.scan(params, (err, data) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(data.Items);
        }
    });
}
// {/fact}

export { app };