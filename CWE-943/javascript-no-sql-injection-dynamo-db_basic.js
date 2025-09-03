// Filename: dynamodb_nosql_injection_examples.js

const AWS = require('aws-sdk');
const express = require('express');
const app = express();
app.use(express.json());

// Configure AWS
AWS.config.update({
  region: 'us-west-2',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

const dynamodb = new AWS.DynamoDB.DocumentClient();

// True Positive Examples (Vulnerable Code)

// Example 1: Basic query with user input directly in filter expression
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_1(req, res) {
  const username = req.query.username;
  
  const params = {
    TableName: 'Users',
    FilterExpression: 'username = :username',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':username': username
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 2: Query with user input in key condition expression
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_2(req, res) {
  const userId = req.params.id;
  
  const params = {
    TableName: 'Orders',
    KeyConditionExpression: 'userId = :userId',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':userId': userId
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 3: Scan with multiple user inputs
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_3(req, res) {
  const minAge = req.query.minAge;
  const status = req.query.status;
  
  const params = {
    TableName: 'Customers',
    FilterExpression: 'age > :minAge AND status = :status',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':minAge': minAge,
      ':status': status
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 4: Query with user input in a more complex expression
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_4(req, res) {
  const productCategory = req.query.category;
  const minRating = req.query.rating;
  
  const params = {
    TableName: 'Products',
    IndexName: 'CategoryIndex',
    KeyConditionExpression: 'category = :category',
    FilterExpression: 'rating >= :rating',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':category': productCategory,
      ':rating': minRating
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 5: Scan with user input in attribute names
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_5(req, res) {
  const field = req.query.field;
  const value = req.query.value;
  
  const params = {
    TableName: 'Inventory',
    FilterExpression: '#field = :value',
    ExpressionAttributeNames: {
      '#field': field
    },
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':value': value
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 6: Query with user input in begins_with function
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_6(req, res) {
  const namePrefix = req.query.prefix;
  
  const params = {
    TableName: 'Employees',
    FilterExpression: 'begins_with(fullName, :prefix)',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':prefix': namePrefix
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 7: Query with user input from request body
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_7(req, res) {
  const searchCriteria = req.body.search;
  
  const params = {
    TableName: 'Articles',
    FilterExpression: 'contains(title, :searchTerm)',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':searchTerm': searchCriteria
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 8: Query with user input from headers
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_8(req, res) {
  const tenantId = req.headers['x-tenant-id'];
  
  const params = {
    TableName: 'MultiTenantData',
    KeyConditionExpression: 'tenantId = :tenantId',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':tenantId': tenantId
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 9: Query with user input in between operator
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_9(req, res) {
  const startDate = req.query.start;
  const endDate = req.query.end;
  
  const params = {
    TableName: 'Events',
    FilterExpression: 'eventDate BETWEEN :startDate AND :endDate',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':startDate': startDate,
      ':endDate': endDate
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 10: Query with user input in IN operator
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_10(req, res) {
  const statusList = req.query.statuses.split(',');
  
  const params = {
    TableName: 'Tasks',
    FilterExpression: 'taskStatus IN (:status0, :status1, :status2)',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':status0': statusList[0],
      ':status1': statusList[1],
      ':status2': statusList[2]
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 11: Query with user input in async/await pattern
// {fact rule=nosql-injection@v1.0 defects=1}
async function bad_case_11(req, res) {
  try {
    const department = req.query.dept;
    
    const params = {
      TableName: 'Employees',
      IndexName: 'DepartmentIndex',
      KeyConditionExpression: 'department = :dept',
      ExpressionAttributeValues: {
        // ruleid: javascript-no-sql-injection-dynamo-db
        ':dept': department
      }
    };
    
    const result = await dynamodb.query(params).promise();
    res.json(result.Items);
  } catch (err) {
    res.status(500).send(err);
  }
}
// {/fact}

// Example 12: Scan with user input in promise pattern
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_12(req, res) {
  const category = req.query.category;
  const minPrice = req.query.minPrice;
  const maxPrice = req.query.maxPrice;
  
  const params = {
    TableName: 'Products',
    FilterExpression: 'category = :category AND price BETWEEN :min AND :max',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':category': category,
      ':min': minPrice,
      ':max': maxPrice
    }
  };
  
  dynamodb.scan(params).promise()
    .then(data => {
      res.json(data.Items);
    })
    .catch(err => {
      res.status(500).send(err);
    });
}
// {/fact}

// Example 13: Query with user input in cookie
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_13(req, res) {
  const userRegion = req.cookies.region;
  
  const params = {
    TableName: 'RegionalSettings',
    KeyConditionExpression: 'region = :region',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':region': userRegion
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 14: Scan with user input in a more complex scenario
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_14(req, res) {
  const searchTerm = req.query.search;
  const userType = req.headers['x-user-type'];
  
  let filterExpression = 'contains(description, :searchTerm)';
  let expressionValues = {
    // ruleid: javascript-no-sql-injection-dynamo-db
    ':searchTerm': searchTerm
  };
  
  if (userType) {
    filterExpression += ' AND userType = :userType';
    expressionValues[':userType'] = userType;
  }
  
  const params = {
    TableName: 'Content',
    FilterExpression: filterExpression,
    ExpressionAttributeValues: expressionValues
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 15: Query with user input in a nested object
// {fact rule=nosql-injection@v1.0 defects=1}
function bad_case_15(req, res) {
  const filters = {
    productId: req.query.productId,
    minQuantity: req.query.minQuantity
  };
  
  const params = {
    TableName: 'Inventory',
    KeyConditionExpression: 'productId = :productId',
    FilterExpression: 'quantity >= :minQuantity',
    ExpressionAttributeValues: {
      // ruleid: javascript-no-sql-injection-dynamo-db
      ':productId': filters.productId,
      ':minQuantity': filters.minQuantity
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Query with validated numeric input
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_1(req, res) {
  let userId = req.params.id;
  
  // Validate that userId is a number
  userId = parseInt(userId, 10);
  if (isNaN(userId)) {
    return res.status(400).send('Invalid user ID');
  }
  
  const params = {
    TableName: 'Users',
    KeyConditionExpression: 'userId = :userId',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':userId': userId
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 2: Scan with whitelisted input
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_2(req, res) {
  let status = req.query.status;
  
  // Whitelist validation
  const validStatuses = ['active', 'pending', 'closed'];
  if (!validStatuses.includes(status)) {
    status = 'active'; // Default to a safe value
  }
  
  const params = {
    TableName: 'Orders',
    FilterExpression: 'orderStatus = :status',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':status': status
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 3: Query with regex-validated input
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_3(req, res) {
  let productId = req.params.id;
  
  // Validate product ID format (alphanumeric)
  if (!/^[a-zA-Z0-9-]+$/.test(productId)) {
    return res.status(400).send('Invalid product ID format');
  }
  
  const params = {
    TableName: 'Products',
    KeyConditionExpression: 'productId = :productId',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':productId': productId
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 4: Scan with hardcoded values (no user input)
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_4(req, res) {
  const params = {
    TableName: 'Products',
    FilterExpression: 'category = :category AND inStock = :inStock',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':category': 'electronics',
      ':inStock': true
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 5: Query with input validation and transformation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_5(req, res) {
  let searchDate = req.query.date;
  
  // Validate date format
  if (!/^\d{4}-\d{2}-\d{2}$/.test(searchDate)) {
    return res.status(400).send('Invalid date format. Use YYYY-MM-DD');
  }
  
  // Transform to Date object for additional validation
  const dateObj = new Date(searchDate);
  if (isNaN(dateObj.getTime())) {
    return res.status(400).send('Invalid date');
  }
  
  const params = {
    TableName: 'Events',
    IndexName: 'DateIndex',
    KeyConditionExpression: 'eventDate = :date',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':date': searchDate
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 6: Scan with input sanitization
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_6(req, res) {
  let username = req.query.username;
  
  // Sanitize username: remove special characters
  username = username.replace(/[^\w\s]/gi, '');
  
  const params = {
    TableName: 'Users',
    FilterExpression: 'contains(username, :username)',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':username': username
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 7: Query with type conversion and validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_7(req, res) {
  let minPrice = req.query.minPrice;
  let maxPrice = req.query.maxPrice;
  
  // Convert to numbers and validate
  minPrice = parseFloat(minPrice);
  maxPrice = parseFloat(maxPrice);
  
  if (isNaN(minPrice) || isNaN(maxPrice) || minPrice < 0 || maxPrice < minPrice) {
    return res.status(400).send('Invalid price range');
  }
  
  const params = {
    TableName: 'Products',
    FilterExpression: 'price BETWEEN :min AND :max',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':min': minPrice,
      ':max': maxPrice
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 8: Scan with environment variables (no user input)
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_8(req, res) {
  const params = {
    TableName: 'Configuration',
    FilterExpression: 'environment = :env',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':env': process.env.NODE_ENV
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 9: Query with validated enum input
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_9(req, res) {
  let category = req.query.category;
  
  // Validate against enum
  const validCategories = ['books', 'electronics', 'clothing', 'food'];
  if (!validCategories.includes(category)) {
    return res.status(400).send('Invalid category');
  }
  
  const params = {
    TableName: 'Products',
    IndexName: 'CategoryIndex',
    KeyConditionExpression: 'category = :category',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':category': category
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 10: Scan with length validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_10(req, res) {
  let searchTerm = req.query.search;
  
  // Validate length
  if (!searchTerm || searchTerm.length < 3 || searchTerm.length > 50) {
    return res.status(400).send('Search term must be between 3 and 50 characters');
  }
  
  // Sanitize
  searchTerm = searchTerm.trim();
  
  const params = {
    TableName: 'Articles',
    FilterExpression: 'contains(title, :searchTerm)',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':searchTerm': searchTerm
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 11: Query with UUID validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_11(req, res) {
  let userId = req.params.id;
  
  // Validate UUID format
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(userId)) {
    return res.status(400).send('Invalid user ID format');
  }
  
  const params = {
    TableName: 'Users',
    KeyConditionExpression: 'userId = :userId',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':userId': userId
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 12: Scan with boolean conversion
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_12(req, res) {
  let isActive = req.query.active;
  
  // Convert string to boolean
  if (isActive === 'true') {
    isActive = true;
  } else if (isActive === 'false') {
    isActive = false;
  } else {
    return res.status(400).send('Invalid active parameter. Use "true" or "false"');
  }
  
  const params = {
    TableName: 'Accounts',
    FilterExpression: 'isActive = :active',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':active': isActive
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 13: Query with date range validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_13(req, res) {
  let startDate = req.query.start;
  let endDate = req.query.end;
  
  // Validate date format
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(startDate) || !dateRegex.test(endDate)) {
    return res.status(400).send('Invalid date format. Use YYYY-MM-DD');
  }
  
  // Convert to Date objects for validation
  const startDateObj = new Date(startDate);
  const endDateObj = new Date(endDate);
  
  if (isNaN(startDateObj.getTime()) || isNaN(endDateObj.getTime())) {
    return res.status(400).send('Invalid date');
  }
  
  if (startDateObj > endDateObj) {
    return res.status(400).send('Start date must be before end date');
  }
  
  const params = {
    TableName: 'Events',
    FilterExpression: 'eventDate BETWEEN :startDate AND :endDate',
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':startDate': startDate,
      ':endDate': endDate
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 14: Scan with array validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_14(req, res) {
  let categories = req.query.categories ? req.query.categories.split(',') : [];
  
  // Validate array content
  const validCategories = ['books', 'electronics', 'clothing', 'food'];
  
  // Filter out invalid categories
  categories = categories.filter(cat => validCategories.includes(cat));
  
  if (categories.length === 0) {
    return res.status(400).send('No valid categories provided');
  }
  
  // Create expression attribute values dynamically
  const expressionValues = {};
  const expressions = [];
  
  categories.forEach((cat, index) => {
    const placeholder = `:cat${index}`;
    expressionValues[placeholder] = cat;
    expressions.push(`category = ${placeholder}`);
  });
  
  const params = {
    TableName: 'Products',
    FilterExpression: expressions.join(' OR '),
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ...expressionValues
    }
  };
  
  dynamodb.scan(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Example 15: Query with comprehensive validation
// {fact rule=nosql-injection@v1.0 defects=0}
function good_case_15(req, res) {
  let userId = req.params.id;
  let status = req.query.status;
  let minDate = req.query.since;
  
  // Validate userId (numeric)
  userId = parseInt(userId, 10);
  if (isNaN(userId) || userId <= 0) {
    return res.status(400).send('Invalid user ID');
  }
  
  // Validate status (enum)
  const validStatuses = ['pending', 'completed', 'cancelled'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).send('Invalid status');
  }
  
  // Validate date
  if (minDate) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(minDate)) {
      return res.status(400).send('Invalid date format. Use YYYY-MM-DD');
    }
    
    const dateObj = new Date(minDate);
    if (isNaN(dateObj.getTime())) {
      return res.status(400).send('Invalid date');
    }
  } else {
    // Default to 30 days ago if not provided
    const defaultDate = new Date();
    defaultDate.setDate(defaultDate.getDate() - 30);
    minDate = defaultDate.toISOString().split('T')[0];
  }
  
  // Build query parameters
  let filterExpression = 'createdAt >= :minDate';
  let expressionValues = {
    ':minDate': minDate
  };
  
  if (status) {
    filterExpression += ' AND orderStatus = :status';
    expressionValues[':status'] = status;
  }
  
  const params = {
    TableName: 'Orders',
    KeyConditionExpression: 'userId = :userId',
    FilterExpression: filterExpression,
    ExpressionAttributeValues: {
      // ok: javascript-no-sql-injection-dynamo-db
      ':userId': userId,
      ...expressionValues
    }
  };
  
  dynamodb.query(params, (err, data) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(data.Items);
    }
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;