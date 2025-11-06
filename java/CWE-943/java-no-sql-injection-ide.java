import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.BasicDBObject;
import com.mongodb.client.model.Filters;
import org.bson.Document;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class NoSqlInjectionExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=nosql-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        // ruleid: java-no-sql-injection-ide
        BasicDBObject query = new BasicDBObject();
        query.put("username", username);
        Document result = collection.find(query).first();
        
        mongoClient.close();
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("id");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        // Using string concatenation in JSON
        String jsonQuery = "{\"_id\": \"" + userId + "\"}";
        // ruleid: java-no-sql-injection-ide
        Document result = collection.find(Document.parse(jsonQuery)).first();
        
        mongoClient.close();
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        String role = request.getParameter("role");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        // ruleid: java-no-sql-injection-ide
        collection.updateMany(
            new BasicDBObject("active", true),
            new BasicDBObject("$set", new BasicDBObject("role", role))
        );
        
        mongoClient.close();
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
        String email = request.getParameter("email");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Users");
        
        Map<String, AttributeValue> key = new HashMap<>();
        // ruleid: java-no-sql-injection-ide
        key.put("email", new AttributeValue(email));
        client.getItem("Users", key);
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
        String searchTerm = request.getParameter("search");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // ruleid: java-no-sql-injection-ide
        Document regexQuery = new Document();
        regexQuery.append("name", new Document("$regex", searchTerm));
        collection.find(regexQuery);
        
        mongoClient.close();
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        String userInput = request.getParameter("filter");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("orders");
        
        // ruleid: java-no-sql-injection-ide
        Document query = Document.parse(userInput);
        collection.find(query);
        
        mongoClient.close();
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        // ruleid: java-no-sql-injection-ide
        Document query = new Document("username", username)
                          .append("password", password);
        Document user = collection.find(query).first();
        
        mongoClient.close();
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) {
        String sortField = request.getParameter("sortBy");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // ruleid: java-no-sql-injection-ide
        Document sortQuery = new Document(sortField, 1);
        collection.find().sort(sortQuery);
        
        mongoClient.close();
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("userId");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Users");
        
        // ruleid: java-no-sql-injection-ide
        GetItemSpec spec = new GetItemSpec()
            .withPrimaryKey("id", userId);
        Item item = table.getItem(spec);
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) {
        String field = request.getParameter("field");
        String value = request.getParameter("value");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("data");
        
        // ruleid: java-no-sql-injection-ide
        BasicDBObject query = new BasicDBObject();
        query.put(field, value);  // Both field and value are user-controlled
        collection.find(query);
        
        mongoClient.close();
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) {
        String operator = request.getParameter("operator");
        String value = request.getParameter("value");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("metrics");
        
        // ruleid: java-no-sql-injection-ide
        Document query = new Document("score", new Document(operator, Integer.parseInt(value)));
        collection.find(query);
        
        mongoClient.close();
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, String> expressionAttributeNames = new HashMap<>();
        expressionAttributeNames.put("#username", "username");
        
        Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
        // ruleid: java-no-sql-injection-ide
        expressionAttributeValues.put(":username", new AttributeValue().withS(username));
        
        client.scan(
            "Users",
            "contains(#username, :username)",
            expressionAttributeNames,
            expressionAttributeValues
        );
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) {
        String category = request.getParameter("category");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // ruleid: java-no-sql-injection-ide
        collection.aggregate(java.util.Arrays.asList(
            new Document("$match", new Document("category", category)),
            new Document("$group", new Document("_id", "$category").append("count", new Document("$sum", 1)))
        ));
        
        mongoClient.close();
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
        String fieldName = request.getParameter("field");
        String fieldValue = request.getParameter("value");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        Document document = new Document();
        // ruleid: java-no-sql-injection-ide
        document.append(fieldName, fieldValue);
        collection.insertOne(document);
        
        mongoClient.close();
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("userId");
        String operation = request.getParameter("operation");
        String amount = request.getParameter("amount");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("accounts");
        
        // ruleid: java-no-sql-injection-ide
        Document updateOperation = new Document(operation, Integer.parseInt(amount));
        collection.updateOne(
            new Document("userId", userId),
            new Document("$inc", updateOperation)
        );
        
        mongoClient.close();
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        // Validate input
        if (!username.matches("[a-zA-Z0-9_]+")) {
            throw new IllegalArgumentException("Invalid username format");
        }
        
        // ok: java-no-sql-injection-ide
        BasicDBObject query = new BasicDBObject();
        query.put("username", username);
        Document result = collection.find(query).first();
        
        mongoClient.close();
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("id");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        // Using parameterized query with proper type conversion
        try {
            // ok: java-no-sql-injection-ide
            Document result = collection.find(Filters.eq("_id", userId)).first();
        } catch (IllegalArgumentException e) {
            // Handle invalid input
        }
        
        mongoClient.close();
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        String role = request.getParameter("role");
        
        // Validate against a whitelist of allowed roles
        String[] allowedRoles = {"user", "admin", "moderator"};
        boolean isValidRole = false;
        for (String allowedRole : allowedRoles) {
            if (allowedRole.equals(role)) {
                isValidRole = true;
                break;
            }
        }
        
        if (!isValidRole) {
            throw new IllegalArgumentException("Invalid role");
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        // ok: java-no-sql-injection-ide
        collection.updateMany(
            new BasicDBObject("active", true),
            new BasicDBObject("$set", new BasicDBObject("role", role))
        );
        
        mongoClient.close();
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
        String email = request.getParameter("email");
        
        // Validate email format
        if (!email.matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            throw new IllegalArgumentException("Invalid email format");
        }
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Users");
        
        Map<String, AttributeValue> key = new HashMap<>();
        // ok: java-no-sql-injection-ide
        key.put("email", new AttributeValue(email));
        client.getItem("Users", key);
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
        String searchTerm = request.getParameter("search");
        
        // Escape regex special characters
        searchTerm = searchTerm.replaceAll("[\\\\^$*+?.()|{}\\[\\]]", "\\\\$0");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // ok: java-no-sql-injection-ide
        Document regexQuery = new Document();
        regexQuery.append("name", new Document("$regex", searchTerm));
        collection.find(regexQuery);
        
        mongoClient.close();
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) {
        String category = request.getParameter("category");
        String minPrice = request.getParameter("minPrice");
        
        // Use a predefined query structure and validate inputs
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // Validate category against whitelist
        String[] validCategories = {"electronics", "books", "clothing"};
        boolean isValidCategory = false;
        for (String validCategory : validCategories) {
            if (validCategory.equals(category)) {
                isValidCategory = true;
                break;
            }
        }
        
        if (!isValidCategory) {
            throw new IllegalArgumentException("Invalid category");
        }
        
        double price;
        try {
            price = Double.parseDouble(minPrice);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid price");
        }
        
        // ok: java-no-sql-injection-ide
        Document query = new Document("category", category)
                         .append("price", new Document("$gte", price));
        collection.find(query);
        
        mongoClient.close();
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Validate inputs
        if (!username.matches("[a-zA-Z0-9_]+") || password.length() < 8) {
            throw new IllegalArgumentException("Invalid input");
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        // Hash password before querying
        String hashedPassword = hashPassword(password);
        
        // ok: java-no-sql-injection-ide
        Document query = new Document("username", username)
                          .append("password", hashedPassword);
        Document user = collection.find(query).first();
        
        mongoClient.close();
    }
    
    private String hashPassword(String password) {
        // Implementation of password hashing
        return java.security.MessageDigest.getInstance("SHA-256")
                .digest(password.getBytes())
                .toString();
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) {
        String sortField = request.getParameter("sortBy");
        
        // Validate sort field against whitelist
        String[] allowedSortFields = {"name", "price", "date"};
        boolean isValidSortField = false;
        for (String allowedField : allowedSortFields) {
            if (allowedField.equals(sortField)) {
                isValidSortField = true;
                break;
            }
        }
        
        if (!isValidSortField) {
            sortField = "name"; // Default to a safe value
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // ok: java-no-sql-injection-ide
        Document sortQuery = new Document(sortField, 1);
        collection.find().sort(sortQuery);
        
        mongoClient.close();
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("userId");
        
        // Validate userId format
        if (!userId.matches("[a-zA-Z0-9-]+")) {
            throw new IllegalArgumentException("Invalid user ID format");
        }
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Users");
        
        // ok: java-no-sql-injection-ide
        GetItemSpec spec = new GetItemSpec()
            .withPrimaryKey("id", userId);
        Item item = table.getItem(spec);
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) {
        String value = request.getParameter("value");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("data");
        
        // Use a fixed field name and validate the value
        if (!value.matches("[a-zA-Z0-9_]+")) {
            throw new IllegalArgumentException("Invalid value format");
        }
        
        // ok: java-no-sql-injection-ide
        BasicDBObject query = new BasicDBObject();
        query.put("name", value);  // Field name is hardcoded
        collection.find(query);
        
        mongoClient.close();
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) {
        String operator = request.getParameter("operator");
        String value = request.getParameter("value");
        
        // Validate operator against whitelist
        String[] allowedOperators = {"$gt", "$lt", "$eq", "$gte", "$lte"};
        boolean isValidOperator = false;
        for (String allowedOp : allowedOperators) {
            if (allowedOp.equals(operator)) {
                isValidOperator = true;
                break;
            }
        }
        
        if (!isValidOperator) {
            throw new IllegalArgumentException("Invalid operator");
        }
        
        // Validate value is a number
        int numericValue;
        try {
            numericValue = Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid numeric value");
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("metrics");
        
        // ok: java-no-sql-injection-ide
        Document query = new Document("score", new Document(operator, numericValue));
        collection.find(query);
        
        mongoClient.close();
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        
        // Sanitize the input
        username = username.replaceAll("[^a-zA-Z0-9]", "");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, String> expressionAttributeNames = new HashMap<>();
        expressionAttributeNames.put("#username", "username");
        
        Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
        // ok: java-no-sql-injection-ide
        expressionAttributeValues.put(":username", new AttributeValue().withS(username));
        
        client.scan(
            "Users",
            "contains(#username, :username)",
            expressionAttributeNames,
            expressionAttributeValues
        );
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) {
        String category = request.getParameter("category");
        
        // Validate category against whitelist
        String[] validCategories = {"electronics", "books", "clothing", "food"};
        boolean isValidCategory = false;
        for (String validCategory : validCategories) {
            if (validCategory.equals(category)) {
                isValidCategory = true;
                break;
            }
        }
        
        if (!isValidCategory) {
            category = "electronics"; // Default to a safe value
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // ok: java-no-sql-injection-ide
        collection.aggregate(java.util.Arrays.asList(
            new Document("$match", new Document("category", category)),
            new Document("$group", new Document("_id", "$category").append("count", new Document("$sum", 1)))
        ));
        
        mongoClient.close();
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
        String fieldValue = request.getParameter("value");
        
        // Sanitize input
        fieldValue = fieldValue.replaceAll("[<>\"'%;()]", "");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        Document document = new Document();
        // Use a predefined field name instead of user input
        // ok: java-no-sql-injection-ide
        document.append("userInput", fieldValue);
        collection.insertOne(document);
        
        mongoClient.close();
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("userId");
        String amountStr = request.getParameter("amount");
        
        // Validate userId
        if (!userId.matches("[a-zA-Z0-9-]+")) {
            throw new IllegalArgumentException("Invalid user ID format");
        }
        
        // Validate and parse amount
        int amount;
        try {
            amount = Integer.parseInt(amountStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid amount");
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("accounts");
        
        // Use a fixed operation name instead of user input
        // ok: java-no-sql-injection-ide
        collection.updateOne(
            new Document("userId", userId),
            new Document("$inc", new Document("balance", amount))
        );
        
        mongoClient.close();
    }
}
// {/fact}