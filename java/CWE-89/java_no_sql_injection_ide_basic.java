import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class NoSqlInjectionExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("users");
        MongoCollection<Document> collection = database.getCollection("accounts");
        
        // ruleid: java-no-sql-injection-ide
        Document query = new Document("username", username);
        Document result = collection.find(query).first();
        
        // Process result
        mongoClient.close();
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("id");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("users");
        MongoCollection<Document> collection = database.getCollection("accounts");
        
        // ruleid: java-no-sql-injection-ide
        Bson filter = Filters.eq("_id", userId);
        Document result = collection.find(filter).first();
        
        // Process result
        mongoClient.close();
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        String searchQuery = request.getParameter("search");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Products");
        
        // ruleid: java-no-sql-injection-ide
        QuerySpec spec = new QuerySpec()
                .withKeyConditionExpression("productName = :name")
                .withValueMap(new ValueMap().withString(":name", searchQuery));
        
        table.query(spec);
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
        String role = request.getParameter("role");
        String status = request.getParameter("status");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("company");
        MongoCollection<Document> collection = database.getCollection("employees");
        
        // ruleid: java-no-sql-injection-ide
        Document query = new Document()
                .append("role", role)
                .append("status", status);
        
        collection.find(query);
        mongoClient.close();
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
        String email = request.getParameter("email");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Users");
        
        // ruleid: java-no-sql-injection-ide
        Item item = table.getItem("email", email);
        
        // Process item
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        String category = request.getParameter("category");
        String minPrice = request.getParameter("minPrice");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("store");
        MongoCollection<Document> collection = database.getCollection("products");
        
        Document priceFilter = new Document("$gt", minPrice);
        
        // ruleid: java-no-sql-injection-ide
        Document query = new Document()
                .append("category", category)
                .append("price", priceFilter);
        
        collection.find(query);
        mongoClient.close();
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) {
        String department = request.getParameter("dept");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Employees");
        
        Map<String, Object> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":dept", department);
        
        // ruleid: java-no-sql-injection-ide
        QuerySpec querySpec = new QuerySpec()
                .withKeyConditionExpression("department = :dept")
                .withExpressionAttributeValues(expressionAttributeValues);
        
        table.query(querySpec);
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) {
        String userInput = request.getParameter("query");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("blog");
        MongoCollection<Document> collection = database.getCollection("posts");
        
        // ruleid: java-no-sql-injection-ide
        Document query = Document.parse(userInput);  // Extremely dangerous - parsing JSON directly from user input
        collection.find(query);
        
        mongoClient.close();
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) {
        String tagName = request.getParameter("tag");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("blog");
        MongoCollection<Document> collection = database.getCollection("posts");
        
        // ruleid: java-no-sql-injection-ide
        Bson filter = Filters.all("tags", tagName);
        collection.find(filter);
        
        mongoClient.close();
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("users");
        MongoCollection<Document> collection = database.getCollection("accounts");
        
        // ruleid: java-no-sql-injection-ide
        Document query = new Document()
                .append("username", username)
                .append("password", password);
        
        Document user = collection.find(query).first();
        // Authentication logic
        
        mongoClient.close();
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) {
        String orderId = request.getParameter("orderId");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Orders");
        
        // ruleid: java-no-sql-injection-ide
        Item item = new Item()
                .withPrimaryKey("id", orderId)
                .withString("status", "processing");
        
        table.putItem(item);
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) {
        String field = request.getParameter("field");
        String value = request.getParameter("value");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("inventory");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // ruleid: java-no-sql-injection-ide
        Document query = new Document(field, value);  // Field name from user input is dangerous
        collection.find(query);
        
        mongoClient.close();
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) {
        String operator = request.getParameter("operator");
        String value = request.getParameter("value");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("analytics");
        MongoCollection<Document> collection = database.getCollection("metrics");
        
        Document operatorDoc = new Document(operator, value);  // Operator from user input
        
        // ruleid: java-no-sql-injection-ide
        Document query = new Document("count", operatorDoc);
        collection.find(query);
        
        mongoClient.close();
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
        String sortField = request.getParameter("sortBy");
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("library");
        MongoCollection<Document> collection = database.getCollection("books");
        
        // ruleid: java-no-sql-injection-ide
        Document sort = new Document(sortField, 1);  // Sort field from user input
        collection.find().sort(sort);
        
        mongoClient.close();
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
        String attribute = request.getParameter("attribute");
        String value = request.getParameter("value");
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("UserPreferences");
        
        Map<String, Object> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":val", value);
        
        // ruleid: java-no-sql-injection-ide
        String updateExpression = "set " + attribute + " = :val";  // Attribute name from user input
        
        table.updateItem(
            "userId", "123456",
            updateExpression,
            expressionAttributeValues
        );
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        
        // Input validation
        if (!username.matches("[a-zA-Z0-9_]{3,20}")) {
            response.setStatus(400);
            return;
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("users");
        MongoCollection<Document> collection = database.getCollection("accounts");
        
        // ok: java-no-sql-injection-ide
        Document query = new Document("username", username);
        Document result = collection.find(query).first();
        
        // Process result
        mongoClient.close();
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("id");
        
        // Validate that ID is numeric
        if (!userId.matches("\\d+")) {
            response.setStatus(400);
            return;
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("users");
        MongoCollection<Document> collection = database.getCollection("accounts");
        
        // ok: java-no-sql-injection-ide
        Bson filter = Filters.eq("_id", Integer.parseInt(userId));
        Document result = collection.find(filter).first();
        
        // Process result
        mongoClient.close();
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        String searchQuery = request.getParameter("search");
        
        // Sanitize input
        searchQuery = Pattern.quote(searchQuery);
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Products");
        
        // ok: java-no-sql-injection-ide
        QuerySpec spec = new QuerySpec()
                .withKeyConditionExpression("productName = :name")
                .withValueMap(new ValueMap().withString(":name", searchQuery));
        
        table.query(spec);
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
        String roleInput = request.getParameter("role");
        String statusInput = request.getParameter("status");
        
        // Validate against allowed values
        String[] allowedRoles = {"admin", "user", "guest"};
        String[] allowedStatuses = {"active", "inactive", "pending"};
        
        boolean validRole = false;
        boolean validStatus = false;
        
        for (String role : allowedRoles) {
            if (role.equals(roleInput)) {
                validRole = true;
                break;
            }
        }
        
        for (String status : allowedStatuses) {
            if (status.equals(statusInput)) {
                validStatus = true;
                break;
            }
        }
        
        if (!validRole || !validStatus) {
            response.setStatus(400);
            return;
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("company");
        MongoCollection<Document> collection = database.getCollection("employees");
        
        // ok: java-no-sql-injection-ide
        Document query = new Document()
                .append("role", roleInput)
                .append("status", statusInput);
        
        collection.find(query);
        mongoClient.close();
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
        String email = request.getParameter("email");
        
        // Validate email format
        if (!email.matches("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")) {
            response.setStatus(400);
            return;
        }
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Users");
        
        // ok: java-no-sql-injection-ide
        Item item = table.getItem("email", email);
        
        // Process item
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) {
        String category = request.getParameter("category");
        String minPriceStr = request.getParameter("minPrice");
        
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
            response.setStatus(400);
            return;
        }
        
        // Validate minPrice is numeric
        if (!minPriceStr.matches("\\d+(\\.\\d+)?")) {
            response.setStatus(400);
            return;
        }
        
        double minPrice = Double.parseDouble(minPriceStr);
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("store");
        MongoCollection<Document> collection = database.getCollection("products");
        
        Document priceFilter = new Document("$gt", minPrice);
        
        // ok: java-no-sql-injection-ide
        Document query = new Document()
                .append("category", category)
                .append("price", priceFilter);
        
        collection.find(query);
        mongoClient.close();
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        String department = request.getParameter("dept");
        
        // Validate department against whitelist
        String[] validDepartments = {"engineering", "marketing", "sales", "hr"};
        boolean isValidDepartment = false;
        for (String validDept : validDepartments) {
            if (validDept.equals(department)) {
                isValidDepartment = true;
                break;
            }
        }
        
        if (!isValidDepartment) {
            response.setStatus(400);
            return;
        }
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Employees");
        
        Map<String, Object> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":dept", department);
        
        // ok: java-no-sql-injection-ide
        QuerySpec querySpec = new QuerySpec()
                .withKeyConditionExpression("department = :dept")
                .withExpressionAttributeValues(expressionAttributeValues);
        
        table.query(querySpec);
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) {
        String userInput = request.getParameter("query");
        
        // Instead of parsing user input directly, use specific fields
        String title = request.getParameter("title");
        String author = request.getParameter("author");
        
        // Validate inputs
        if (title != null && !title.matches("[a-zA-Z0-9\\s]{1,100}")) {
            response.setStatus(400);
            return;
        }
        
        if (author != null && !author.matches("[a-zA-Z\\s]{1,50}")) {
            response.setStatus(400);
            return;
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("blog");
        MongoCollection<Document> collection = database.getCollection("posts");
        
        // ok: java-no-sql-injection-ide
        Document query = new Document();
        if (title != null) {
            query.append("title", title);
        }
        if (author != null) {
            query.append("author", author);
        }
        
        collection.find(query);
        mongoClient.close();
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) {
        String tagName = request.getParameter("tag");
        
        // Validate tag format
        if (!tagName.matches("[a-zA-Z0-9-]{1,20}")) {
            response.setStatus(400);
            return;
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("blog");
        MongoCollection<Document> collection = database.getCollection("posts");
        
        // ok: java-no-sql-injection-ide
        Bson filter = Filters.all("tags", tagName);
        collection.find(filter);
        
        mongoClient.close();
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Validate username format
        if (!username.matches("[a-zA-Z0-9_]{3,20}")) {
            response.setStatus(400);
            return;
        }
        
        // Never store or compare plain text passwords
        // This is just to demonstrate NoSQL injection protection
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("users");
        MongoCollection<Document> collection = database.getCollection("accounts");
        
        // ok: java-no-sql-injection-ide
        Document query = new Document("username", username);
        Document user = collection.find(query).first();
        
        // Proper password verification would be done here with hashing
        // if (user != null && passwordHasher.verify(password, user.getString("passwordHash"))) {
        //     // Authentication successful
        // }
        
        mongoClient.close();
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) {
        String orderId = request.getParameter("orderId");
        
        // Validate order ID format (assuming it should be alphanumeric)
        if (!orderId.matches("[a-zA-Z0-9-]{10,36}")) {
            response.setStatus(400);
            return;
        }
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("Orders");
        
        // ok: java-no-sql-injection-ide
        Item item = new Item()
                .withPrimaryKey("id", orderId)
                .withString("status", "processing");
        
        table.putItem(item);
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) {
        String fieldInput = request.getParameter("field");
        String value = request.getParameter("value");
        
        // Use a whitelist for allowed fields
        Map<String, String> allowedFields = new HashMap<>();
        allowedFields.put("name", "name");
        allowedFields.put("category", "category");
        allowedFields.put("price", "price");
        
        String field = allowedFields.get(fieldInput);
        if (field == null) {
            response.setStatus(400);
            return;
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("inventory");
        MongoCollection<Document> collection = database.getCollection("products");
        
        // ok: java-no-sql-injection-ide
        Document query = new Document(field, value);
        collection.find(query);
        
        mongoClient.close();
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) {
        String operatorInput = request.getParameter("operator");
        String valueStr = request.getParameter("value");
        
        // Validate operator against whitelist
        Map<String, String> allowedOperators = new HashMap<>();
        allowedOperators.put("gt", "$gt");
        allowedOperators.put("lt", "$lt");
        allowedOperators.put("eq", "$eq");
        
        String operator = allowedOperators.get(operatorInput);
        if (operator == null) {
            response.setStatus(400);
            return;
        }
        
        // Validate value is numeric
        if (!valueStr.matches("\\d+(\\.\\d+)?")) {
            response.setStatus(400);
            return;
        }
        
        double value = Double.parseDouble(valueStr);
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("analytics");
        MongoCollection<Document> collection = database.getCollection("metrics");
        
        Document operatorDoc = new Document(operator, value);
        
        // ok: java-no-sql-injection-ide
        Document query = new Document("count", operatorDoc);
        collection.find(query);
        
        mongoClient.close();
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
        String sortByInput = request.getParameter("sortBy");
        
        // Use a whitelist for allowed sort fields
        Map<String, String> allowedSortFields = new HashMap<>();
        allowedSortFields.put("title", "title");
        allowedSortFields.put("author", "author");
        allowedSortFields.put("year", "year");
        allowedSortFields.put("price", "price");
        
        String sortField = allowedSortFields.get(sortByInput);
        if (sortField == null) {
            // Default sort if invalid
            sortField = "title";
        }
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("library");
        MongoCollection<Document> collection = database.getCollection("books");
        
        // ok: java-no-sql-injection-ide
        Document sort = new Document(sortField, 1);
        collection.find().sort(sort);
        
        mongoClient.close();
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) {
        String attributeInput = request.getParameter("attribute");
        String value = request.getParameter("value");
        
        // Use a whitelist for allowed attributes
        Map<String, String> allowedAttributes = new HashMap<>();
        allowedAttributes.put("theme", "theme");
        allowedAttributes.put("language", "language");
        allowedAttributes.put("notifications", "notifications");
        
        String attribute = allowedAttributes.get(attributeInput);
        if (attribute == null) {
            response.setStatus(400);
            return;
        }
        
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        Table table = dynamoDB.getTable("UserPreferences");
        
        Map<String, Object> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":val", value);
        
        Map<String, String> expressionAttributeNames = new HashMap<>();
        expressionAttributeNames.put("#attr", attribute);
        
        // ok: java-no-sql-injection-ide
        String updateExpression = "set #attr = :val";
        
        table.updateItem(
            "userId", "123456",
            updateExpression,
            expressionAttributeNames,
            expressionAttributeValues
        );
    }
}
// {/fact}