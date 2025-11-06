import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import com.mongodb.BasicDBObject;
import com.mongodb.client.model.Filters;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import java.util.HashMap;
import java.util.Map;
import spark.Request;
import spark.Response;
import spark.Spark;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Criteria;
import com.mongodb.reactivestreams.client.MongoClients;
import com.mongodb.reactivestreams.client.MongoClient as ReactiveMongoClient;
import org.litote.kmongo.KMongo;
import org.litote.kmongo.eq;
import org.litote.kmongo.json;
import dev.morphia.Datastore;
import dev.morphia.Morphia;
import dev.morphia.query.filters.Filter;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBQueryExpression;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue as AwsAttributeValue;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query as MongoQuery;

// Security Issue: NoSQL Injection in MongoDB and DynamoDB operations

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    String username = request.getParameter("username");
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("users");
    
    // ruleid: java-no-sql-injection-ide
    Document query = Document.parse("{username: \"" + username + "\"}");
    Document result = collection.find(query).first();
    
    // Vulnerable because user input is directly interpolated into a JSON string
    // which is then parsed into a MongoDB query
}

public void bad_case_2(HttpServletRequest request) {
    String userId = request.getParameter("id");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDB dynamoDB = new DynamoDB(client);
    Table table = dynamoDB.getTable("Users");
    
    // ruleid: java-no-sql-injection-ide
    String expression = "id = " + userId;
    QuerySpec querySpec = new QuerySpec()
        .withKeyConditionExpression(expression);
    
    // Vulnerable because user input is directly interpolated into the key condition expression
}

@RestController
public void bad_case_3(@RequestParam String role) {
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("employees");
    
    // ruleid: java-no-sql-injection-ide
    BasicDBObject query = new BasicDBObject();
    query.put("role", role);
    collection.find(query);
    
    // Vulnerable because user input is directly used in the query object without validation
}

public void bad_case_4(spark.Request request) {
    String age = request.queryParams("age");
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("customers");
    
    // ruleid: java-no-sql-injection-ide
    String queryString = "{$where: \"this.age > " + age + "\"}";
    Document query = Document.parse(queryString);
    collection.find(query);
    
    // Vulnerable because user input is directly interpolated into a $where clause
}

public void bad_case_5(Context context) {
    String department = context.queryParam("dept");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
    expressionAttributeValues.put(":dept", new AttributeValue().withS(department));
    
    // ruleid: java-no-sql-injection-ide
    ScanRequest scanRequest = new ScanRequest()
        .withTableName("Employees")
        .withFilterExpression("department = " + department);
    
    // Vulnerable because user input is directly interpolated into the filter expression
}

public void bad_case_6(RoutingContext routingContext) {
    String status = routingContext.request().getParam("status");
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("orders");
    
    // ruleid: java-no-sql-injection-ide
    Document query = new Document("status", status);
    collection.find(query);
    
    // Vulnerable because user input is directly used in the query document
}

public void bad_case_7(@RequestBody Map<String, String> payload) {
    String category = payload.get("category");
    
    MongoTemplate mongoTemplate = new MongoTemplate(new MongoClient(), "mydb");
    
    // ruleid: java-no-sql-injection-ide
    Query query = new Query(Criteria.where("category").is(category));
    mongoTemplate.find(query, Product.class);
    
    // Vulnerable because user input is directly used in the criteria
}

public void bad_case_8(HttpServletRequest request) {
    String minRating = request.getParameter("minRating");
    
    ReactiveMongoClient mongoClient = MongoClients.create("mongodb://localhost");
    com.mongodb.reactivestreams.client.MongoDatabase database = mongoClient.getDatabase("mydb");
    com.mongodb.reactivestreams.client.MongoCollection<Document> collection = database.getCollection("reviews");
    
    // ruleid: java-no-sql-injection-ide
    String queryString = "{rating: {$gte: " + minRating + "}}";
    Document query = Document.parse(queryString);
    collection.find(query);
    
    // Vulnerable because user input is directly interpolated into a JSON string
}

public void bad_case_9(HttpServletRequest request) {
    String email = request.getParameter("email");
    
    com.mongodb.client.MongoClient mongoClient = KMongo.createClient();
    com.mongodb.client.MongoDatabase database = mongoClient.getDatabase("mydb");
    com.mongodb.client.MongoCollection<Document> collection = database.getCollection("subscribers");
    
    // ruleid: java-no-sql-injection-ide
    String json = "{email: \"" + email + "\"}";
    collection.find(org.litote.kmongo.json.JsonExtensionsKt.json(json));
    
    // Vulnerable because user input is directly interpolated into a JSON string
}

public void bad_case_10(HttpServletRequest request) {
    String zipCode = request.getParameter("zipCode");
    
    Morphia morphia = new Morphia();
    Datastore datastore = morphia.createDatastore(new MongoClient(), "mydb");
    
    // ruleid: java-no-sql-injection-ide
    datastore.find(Address.class).filter(
        dev.morphia.query.filters.Filters.eq("zipCode", zipCode)
    ).iterator();
    
    // Vulnerable because user input is directly used in the filter
}

public void bad_case_11(HttpServletRequest request) {
    String productId = request.getParameter("productId");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    Product product = new Product();
    product.setId(productId);
    
    // ruleid: java-no-sql-injection-ide
    DynamoDBQueryExpression<Product> queryExpression = new DynamoDBQueryExpression<Product>()
        .withHashKeyValues(product);
    mapper.query(Product.class, queryExpression);
    
    // Vulnerable because user input is directly used in the hash key values
}

public void bad_case_12(HttpServletRequest request) {
    String region = request.getParameter("region");
    
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    Map<String, AwsAttributeValue> expressionValues = new HashMap<>();
    
    // ruleid: java-no-sql-injection-ide
    QueryRequest queryRequest = QueryRequest.builder()
        .tableName("Sales")
        .keyConditionExpression("region = " + region)
        .build();
    
    // Vulnerable because user input is directly interpolated into the key condition expression
}

public void bad_case_13(@RequestHeader String apiKey) {
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("apiusers");
    
    // ruleid: java-no-sql-injection-ide
    Document query = new Document("apiKey", apiKey);
    collection.find(query);
    
    // Vulnerable because user input from header is directly used in the query
}

public void bad_case_14(HttpServletRequest request) {
    String sortField = request.getParameter("sort");
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("products");
    
    // ruleid: java-no-sql-injection-ide
    Document sort = Document.parse("{" + sortField + ": 1}");
    collection.find().sort(sort);
    
    // Vulnerable because user input is directly interpolated into a sort specification
}

public void bad_case_15(HttpServletRequest request) {
    String groupField = request.getParameter("groupBy");
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("transactions");
    
    // ruleid: java-no-sql-injection-ide
    Document groupBy = Document.parse("{_id: \"$" + groupField + "\", total: {$sum: \"$amount\"}}");
    collection.aggregate(java.util.Arrays.asList(new Document("$group", groupBy)));
    
    // Vulnerable because user input is directly interpolated into an aggregation pipeline
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    String username = request.getParameter("username");
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("users");
    
    // ok: java-no-sql-injection-ide
    Document query = new Document("username", username);
    Document result = collection.find(query).first();
    
    // Safe because user input is passed as a value to a field, not interpolated into a string
}

public void good_case_2(HttpServletRequest request) {
    String userId = request.getParameter("id");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDB dynamoDB = new DynamoDB(client);
    Table table = dynamoDB.getTable("Users");
    
    // ok: java-no-sql-injection-ide
    QuerySpec querySpec = new QuerySpec()
        .withKeyConditionExpression("id = :v_id")
        .withValueMap(new ValueMap().withString(":v_id", userId));
    
    // Safe because user input is passed as a parameter value, not interpolated into the expression
}

@RestController
public void good_case_3(@RequestParam String role) {
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("employees");
    
    // Validate input
    if (!role.matches("[a-zA-Z0-9_]+")) {
        throw new IllegalArgumentException("Invalid role format");
    }
    
    // ok: java-no-sql-injection-ide
    collection.find(Filters.eq("role", role));
    
    // Safe because user input is validated and passed through a filter method
}

public void good_case_4(spark.Request request) {
    String ageStr = request.queryParams("age");
    
    // Validate and convert input
    int age;
    try {
        age = Integer.parseInt(ageStr);
    } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Age must be a number");
    }
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("customers");
    
    // ok: java-no-sql-injection-ide
    collection.find(Filters.gt("age", age));
    
    // Safe because user input is validated, converted to the appropriate type, and passed through a filter method
}

public void good_case_5(Context context) {
    String department = context.queryParam("dept");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
    expressionAttributeValues.put(":dept", new AttributeValue().withS(department));
    
    // ok: java-no-sql-injection-ide
    ScanRequest scanRequest = new ScanRequest()
        .withTableName("Employees")
        .withFilterExpression("department = :dept")
        .withExpressionAttributeValues(expressionAttributeValues);
    
    // Safe because user input is passed as a parameter value, not interpolated into the expression
}

public void good_case_6(RoutingContext routingContext) {
    String status = routingContext.request().getParam("status");
    
    // Validate input against allowed values
    List<String> allowedStatuses = Arrays.asList("pending", "processing", "shipped", "delivered");
    if (!allowedStatuses.contains(status)) {
        throw new IllegalArgumentException("Invalid status");
    }
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("orders");
    
    // ok: java-no-sql-injection-ide
    collection.find(Filters.eq("status", status));
    
    // Safe because user input is validated against a whitelist and passed through a filter method
}

public void good_case_7(@RequestBody Map<String, String> payload) {
    String category = payload.get("category");
    
    MongoTemplate mongoTemplate = new MongoTemplate(new MongoClient(), "mydb");
    
    // Validate input
    if (!category.matches("[a-zA-Z0-9_]+")) {
        throw new IllegalArgumentException("Invalid category format");
    }
    
    // ok: java-no-sql-injection-ide
    Query query = new Query();
    query.addCriteria(Criteria.where("category").is(category));
    mongoTemplate.find(query, Product.class);
    
    // Safe because user input is validated and passed as a parameter value to the criteria
}

public void good_case_8(HttpServletRequest request) {
    String minRatingStr = request.getParameter("minRating");
    
    // Validate and convert input
    double minRating;
    try {
        minRating = Double.parseDouble(minRatingStr);
    } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Rating must be a number");
    }
    
    ReactiveMongoClient mongoClient = MongoClients.create("mongodb://localhost");
    com.mongodb.reactivestreams.client.MongoDatabase database = mongoClient.getDatabase("mydb");
    com.mongodb.reactivestreams.client.MongoCollection<Document> collection = database.getCollection("reviews");
    
    // ok: java-no-sql-injection-ide
    collection.find(Filters.gte("rating", minRating));
    
    // Safe because user input is validated, converted to the appropriate type, and passed through a filter method
}

public void good_case_9(HttpServletRequest request) {
    String email = request.getParameter("email");
    
    com.mongodb.client.MongoClient mongoClient = KMongo.createClient();
    com.mongodb.client.MongoDatabase database = mongoClient.getDatabase("mydb");
    com.mongodb.client.MongoCollection<Document> collection = database.getCollection("subscribers");
    
    // ok: java-no-sql-injection-ide
    collection.find(eq(User::getEmail, email));
    
    // Safe because user input is passed through a type-safe filter method
}

public void good_case_10(HttpServletRequest request) {
    String zipCode = request.getParameter("zipCode");
    
    // Validate input
    if (!zipCode.matches("\\d{5}(-\\d{4})?")) {
        throw new IllegalArgumentException("Invalid ZIP code format");
    }
    
    Morphia morphia = new Morphia();
    Datastore datastore = morphia.createDatastore(new MongoClient(), "mydb");
    
    // ok: java-no-sql-injection-ide
    datastore.find(Address.class).filter(
        dev.morphia.query.filters.Filters.eq("zipCode", zipCode)
    ).iterator();
    
    // Safe because user input is validated and passed through a filter method
}

public void good_case_11(HttpServletRequest request) {
    String productId = request.getParameter("productId");
    
    // Validate input
    if (!productId.matches("[A-Z0-9]{10}")) {
        throw new IllegalArgumentException("Invalid product ID format");
    }
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    Map<String, AttributeValue> eav = new HashMap<>();
    eav.put(":val", new AttributeValue().withS(productId));
    
    // ok: java-no-sql-injection-ide
    DynamoDBQueryExpression<Product> queryExpression = new DynamoDBQueryExpression<Product>()
        .withKeyConditionExpression("id = :val")
        .withExpressionAttributeValues(eav);
    mapper.query(Product.class, queryExpression);
    
    // Safe because user input is validated and passed as a parameter value, not interpolated into the expression
}

public void good_case_12(HttpServletRequest request) {
    String region = request.getParameter("region");
    
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    Map<String, AwsAttributeValue> expressionValues = new HashMap<>();
    expressionValues.put(":r", AwsAttributeValue.builder().s(region).build());
    
    // ok: java-no-sql-injection-ide
    QueryRequest queryRequest = QueryRequest.builder()
        .tableName("Sales")
        .keyConditionExpression("region = :r")
        .expressionAttributeValues(expressionValues)
        .build();
    
    // Safe because user input is passed as a parameter value, not interpolated into the expression
}

public void good_case_13(@RequestHeader String apiKey) {
    // Validate input
    if (!apiKey.matches("[A-Za-z0-9_-]{32}")) {
        throw new IllegalArgumentException("Invalid API key format");
    }
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("apiusers");
    
    // ok: java-no-sql-injection-ide
    collection.find(Filters.eq("apiKey", apiKey));
    
    // Safe because user input is validated and passed through a filter method
}

public void good_case_14(HttpServletRequest request) {
    String sortField = request.getParameter("sort");
    
    // Validate input against allowed values
    Map<String, Integer> allowedSortFields = new HashMap<>();
    allowedSortFields.put("price", 1);
    allowedSortFields.put("name", 1);
    allowedSortFields.put("date", -1);
    
    if (!allowedSortFields.containsKey(sortField)) {
        throw new IllegalArgumentException("Invalid sort field");
    }
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("products");
    
    // ok: java-no-sql-injection-ide
    collection.find().sort(new Document(sortField, allowedSortFields.get(sortField)));
    
    // Safe because user input is validated against a whitelist
}

public void good_case_15(HttpServletRequest request) {
    String groupField = request.getParameter("groupBy");
    
    // Validate input against allowed values
    List<String> allowedGroupFields = Arrays.asList("category", "vendor", "region");
    if (!allowedGroupFields.contains(groupField)) {
        throw new IllegalArgumentException("Invalid group field");
    }
    
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("transactions");
    
    // ok: java-no-sql-injection-ide
    Document groupBy = new Document("_id", "$" + groupField)
                        .append("total", new Document("$sum", "$amount"));
    collection.aggregate(java.util.Arrays.asList(new Document("$group", groupBy)));
    
    // Safe because user input is validated against a whitelist before being used in the aggregation pipeline
}