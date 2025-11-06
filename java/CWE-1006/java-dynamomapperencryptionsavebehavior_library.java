import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItem;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.amazonaws.services.dynamodbv2.model.Put;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.spec.PutItemSpec;
import com.amazonaws.services.dynamodbv2.transactions.TransactionManager;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest.Builder;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.mapper.StaticTableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import io.github.boostchicken.dynamodb.transactions.Transaction;
import io.github.boostchicken.dynamodb.transactions.TransactionBuilder;
import io.github.boostchicken.dynamodb.transactions.TransactionExecutor;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.dynamodb.repository.DynamoDBRepository;
import org.springframework.data.dynamodb.repository.EnableDynamoDBRepositories;
import org.springframework.data.dynamodb.repository.config.EnableDynamoDBRepositories;
import org.springframework.data.dynamodb.core.DynamoDBTemplate;
import org.springframework.data.dynamodb.core.DynamoDBOperations;
import com.amazonaws.services.dynamodbv2.transactions.TransactionManager;
import com.amazonaws.services.dynamodbv2.transactions.Transaction;
import com.amazonaws.services.dynamodbv2.transactions.Request;
import com.amazonaws.services.dynamodbv2.transactions.exceptions.TransactionException;
import com.amazonaws.services.dynamodbv2.transactions.exceptions.ItemNotLockedException;
import com.amazonaws.services.dynamodbv2.transactions.exceptions.DuplicateRequestException;
import com.amazonaws.services.dynamodbv2.transactions.exceptions.TransactionCompletedException;
import com.amazonaws.services.dynamodbv2.transactions.exceptions.TransactionNotFoundException;
import com.amazonaws.services.dynamodbv2.transactions.exceptions.TransactionTimedOutException;
import com.amazonaws.services.dynamodbv2.transactions.exceptions.UnknownCompletedTransactionException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;

// Security Issue: Using client-side transaction libraries for DynamoDB operations can introduce performance overhead and higher costs compared to using DynamoDB's native transactional APIs.

// Model class for examples
@DynamoDBTable(tableName = "Users")
class User {
    private String id;
    private String name;
    private String email;
    private String sensitiveData;

    @DynamoDBHashKey
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    @DynamoDBAttribute
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    @DynamoDBAttribute
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    @DynamoDBAttribute
    public String getSensitiveData() { return sensitiveData; }
    public void setSensitiveData(String sensitiveData) { this.sensitiveData = sensitiveData; }
}

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    // ruleid: java-dynamomapperencryptionsavebehavior
    TransactionManager txManager = new TransactionManager(client, "TransactionTable");
    Transaction tx = txManager.newTransaction();
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    try {
        tx.save(mapper, user);
        tx.commit();
    } catch (Exception e) {
        tx.rollback();
    }
}

public void bad_case_2(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    // ruleid: java-dynamomapperencryptionsavebehavior
    io.github.boostchicken.dynamodb.transactions.TransactionExecutor executor = 
        new io.github.boostchicken.dynamodb.transactions.TransactionExecutor(client);
    
    TransactionBuilder txBuilder = new TransactionBuilder();
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    txBuilder.save(mapper, user);
    
    executor.executeTransaction(txBuilder.build());
}

public void bad_case_3(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    // Custom transaction library implementation
    // ruleid: java-dynamomapperencryptionsavebehavior
    CustomTransactionManager txManager = new CustomTransactionManager(client);
    CustomTransaction tx = txManager.beginTransaction();
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.addOperation(new SaveOperation(mapper, user));
    tx.commit();
}

public void bad_case_4(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    // Spring Data DynamoDB with custom transaction manager
    // ruleid: java-dynamomapperencryptionsavebehavior
    SpringTransactionManager txManager = new SpringTransactionManager(client);
    SpringTransaction tx = txManager.startTransaction();
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.save(mapper, user);
    tx.commit();
}

public void bad_case_5(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    // ruleid: java-dynamomapperencryptionsavebehavior
    DynamoDBTransactionLibrary txLib = new DynamoDBTransactionLibrary(client);
    Transaction tx = txLib.createTransaction();
    
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.addItem(mapper, user);
    tx.execute();
}

public void bad_case_6(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    // Using a third-party transaction library with encryption
    AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
    DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab");
    DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
    
    // ruleid: java-dynamomapperencryptionsavebehavior
    EncryptedTransactionManager txManager = new EncryptedTransactionManager(client, encryptor);
    EncryptedTransaction tx = txManager.beginTransaction();
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.saveEncrypted(mapper, user);
    tx.commit();
}

public void bad_case_7(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using a custom ORM with client-side transactions
    CustomDynamoDBClient client = new CustomDynamoDBClient();
    
    // ruleid: java-dynamomapperencryptionsavebehavior
    CustomTransactionCoordinator coordinator = new CustomTransactionCoordinator(client);
    CustomTransaction tx = coordinator.startTransaction();
    
    UserEntity user = new UserEntity();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.save(user);
    tx.commit();
}

public void bad_case_8(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    // Using a distributed transaction manager
    // ruleid: java-dynamomapperencryptionsavebehavior
    DistributedTransactionManager txManager = new DistributedTransactionManager(client);
    DistributedTransaction tx = txManager.createTransaction();
    
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.addOperation(new SaveOperation(mapper, user));
    tx.execute();
}

public void bad_case_9(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using a reactive transaction library
    ReactiveDynamoDBClient client = new ReactiveDynamoDBClient();
    
    // ruleid: java-dynamomapperencryptionsavebehavior
    ReactiveTransactionManager txManager = new ReactiveTransactionManager(client);
    ReactiveTransaction tx = txManager.beginTransaction();
    
    UserDocument user = new UserDocument();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.save(user)
      .then(tx.commit())
      .subscribe();
}

public void bad_case_10(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    // Using a transaction library with optimistic locking
    // ruleid: java-dynamomapperencryptionsavebehavior
    OptimisticTransactionManager txManager = new OptimisticTransactionManager(client);
    OptimisticTransaction tx = txManager.beginTransaction();
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.save(mapper, user);
    tx.commit();
}

public void bad_case_11(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using a microservice transaction coordinator
    // ruleid: java-dynamomapperencryptionsavebehavior
    MicroserviceTransactionCoordinator coordinator = new MicroserviceTransactionCoordinator();
    MicroserviceTransaction tx = coordinator.createTransaction();
    
    DynamoDBService dynamoService = new DynamoDBService();
    UserRecord user = new UserRecord();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.addOperation(() -> dynamoService.saveUser(user));
    tx.execute();
}

public void bad_case_12(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    // Using a transaction library with retry logic
    // ruleid: java-dynamomapperencryptionsavebehavior
    RetryableTransactionManager txManager = new RetryableTransactionManager(client);
    RetryableTransaction tx = txManager.beginTransaction();
    
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.save(mapper, user);
    tx.commitWithRetry(3);
}

public void bad_case_13(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using a transaction library with event sourcing
    // ruleid: java-dynamomapperencryptionsavebehavior
    EventSourcedTransactionManager txManager = new EventSourcedTransactionManager();
    EventSourcedTransaction tx = txManager.startTransaction();
    
    DynamoDBEventStore eventStore = new DynamoDBEventStore();
    UserAggregate user = new UserAggregate(userId);
    user.updateName(userData);
    user.updateSensitiveData("sensitive-" + userData);
    
    tx.recordEvents(user.getUncommittedEvents());
    tx.commit();
}

public void bad_case_14(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    // Using a transaction library with custom serialization
    // ruleid: java-dynamomapperencryptionsavebehavior
    SerializingTransactionManager txManager = new SerializingTransactionManager(client);
    SerializingTransaction tx = txManager.beginTransaction();
    
    UserDTO user = new UserDTO();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.saveWithCustomSerializer(user, new UserSerializer());
    tx.commit();
}

public void bad_case_15(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using a transaction library with audit logging
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    // ruleid: java-dynamomapperencryptionsavebehavior
    AuditedTransactionManager txManager = new AuditedTransactionManager(client);
    AuditedTransaction tx = txManager.beginTransaction("USER_UPDATE");
    
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    tx.saveWithAudit(mapper, user, "admin");
    tx.commit();
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    // Using native DynamoDB transactional API
    List<TransactWriteItem> actions = new ArrayList<>();
    
    Map<String, com.amazonaws.services.dynamodbv2.model.AttributeValue> item = new HashMap<>();
    item.put("id", new com.amazonaws.services.dynamodbv2.model.AttributeValue(userId));
    item.put("name", new com.amazonaws.services.dynamodbv2.model.AttributeValue(userData));
    item.put("sensitiveData", new com.amazonaws.services.dynamodbv2.model.AttributeValue("sensitive-" + userData));
    
    Put put = new Put()
        .withTableName("Users")
        .withItem(item);
    
    actions.add(new TransactWriteItem().withPut(put));
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactWriteItemsRequest placeOrderTransaction = new TransactWriteItemsRequest()
        .withTransactItems(actions);
    
    client.transactWriteItems(placeOrderTransaction);
}

public void good_case_2(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using AWS SDK v2 with native transactional API
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    Map<String, AttributeValue> item = new HashMap<>();
    item.put("id", AttributeValue.builder().s(userId).build());
    item.put("name", AttributeValue.builder().s(userData).build());
    item.put("sensitiveData", AttributeValue.builder().s("sensitive-" + userData).build());
    
    Put put = Put.builder()
        .tableName("Users")
        .item(item)
        .build();
    
    TransactWriteItem transactWriteItem = TransactWriteItem.builder()
        .put(put)
        .build();
    
    // ok: java-dynamomapperencryptionsavebehavior
    software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest transactRequest = 
        software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest.builder()
            .transactItems(transactWriteItem)
            .build();
    
    dynamoDbClient.transactWriteItems(transactRequest);
}

public void good_case_3(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using Enhanced DynamoDB Client with native transactional API
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient.builder()
        .dynamoDbClient(dynamoDbClient)
        .build();
    
    // Define the schema for the User table
    TableSchema<User> userSchema = TableSchema.fromBean(User.class);
    DynamoDbTable<User> userTable = enhancedClient.table("Users", userSchema);
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactWriteItemsEnhancedRequest transactRequest = TransactWriteItemsEnhancedRequest.builder()
        .addPutItem(userTable, user)
        .build();
    
    enhancedClient.transactWriteItems(transactRequest);
}

public void good_case_4(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDB dynamoDB = new DynamoDB(client);
    
    Table table = dynamoDB.getTable("Users");
    Item item = new Item()
        .withPrimaryKey("id", userId)
        .withString("name", userData)
        .withString("sensitiveData", "sensitive-" + userData);
    
    List<TransactWriteItem> actions = new ArrayList<>();
    
    Put put = new Put()
        .withTableName("Users")
        .withItem(item.asMap());
    
    actions.add(new TransactWriteItem().withPut(put));
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactWriteItemsRequest transactRequest = new TransactWriteItemsRequest()
        .withTransactItems(actions);
    
    client.transactWriteItems(transactRequest);
}

public void good_case_5(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using DynamoDBMapper with native transactional API
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
    transactionWriteRequest.addPut(user);
    
    mapper.transactionWrite(transactionWriteRequest);
}

public void good_case_6(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using Spring Data DynamoDB with native transactional API
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBOperations dynamoDBOperations = new DynamoDBTemplate(client);
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    List<TransactWriteItem> actions = new ArrayList<>();
    
    // Convert the user object to a map of attribute values
    Map<String, com.amazonaws.services.dynamodbv2.model.AttributeValue> item = new HashMap<>();
    item.put("id", new com.amazonaws.services.dynamodbv2.model.AttributeValue(userId));
    item.put("name", new com.amazonaws.services.dynamodbv2.model.AttributeValue(userData));
    item.put("sensitiveData", new com.amazonaws.services.dynamodbv2.model.AttributeValue("sensitive-" + userData));
    
    Put put = new Put()
        .withTableName("Users")
        .withItem(item);
    
    actions.add(new TransactWriteItem().withPut(put));
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactWriteItemsRequest transactRequest = new TransactWriteItemsRequest()
        .withTransactItems(actions);
    
    client.transactWriteItems(transactRequest);
}

public void good_case_7(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using AWS SDK v2 with batch operations instead of transactions
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    Map<String, AttributeValue> item = new HashMap<>();
    item.put("id", AttributeValue.builder().s(userId).build());
    item.put("name", AttributeValue.builder().s(userData).build());
    item.put("sensitiveData", AttributeValue.builder().s("sensitive-" + userData).build());
    
    // ok: java-dynamomapperencryptionsavebehavior
    PutItemRequest putRequest = PutItemRequest.builder()
        .tableName("Users")
        .item(item)
        .build();
    
    dynamoDbClient.putItem(putRequest);
}

public void good_case_8(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using DynamoDB Document API with native transactional API
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDB dynamoDB = new DynamoDB(client);
    
    Table table = dynamoDB.getTable("Users");
    
    // Create multiple items for transaction
    Item userItem = new Item()
        .withPrimaryKey("id", userId)
        .withString("name", userData)
        .withString("sensitiveData", "sensitive-" + userData);
    
    Item logItem = new Item()
        .withPrimaryKey("logId", "log-" + userId)
        .withString("action", "CREATE")
        .withString("timestamp", String.valueOf(System.currentTimeMillis()));
    
    List<TransactWriteItem> actions = new ArrayList<>();
    
    actions.add(new TransactWriteItem().withPut(
        new Put().withTableName("Users").withItem(userItem.asMap())
    ));
    
    actions.add(new TransactWriteItem().withPut(
        new Put().withTableName("Logs").withItem(logItem.asMap())
    ));
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactWriteItemsRequest transactRequest = new TransactWriteItemsRequest()
        .withTransactItems(actions);
    
    client.transactWriteItems(transactRequest);
}

public void good_case_9(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using DynamoDBMapper for single item operations (no transaction needed)
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    // ok: java-dynamomapperencryptionsavebehavior
    mapper.save(user);
}

public void good_case_10(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using Enhanced DynamoDB Client for single item operations
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient.builder()
        .dynamoDbClient(dynamoDbClient)
        .build();
    
    TableSchema<User> userSchema = TableSchema.fromBean(User.class);
    DynamoDbTable<User> userTable = enhancedClient.table("Users", userSchema);
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    // ok: java-dynamomapperencryptionsavebehavior
    userTable.putItem(user);
}

public void good_case_11(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using native DynamoDB transactional API with condition expressions
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    Map<String, com.amazonaws.services.dynamodbv2.model.AttributeValue> item = new HashMap<>();
    item.put("id", new com.amazonaws.services.dynamodbv2.model.AttributeValue(userId));
    item.put("name", new com.amazonaws.services.dynamodbv2.model.AttributeValue(userData));
    item.put("sensitiveData", new com.amazonaws.services.dynamodbv2.model.AttributeValue("sensitive-" + userData));
    
    Put put = new Put()
        .withTableName("Users")
        .withItem(item)
        .withConditionExpression("attribute_not_exists(id)");
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactWriteItemsRequest transactRequest = new TransactWriteItemsRequest()
        .withTransactItems(new TransactWriteItem().withPut(put));
    
    client.transactWriteItems(transactRequest);
}

public void good_case_12(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using AWS SDK v2 with native transactional API and multiple operations
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    Map<String, AttributeValue> userItem = new HashMap<>();
    userItem.put("id", AttributeValue.builder().s(userId).build());
    userItem.put("name", AttributeValue.builder().s(userData).build());
    userItem.put("sensitiveData", AttributeValue.builder().s("sensitive-" + userData).build());
    
    Map<String, AttributeValue> auditItem = new HashMap<>();
    auditItem.put("auditId", AttributeValue.builder().s("audit-" + userId).build());
    auditItem.put("action", AttributeValue.builder().s("CREATE").build());
    auditItem.put("timestamp", AttributeValue.builder().s(String.valueOf(System.currentTimeMillis())).build());
    
    Put userPut = Put.builder()
        .tableName("Users")
        .item(userItem)
        .build();
    
    Put auditPut = Put.builder()
        .tableName("Audits")
        .item(auditItem)
        .build();
    
    TransactWriteItem userWriteItem = TransactWriteItem.builder()
        .put(userPut)
        .build();
    
    TransactWriteItem auditWriteItem = TransactWriteItem.builder()
        .put(auditPut)
        .build();
    
    // ok: java-dynamomapperencryptionsavebehavior
    software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest transactRequest = 
        software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest.builder()
            .transactItems(userWriteItem, auditWriteItem)
            .build();
    
    dynamoDbClient.transactWriteItems(transactRequest);
}

public void good_case_13(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using DynamoDBMapper with optimistic locking but native transactional API
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDBMapperConfig config = DynamoDBMapperConfig.builder()
        .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.UPDATE_SKIP_NULL_ATTRIBUTES)
        .withConsistentReads(DynamoDBMapperConfig.ConsistentReads.CONSISTENT)
        .build();
    
    DynamoDBMapper mapper = new DynamoDBMapper(client, config);
    
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
    transactionWriteRequest.addPut(user);
    
    mapper.transactionWrite(transactionWriteRequest);
}

public void good_case_14(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using DynamoDB Document API with conditional writes
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    DynamoDB dynamoDB = new DynamoDB(client);
    
    Table table = dynamoDB.getTable("Users");
    
    Item item = new Item()
        .withPrimaryKey("id", userId)
        .withString("name", userData)
        .withString("sensitiveData", "sensitive-" + userData);
    
    // ok: java-dynamomapperencryptionsavebehavior
    PutItemSpec putItemSpec = new PutItemSpec()
        .withItem(item)
        .withConditionExpression("attribute_not_exists(id)");
    
    table.putItem(putItemSpec);
}

public void good_case_15(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    String userData = request.getParameter("userData");
    
    // Using Spring Data DynamoDB repository pattern
    AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    
    // Create a user entity
    User user = new User();
    user.setId(userId);
    user.setName(userData);
    user.setSensitiveData("sensitive-" + userData);
    
    // Create a transaction request with native API
    List<TransactWriteItem> actions = new ArrayList<>();
    
    // Convert the user object to a map of attribute values
    Map<String, com.amazonaws.services.dynamodbv2.model.AttributeValue> item = new HashMap<>();
    item.put("id", new com.amazonaws.services.dynamodbv2.model.AttributeValue(userId));
    item.put("name", new com.amazonaws.services.dynamodbv2.model.AttributeValue(userData));
    item.put("sensitiveData", new com.amazonaws.services.dynamodbv2.model.AttributeValue("sensitive-" + userData));
    
    Put put = new Put()
        .withTableName("Users")
        .withItem(item);
    
    actions.add(new TransactWriteItem().withPut(put));
    
    // ok: java-dynamomapperencryptionsavebehavior
    TransactWriteItemsRequest transactRequest = new TransactWriteItemsRequest()
        .withTransactItems(actions);
    
    client.transactWriteItems(transactRequest);
}

// Helper classes for examples
class CustomTransactionManager {
    public CustomTransactionManager(AmazonDynamoDB client) {}
    public CustomTransaction beginTransaction() { return new CustomTransaction(); }
}

class CustomTransaction {
    public void addOperation(SaveOperation op) {}
    public void commit() {}
}

class SaveOperation {
    public SaveOperation(DynamoDBMapper mapper, Object item) {}
}

class SpringTransactionManager {
    public SpringTransactionManager(AmazonDynamoDB client) {}
    public SpringTransaction startTransaction() { return new SpringTransaction(); }
}

class SpringTransaction {
    public void save(DynamoDBMapper mapper, Object item) {}
    public void commit() {}
}

class DynamoDBTransactionLibrary {
    public DynamoDBTransactionLibrary(AmazonDynamoDB client) {}
    public Transaction createTransaction() { return new Transaction(); }
}

class EncryptedTransactionManager {
    public EncryptedTransactionManager(AmazonDynamoDB client, DynamoDBEncryptor encryptor) {}
    public EncryptedTransaction beginTransaction() { return new EncryptedTransaction(); }
}

class EncryptedTransaction {
    public void saveEncrypted(DynamoDBMapper mapper, Object item) {}
    public void commit() {}
}

class CustomDynamoDBClient {}

class CustomTransactionCoordinator {
    public CustomTransactionCoordinator(CustomDynamoDBClient client) {}
    public CustomTransaction startTransaction() { return new CustomTransaction(); }
}

class UserEntity {}

class DistributedTransactionManager {
    public DistributedTransactionManager(AmazonDynamoDB client) {}
    public DistributedTransaction createTransaction() { return new DistributedTransaction(); }
}

class DistributedTransaction {
    public void addOperation(SaveOperation op) {}
    public void execute() {}
}

class ReactiveDynamoDBClient {}

class ReactiveTransactionManager {
    public ReactiveTransactionManager(ReactiveDynamoDBClient client) {}
    public ReactiveTransaction beginTransaction() { return new ReactiveTransaction(); }
}

class ReactiveTransaction {
    public ReactiveTransaction save(Object item) { return this; }
    public ReactiveTransaction then(ReactiveTransaction tx) { return this; }
    public void subscribe() {}
    public ReactiveTransaction commit() { return this; }
}

class UserDocument {
    private String id;
    private String name;
    private String sensitiveData;
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getSensitiveData() { return sensitiveData; }
    public void setSensitiveData(String sensitiveData) { this.sensitiveData = sensitiveData; }
}

class OptimisticTransactionManager {
    public OptimisticTransactionManager(AmazonDynamoDB client) {}
    public OptimisticTransaction beginTransaction() { return new OptimisticTransaction(); }
}

class OptimisticTransaction {
    public void save(DynamoDBMapper mapper, Object item) {}
    public void commit() {}
}

class MicroserviceTransactionCoordinator {
    public MicroserviceTransaction createTransaction() { return new MicroserviceTransaction(); }
}

class MicroserviceTransaction {
    public void addOperation(Runnable operation) {}
    public void execute() {}
}

class DynamoDBService {
    public void saveUser(UserRecord user) {}
}

class UserRecord {
    private String id;
    private String name;
    private String sensitiveData;
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getSensitiveData() { return sensitiveData; }
    public void setSensitiveData(String sensitiveData) { this.sensitiveData = sensitiveData; }
}

class RetryableTransactionManager {
    public RetryableTransactionManager(AmazonDynamoDB client) {}
    public RetryableTransaction beginTransaction() { return new RetryableTransaction(); }
}

class RetryableTransaction {
    public void save(DynamoDBMapper mapper, Object item) {}
    public void commitWithRetry(int maxRetries) {}
}

class EventSourcedTransactionManager {
    public EventSourcedTransaction startTransaction() { return new EventSourcedTransaction(); }
}

class EventSourcedTransaction {
    public void recordEvents(List<Object> events) {}
    public void commit() {}
}

class DynamoDBEventStore {}

class UserAggregate {
    public UserAggregate(String id) {}
    public void updateName(String name) {}
    public void updateSensitiveData(String data) {}
    public List<Object> getUncommittedEvents() { return new ArrayList<>(); }
}

class SerializingTransactionManager {
    public SerializingTransactionManager(AmazonDynamoDB client) {}
    public SerializingTransaction beginTransaction() { return new SerializingTransaction(); }
}

class SerializingTransaction {
    public void saveWithCustomSerializer(Object item, UserSerializer serializer) {}
    public void commit() {}
}

class UserDTO {
    private String id;
    private String name;
    private String sensitiveData;
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getSensitiveData() { return sensitiveData; }
    public void setSensitiveData(String sensitiveData) { this.sensitiveData = sensitiveData; }
}

class UserSerializer {}

class AuditedTransactionManager {
    public AuditedTransactionManager(AmazonDynamoDB client) {}
    public AuditedTransaction beginTransaction(String operationType) { return new AuditedTransaction(); }
}

class AuditedTransaction {
    public void saveWithAudit(DynamoDBMapper mapper, Object item, String userId) {}
    public void commit() {}
}

class TransactionWriteRequest {
    public void addPut(Object item) {}
}

@RestController
class DynamoDBController {
    @PostMapping("/users")
    public ResponseEntity<String> createUser(@RequestBody User user, HttpServletRequest request) {
        // Call one of the example methods
        good_case_1(request);
        return ResponseEntity.ok("User created");
    }
}