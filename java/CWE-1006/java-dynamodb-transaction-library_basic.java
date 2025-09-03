import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.model.*;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTransactionManager;
import com.amazonaws.services.dynamodbv2.datamodeling.TransactionWriteRequest;
import com.amazonaws.services.dynamodbv2.datamodeling.TransactionLoadRequest;
import com.amazonaws.services.dynamodbv2.transactions.Transaction;
import com.amazonaws.services.dynamodbv2.transactions.TransactionManager;
import com.amazonaws.services.dynamodbv2.transactions.exceptions.TransactionException;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItem;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.amazonaws.services.dynamodbv2.model.TransactGetItemsRequest;
import com.amazonaws.services.dynamodbv2.model.TransactGetItem;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DynamoDBTransactionExamples {

    // True Positives (Vulnerable/Insecure Code)

// {fact rule=batches-preferred-over-loops@v1.0 defects=1}
    public void bad_case_1() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        TransactionManager transactionManager = new TransactionManager(dynamoDBClient, "LockTable");
        Transaction transaction = transactionManager.newTransaction();
        
        try {
            transaction.put(dynamoDB.getTable("Users"), new Item().withPrimaryKey("UserId", "user123").withString("Name", "John Doe"));
            transaction.put(dynamoDB.getTable("Orders"), new Item().withPrimaryKey("OrderId", "order456").withString("Status", "Pending"));
            transaction.commit();
        } catch (TransactionException e) {
            transaction.rollback();
        }
    }

    public void bad_case_2() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        TransactionManager txManager = new TransactionManager(dynamoDBClient, "TransactionLockTable");
        Transaction tx = txManager.newTransaction();
        
        try {
            Map<String, AttributeValue> userKey = new HashMap<>();
            userKey.put("UserId", new AttributeValue().withS("user123"));
            
            tx.load(dynamoDBClient, "Users", userKey);
            tx.delete(dynamoDB.getTable("Users"), new Item().withPrimaryKey("UserId", "user123"));
            tx.commit();
        } catch (Exception e) {
            tx.rollback();
        }
    }

    public void bad_case_3() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        DynamoDBTransactionManager transactionManager = new DynamoDBTransactionManager(mapper);
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        
        User user = new User();
        user.setUserId("user123");
        user.setName("John Doe");
        
        Order order = new Order();
        order.setOrderId("order456");
        order.setStatus("Pending");
        
        transactionWriteRequest.addPut(user);
        transactionWriteRequest.addPut(order);
        
        transactionManager.executeTransactionWrite(transactionWriteRequest);
    }

    public void bad_case_4() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ruleid: java-dynamodb-transaction-library
        TransactionManager txManager = new TransactionManager(dynamoDBClient, "LockTable");
        Transaction transaction = txManager.newTransaction();
        
        try {
            Map<String, AttributeValue> key1 = new HashMap<>();
            key1.put("PK", new AttributeValue().withS("USER#123"));
            
            Map<String, AttributeValue> key2 = new HashMap<>();
            key2.put("PK", new AttributeValue().withS("ORDER#456"));
            
            transaction.load(dynamoDBClient, "DataTable", key1);
            transaction.load(dynamoDBClient, "DataTable", key2);
            
            // Business logic here
            
            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
        }
    }

    public void bad_case_5() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        DynamoDBTransactionManager txManager = new DynamoDBTransactionManager(mapper);
        TransactionLoadRequest loadRequest = new TransactionLoadRequest();
        
        User user = new User();
        user.setUserId("user123");
        
        Order order = new Order();
        order.setOrderId("order456");
        
        loadRequest.addLoad(user);
        loadRequest.addLoad(order);
        
        txManager.executeTransactionLoad(loadRequest);
    }

    public void bad_case_6() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        TransactionManager txManager = new TransactionManager(dynamoDBClient, "TransactionLockTable");
        
        for (int i = 0; i < 10; i++) {
            Transaction tx = txManager.newTransaction();
            try {
                tx.put(dynamoDB.getTable("Inventory"), 
                    new Item().withPrimaryKey("ProductId", "product" + i)
                              .withNumber("Quantity", 100));
                tx.commit();
            } catch (Exception e) {
                tx.rollback();
            }
        }
    }

    public void bad_case_7() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        DynamoDBTransactionManager transactionManager = new DynamoDBTransactionManager(mapper);
        
        try {
            TransactionWriteRequest writeRequest = new TransactionWriteRequest();
            
            Product product = new Product();
            product.setProductId("prod123");
            product.setStock(50);
            
            Inventory inventory = new Inventory();
            inventory.setProductId("prod123");
            inventory.setWarehouse("warehouse1");
            inventory.setQuantity(50);
            
            writeRequest.addPut(product);
            writeRequest.addPut(inventory);
            
            transactionManager.executeTransactionWrite(writeRequest);
        } catch (Exception e) {
            // Handle exception
        }
    }

    public void bad_case_8() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ruleid: java-dynamodb-transaction-library
        TransactionManager txManager = new TransactionManager(dynamoDBClient, "LockTable");
        Transaction tx = txManager.newTransaction();
        
        try {
            DynamoDB dynamoDB = new DynamoDB(dynamoDBClient);
            Table accountTable = dynamoDB.getTable("Accounts");
            
            // Transfer money between accounts
            tx.update(accountTable, 
                new Item().withPrimaryKey("AccountId", "account1"), 
                "SET Balance = Balance - :amount", 
                new HashMap<String, Object>() {{ put(":amount", 100); }});
                
            tx.update(accountTable, 
                new Item().withPrimaryKey("AccountId", "account2"), 
                "SET Balance = Balance + :amount", 
                new HashMap<String, Object>() {{ put(":amount", 100); }});
                
            tx.commit();
        } catch (Exception e) {
            tx.rollback();
        }
    }

    public void bad_case_9() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        DynamoDBTransactionManager txManager = new DynamoDBTransactionManager(mapper);
        
        if (checkCondition()) {
            TransactionWriteRequest writeRequest = new TransactionWriteRequest();
            
            User user = mapper.load(User.class, "user123");
            user.setStatus("Active");
            
            Order order = new Order();
            order.setOrderId("order789");
            order.setUserId("user123");
            
            writeRequest.addUpdate(user);
            writeRequest.addPut(order);
            
            txManager.executeTransactionWrite(writeRequest);
        }
    }

    public void bad_case_10() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ruleid: java-dynamodb-transaction-library
        TransactionManager txManager = new TransactionManager(dynamoDBClient, "TransactionLockTable");
        Transaction tx = txManager.newTransaction();
        
        try {
            DynamoDB dynamoDB = new DynamoDB(dynamoDBClient);
            
            // Complex transaction with multiple operations
            tx.load(dynamoDBClient, "Users", createKey("UserId", "user123"));
            tx.load(dynamoDBClient, "Products", createKey("ProductId", "prod456"));
            
            tx.put(dynamoDB.getTable("Orders"), new Item()
                .withPrimaryKey("OrderId", "order789")
                .withString("UserId", "user123")
                .withString("ProductId", "prod456")
                .withNumber("Quantity", 2));
                
            tx.update(dynamoDB.getTable("Inventory"), 
                new Item().withPrimaryKey("ProductId", "prod456"), 
                "SET Stock = Stock - :qty", 
                new HashMap<String, Object>() {{ put(":qty", 2); }});
                
            tx.commit();
        } catch (Exception e) {
            tx.rollback();
        }
    }

    public void bad_case_11() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        DynamoDBTransactionManager txManager = new DynamoDBTransactionManager(mapper);
        
        String userId = "user123";
        String orderId = "order456";
        
        TransactionLoadRequest loadRequest = new TransactionLoadRequest();
        
        User userKey = new User();
        userKey.setUserId(userId);
        
        Order orderKey = new Order();
        orderKey.setOrderId(orderId);
        
        loadRequest.addLoad(userKey);
        loadRequest.addLoad(orderKey);
        
        Map<Class<?>, List<Object>> results = txManager.executeTransactionLoad(loadRequest);
        
        // Process results
        User loadedUser = (User) results.get(User.class).get(0);
        Order loadedOrder = (Order) results.get(Order.class).get(0);
    }

    public void bad_case_12() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ruleid: java-dynamodb-transaction-library
        TransactionManager txManager = new TransactionManager(dynamoDBClient, "LockTable");
        
        try {
            // Batch processing with transactions
            List<String> userIds = getUserIdsForProcessing();
            
            for (String userId : userIds) {
                Transaction tx = txManager.newTransaction();
                try {
                    Map<String, AttributeValue> userKey = new HashMap<>();
                    userKey.put("UserId", new AttributeValue().withS(userId));
                    
                    tx.load(dynamoDBClient, "Users", userKey);
                    
                    // Process user data
                    
                    tx.update(new DynamoDB(dynamoDBClient).getTable("Users"),
                        new Item().withPrimaryKey("UserId", userId),
                        "SET ProcessedFlag = :flag",
                        new HashMap<String, Object>() {{ put(":flag", true); }});
                        
                    tx.commit();
                } catch (Exception e) {
                    tx.rollback();
                }
            }
        } catch (Exception e) {
            // Handle exception
        }
    }

    public void bad_case_13() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        DynamoDBTransactionManager txManager = new DynamoDBTransactionManager(mapper);
        
        try {
            // Conditional transaction
            TransactionWriteRequest writeRequest = new TransactionWriteRequest();
            
            User user = new User();
            user.setUserId("user123");
            user.setCredits(100);
            
            Subscription subscription = new Subscription();
            subscription.setUserId("user123");
            subscription.setPlanId("premium");
            subscription.setStatus("Active");
            
            // Add condition that user must have enough credits
            DynamoDBMapperConfig.Builder configBuilder = new DynamoDBMapperConfig.Builder();
            writeRequest.addPut(user, configBuilder.build());
            writeRequest.addPut(subscription);
            
            txManager.executeTransactionWrite(writeRequest);
        } catch (Exception e) {
            // Handle exception
        }
    }

    public void bad_case_14() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ruleid: java-dynamodb-transaction-library
        TransactionManager txManager = new TransactionManager(dynamoDBClient, "TransactionLockTable");
        Transaction tx = txManager.newTransaction();
        
        try {
            DynamoDB dynamoDB = new DynamoDB(dynamoDBClient);
            
            // Multi-table transaction with conditions
            Map<String, AttributeValue> userKey = new HashMap<>();
            userKey.put("UserId", new AttributeValue().withS("user123"));
            
            tx.load(dynamoDBClient, "Users", userKey);
            
            Map<String, AttributeValue> itemKey = new HashMap<>();
            itemKey.put("ItemId", new AttributeValue().withS("item456"));
            
            tx.load(dynamoDBClient, "Items", itemKey);
            
            // Add purchase record
            tx.put(dynamoDB.getTable("Purchases"), 
                new Item().withPrimaryKey("PurchaseId", "purchase789")
                          .withString("UserId", "user123")
                          .withString("ItemId", "item456")
                          .withString("Status", "Completed"));
                          
            // Update inventory
            tx.update(dynamoDB.getTable("Inventory"),
                new Item().withPrimaryKey("ItemId", "item456"),
                "SET Stock = Stock - :qty",
                new HashMap<String, Object>() {{ put(":qty", 1); }});
                
            tx.commit();
        } catch (Exception e) {
            tx.rollback();
        }
    }

    public void bad_case_15() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(dynamoDBClient);
        
        // ruleid: java-dynamodb-transaction-library
        DynamoDBTransactionManager txManager = new DynamoDBTransactionManager(mapper);
        
        try {
            // Complex transaction with multiple operations and conditions
            TransactionWriteRequest writeRequest = new TransactionWriteRequest();
            
            // Update user profile
            User user = mapper.load(User.class, "user123");
            user.setLastLoginDate(new java.util.Date());
            
            // Create session
            Session session = new Session();
            session.setSessionId("session" + System.currentTimeMillis());
            session.setUserId("user123");
            session.setExpiryTime(System.currentTimeMillis() + 3600000);
            
            // Update login stats
            LoginStats stats = new LoginStats();
            stats.setUserId("user123");
            stats.setLoginCount(user.getLoginCount() + 1);
            
            writeRequest.addUpdate(user);
            writeRequest.addPut(session);
            writeRequest.addPut(stats);
            
            txManager.executeTransactionWrite(writeRequest);
        } catch (Exception e) {
            // Handle exception
        }
    }

    // True Negatives (Safe/Secure Code)

    public void good_case_1() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Add a Put operation
        Map<String, AttributeValue> userItem = new HashMap<>();
        userItem.put("UserId", new AttributeValue().withS("user123"));
        userItem.put("Name", new AttributeValue().withS("John Doe"));
        
        Put userPut = new Put()
            .withTableName("Users")
            .withItem(userItem);
            
        actions.add(new TransactWriteItem().withPut(userPut));
        
        // Add another Put operation
        Map<String, AttributeValue> orderItem = new HashMap<>();
        orderItem.put("OrderId", new AttributeValue().withS("order456"));
        orderItem.put("Status", new AttributeValue().withS("Pending"));
        
        Put orderPut = new Put()
            .withTableName("Orders")
            .withItem(orderItem);
            
        actions.add(new TransactWriteItem().withPut(orderPut));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    public void good_case_2() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Add a Get operation
        Map<String, AttributeValue> userKey = new HashMap<>();
        userKey.put("UserId", new AttributeValue().withS("user123"));
        
        // Add a Delete operation
        Delete deleteAction = new Delete()
            .withTableName("Users")
            .withKey(userKey);
            
        actions.add(new TransactWriteItem().withDelete(deleteAction));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    public void good_case_3() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Add a Put operation for User
        Map<String, AttributeValue> userItem = new HashMap<>();
        userItem.put("UserId", new AttributeValue().withS("user123"));
        userItem.put("Name", new AttributeValue().withS("John Doe"));
        
        Put userPut = new Put()
            .withTableName("Users")
            .withItem(userItem);
            
        actions.add(new TransactWriteItem().withPut(userPut));
        
        // Add a Put operation for Order
        Map<String, AttributeValue> orderItem = new HashMap<>();
        orderItem.put("OrderId", new AttributeValue().withS("order456"));
        orderItem.put("Status", new AttributeValue().withS("Pending"));
        
        Put orderPut = new Put()
            .withTableName("Orders")
            .withItem(orderItem);
            
        actions.add(new TransactWriteItem().withPut(orderPut));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    public void good_case_4() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        List<TransactGetItem> actions = new ArrayList<>();
        
        // Add a Get operation for the first item
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("PK", new AttributeValue().withS("USER#123"));
        
        Get getUser = new Get()
            .withTableName("DataTable")
            .withKey(key1);
            
        actions.add(new TransactGetItem().withGet(getUser));
        
        // Add a Get operation for the second item
        Map<String, AttributeValue> key2 = new HashMap<>();
        key2.put("PK", new AttributeValue().withS("ORDER#456"));
        
        Get getOrder = new Get()
            .withTableName("DataTable")
            .withKey(key2);
            
        actions.add(new TransactGetItem().withGet(getOrder));
        
        // Execute the transaction
        TransactGetItemsRequest request = new TransactGetItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactGetItems(request);
    }

    public void good_case_5() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        List<TransactGetItem> actions = new ArrayList<>();
        
        // Add a Get operation for User
        Map<String, AttributeValue> userKey = new HashMap<>();
        userKey.put("UserId", new AttributeValue().withS("user123"));
        
        Get getUser = new Get()
            .withTableName("Users")
            .withKey(userKey);
            
        actions.add(new TransactGetItem().withGet(getUser));
        
        // Add a Get operation for Order
        Map<String, AttributeValue> orderKey = new HashMap<>();
        orderKey.put("OrderId", new AttributeValue().withS("order456"));
        
        Get getOrder = new Get()
            .withTableName("Orders")
            .withKey(orderKey);
            
        actions.add(new TransactGetItem().withGet(getOrder));
        
        // Execute the transaction
        TransactGetItemsRequest request = new TransactGetItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactGetItems(request);
    }

    public void good_case_6() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        for (int i = 0; i < 10; i++) {
            List<TransactWriteItem> actions = new ArrayList<>();
            
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("ProductId", new AttributeValue().withS("product" + i));
            item.put("Quantity", new AttributeValue().withN("100"));
            
            Put put = new Put()
                .withTableName("Inventory")
                .withItem(item);
                
            actions.add(new TransactWriteItem().withPut(put));
            
            TransactWriteItemsRequest request = new TransactWriteItemsRequest()
                .withTransactItems(actions);
                
            dynamoDBClient.transactWriteItems(request);
        }
    }

    public void good_case_7() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Add product item
        Map<String, AttributeValue> productItem = new HashMap<>();
        productItem.put("ProductId", new AttributeValue().withS("prod123"));
        productItem.put("Stock", new AttributeValue().withN("50"));
        
        Put productPut = new Put()
            .withTableName("Products")
            .withItem(productItem);
            
        actions.add(new TransactWriteItem().withPut(productPut));
        
        // Add inventory item
        Map<String, AttributeValue> inventoryItem = new HashMap<>();
        inventoryItem.put("ProductId", new AttributeValue().withS("prod123"));
        inventoryItem.put("Warehouse", new AttributeValue().withS("warehouse1"));
        inventoryItem.put("Quantity", new AttributeValue().withN("50"));
        
        Put inventoryPut = new Put()
            .withTableName("Inventory")
            .withItem(inventoryItem);
            
        actions.add(new TransactWriteItem().withPut(inventoryPut));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    public void good_case_8() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Update first account (withdraw)
        Map<String, AttributeValue> account1Key = new HashMap<>();
        account1Key.put("AccountId", new AttributeValue().withS("account1"));
        
        Map<String, AttributeValueUpdate> account1Updates = new HashMap<>();
        account1Updates.put("Balance", new AttributeValueUpdate()
            .withAction(AttributeAction.ADD)
            .withValue(new AttributeValue().withN("-100")));
            
        Update updateAccount1 = new Update()
            .withTableName("Accounts")
            .withKey(account1Key)
            .withUpdateExpression("SET Balance = Balance - :amount")
            .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                put(":amount", new AttributeValue().withN("100"));
            }});
            
        actions.add(new TransactWriteItem().withUpdate(updateAccount1));
        
        // Update second account (deposit)
        Map<String, AttributeValue> account2Key = new HashMap<>();
        account2Key.put("AccountId", new AttributeValue().withS("account2"));
        
        Update updateAccount2 = new Update()
            .withTableName("Accounts")
            .withKey(account2Key)
            .withUpdateExpression("SET Balance = Balance + :amount")
            .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                put(":amount", new AttributeValue().withN("100"));
            }});
            
        actions.add(new TransactWriteItem().withUpdate(updateAccount2));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    public void good_case_9() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        if (checkCondition()) {
            List<TransactWriteItem> actions = new ArrayList<>();
            
            // Update user status
            Map<String, AttributeValue> userKey = new HashMap<>();
            userKey.put("UserId", new AttributeValue().withS("user123"));
            
            Update updateUser = new Update()
                .withTableName("Users")
                .withKey(userKey)
                .withUpdateExpression("SET Status = :status")
                .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                    put(":status", new AttributeValue().withS("Active"));
                }});
                
            actions.add(new TransactWriteItem().withUpdate(updateUser));
            
            // Create new order
            Map<String, AttributeValue> orderItem = new HashMap<>();
            orderItem.put("OrderId", new AttributeValue().withS("order789"));
            orderItem.put("UserId", new AttributeValue().withS("user123"));
            
            Put orderPut = new Put()
                .withTableName("Orders")
                .withItem(orderItem);
                
            actions.add(new TransactWriteItem().withPut(orderPut));
            
            // Execute the transaction
            TransactWriteItemsRequest request = new TransactWriteItemsRequest()
                .withTransactItems(actions);
                
            dynamoDBClient.transactWriteItems(request);
        }
    }

    public void good_case_10() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        // Complex transaction with multiple operations
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Create order
        Map<String, AttributeValue> orderItem = new HashMap<>();
        orderItem.put("OrderId", new AttributeValue().withS("order789"));
        orderItem.put("UserId", new AttributeValue().withS("user123"));
        orderItem.put("ProductId", new AttributeValue().withS("prod456"));
        orderItem.put("Quantity", new AttributeValue().withN("2"));
        
        Put orderPut = new Put()
            .withTableName("Orders")
            .withItem(orderItem);
            
        actions.add(new TransactWriteItem().withPut(orderPut));
        
        // Update inventory
        Map<String, AttributeValue> inventoryKey = new HashMap<>();
        inventoryKey.put("ProductId", new AttributeValue().withS("prod456"));
        
        Update updateInventory = new Update()
            .withTableName("Inventory")
            .withKey(inventoryKey)
            .withUpdateExpression("SET Stock = Stock - :qty")
            .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                put(":qty", new AttributeValue().withN("2"));
            }});
            
        actions.add(new TransactWriteItem().withUpdate(updateInventory));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    public void good_case_11() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        String userId = "user123";
        String orderId = "order456";
        
        List<TransactGetItem> actions = new ArrayList<>();
        
        // Get user
        Map<String, AttributeValue> userKey = new HashMap<>();
        userKey.put("UserId", new AttributeValue().withS(userId));
        
        Get getUser = new Get()
            .withTableName("Users")
            .withKey(userKey);
            
        actions.add(new TransactGetItem().withGet(getUser));
        
        // Get order
        Map<String, AttributeValue> orderKey = new HashMap<>();
        orderKey.put("OrderId", new AttributeValue().withS(orderId));
        
        Get getOrder = new Get()
            .withTableName("Orders")
            .withKey(orderKey);
            
        actions.add(new TransactGetItem().withGet(getOrder));
        
        // Execute the transaction
        TransactGetItemsRequest request = new TransactGetItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactGetItems(request);
    }

    public void good_case_12() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        // Batch processing with transactions
        List<String> userIds = getUserIdsForProcessing();
        
        for (String userId : userIds) {
            List<TransactWriteItem> actions = new ArrayList<>();
            
            Map<String, AttributeValue> userKey = new HashMap<>();
            userKey.put("UserId", new AttributeValue().withS(userId));
            
            Update updateUser = new Update()
                .withTableName("Users")
                .withKey(userKey)
                .withUpdateExpression("SET ProcessedFlag = :flag")
                .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                    put(":flag", new AttributeValue().withBOOL(true));
                }});
                
            actions.add(new TransactWriteItem().withUpdate(updateUser));
            
            // Execute the transaction
            TransactWriteItemsRequest request = new TransactWriteItemsRequest()
                .withTransactItems(actions);
                
            dynamoDBClient.transactWriteItems(request);
        }
    }

    public void good_case_13() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        // Conditional transaction
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Update user credits
        Map<String, AttributeValue> userItem = new HashMap<>();
        userItem.put("UserId", new AttributeValue().withS("user123"));
        userItem.put("Credits", new AttributeValue().withN("100"));
        
        Put userPut = new Put()
            .withTableName("Users")
            .withItem(userItem)
            .withConditionExpression("Credits >= :minCredits")
            .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                put(":minCredits", new AttributeValue().withN("50"));
            }});
            
        actions.add(new TransactWriteItem().withPut(userPut));
        
        // Create subscription
        Map<String, AttributeValue> subscriptionItem = new HashMap<>();
        subscriptionItem.put("UserId", new AttributeValue().withS("user123"));
        subscriptionItem.put("PlanId", new AttributeValue().withS("premium"));
        subscriptionItem.put("Status", new AttributeValue().withS("Active"));
        
        Put subscriptionPut = new Put()
            .withTableName("Subscriptions")
            .withItem(subscriptionItem);
            
        actions.add(new TransactWriteItem().withPut(subscriptionPut));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    public void good_case_14() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        // Multi-table transaction with conditions
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Add purchase record
        Map<String, AttributeValue> purchaseItem = new HashMap<>();
        purchaseItem.put("PurchaseId", new AttributeValue().withS("purchase789"));
        purchaseItem.put("UserId", new AttributeValue().withS("user123"));
        purchaseItem.put("ItemId", new AttributeValue().withS("item456"));
        purchaseItem.put("Status", new AttributeValue().withS("Completed"));
        
        Put purchasePut = new Put()
            .withTableName("Purchases")
            .withItem(purchaseItem);
            
        actions.add(new TransactWriteItem().withPut(purchasePut));
        
        // Update inventory
        Map<String, AttributeValue> inventoryKey = new HashMap<>();
        inventoryKey.put("ItemId", new AttributeValue().withS("item456"));
        
        Update updateInventory = new Update()
            .withTableName("Inventory")
            .withKey(inventoryKey)
            .withUpdateExpression("SET Stock = Stock - :qty")
            .withConditionExpression("Stock >= :qty")
            .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                put(":qty", new AttributeValue().withN("1"));
            }});
            
        actions.add(new TransactWriteItem().withUpdate(updateInventory));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    public void good_case_15() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ok: java-dynamodb-transaction-library
        // Complex transaction with multiple operations and conditions
        List<TransactWriteItem> actions = new ArrayList<>();
        
        // Update user profile
        Map<String, AttributeValue> userKey = new HashMap<>();
        userKey.put("UserId", new AttributeValue().withS("user123"));
        
        Update updateUser = new Update()
            .withTableName("Users")
            .withKey(userKey)
            .withUpdateExpression("SET LastLoginDate = :date, LoginCount = LoginCount + :inc")
            .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                put(":date", new AttributeValue().withS(new java.util.Date().toString()));
                put(":inc", new AttributeValue().withN("1"));
            }});
            
        actions.add(new TransactWriteItem().withUpdate(updateUser));
        
        // Create session
        Map<String, AttributeValue> sessionItem = new HashMap<>();
        sessionItem.put("SessionId", new AttributeValue().withS("session" + System.currentTimeMillis()));
        sessionItem.put("UserId", new AttributeValue().withS("user123"));
        sessionItem.put("ExpiryTime", new AttributeValue().withN(String.valueOf(System.currentTimeMillis() + 3600000)));
        
        Put sessionPut = new Put()
            .withTableName("Sessions")
            .withItem(sessionItem);
            
        actions.add(new TransactWriteItem().withPut(sessionPut));
        
        // Update login stats
        Map<String, AttributeValue> statsKey = new HashMap<>();
        statsKey.put("UserId", new AttributeValue().withS("user123"));
        
        Update updateStats = new Update()
            .withTableName("LoginStats")
            .withKey(statsKey)
            .withUpdateExpression("SET LoginCount = LoginCount + :inc")
            .withExpressionAttributeValues(new HashMap<String, AttributeValue>() {{
                put(":inc", new AttributeValue().withN("1"));
            }});
            
        actions.add(new TransactWriteItem().withUpdate(updateStats));
        
        // Execute the transaction
        TransactWriteItemsRequest request = new TransactWriteItemsRequest()
            .withTransactItems(actions);
            
        dynamoDBClient.transactWriteItems(request);
    }

    // Helper methods
    private Map<String, AttributeValue> createKey(String keyName, String keyValue) {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put(keyName, new AttributeValue().withS(keyValue));
        return key;
    }

    private boolean checkCondition() {
        return true; // Simplified for example
    }

    private List<String> getUserIdsForProcessing() {
        List<String> userIds = new ArrayList<>();
        userIds.add("user1");
        userIds.add("user2");
        userIds.add("user3");
        return userIds;
    }

    // Sample model classes
    class User {
        private String userId;
        private String name;
        private int loginCount;
        private java.util.Date lastLoginDate;
        private int credits;
        private String status;

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public int getLoginCount() { return loginCount; }
        public void setLoginCount(int loginCount) { this.loginCount = loginCount; }
        public java.util.Date getLastLoginDate() { return lastLoginDate; }
        public void setLastLoginDate(java.util.Date lastLoginDate) { this.lastLoginDate = lastLoginDate; }
        public int getCredits() { return credits; }
        public void setCredits(int credits) { this.credits = credits; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }

    class Order {
        private String orderId;
        private String userId;
        private String status;

        public String getOrderId() { return orderId; }
        public void setOrderId(String orderId) { this.orderId = orderId; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }

    class Product {
        private String productId;
        private int stock;

        public String getProductId() { return productId; }
        public void setProductId(String productId) { this.productId = productId; }
        public int getStock() { return stock; }
        public void setStock(int stock) { this.stock = stock; }
    }

    class Inventory {
        private String productId;
        private String warehouse;
        private int quantity;

        public String getProductId() { return productId; }
        public void setProductId(String productId) { this.productId = productId; }
        public String getWarehouse() { return warehouse; }
        public void setWarehouse(String warehouse) { this.warehouse = warehouse; }
        public int getQuantity() { return quantity; }
        public void setQuantity(int quantity) { this.quantity = quantity; }
    }

    class Session {
        private String sessionId;
        private String userId;
        private long expiryTime;

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public long getExpiryTime() { return expiryTime; }
        public void setExpiryTime(long expiryTime) { this.expiryTime = expiryTime; }
    }

    class Subscription {
        private String userId;
        private String planId;
        private String status;

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getPlanId() { return planId; }
        public void setPlanId(String planId) { this.planId = planId; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }

    class LoginStats {
        private String userId;
        private int loginCount;

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public int getLoginCount() { return loginCount; }
        public void setLoginCount(int loginCount) { this.loginCount = loginCount; }
    }
}
// {/fact}