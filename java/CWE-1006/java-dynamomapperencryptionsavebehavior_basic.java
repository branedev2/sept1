package com.example.dynamodb;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.TransactionWriteRequest;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBEncryptionClient;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.util.HashMap;
import java.util.Map;

public class DynamoDBEncryptionExamples {

    @DynamoDBTable(tableName = "User")
    public static class User {
        private String id;
        private String name;
        private String email;
        private String password;

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
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    // True Positives (Vulnerable/Insecure Code)

// {fact rule=batches-preferred-over-loops@v1.0 defects=1}
    public void bad_case_1() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.save(user);
    }

    public void bad_case_2() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user1 = new User();
        user1.setId("123");
        user1.setName("John Doe");
        user1.setEmail("john@example.com");
        user1.setPassword("secret123");
        
        User user2 = new User();
        user2.setId("456");
        user2.setName("Jane Doe");
        user2.setEmail("jane@example.com");
        user2.setPassword("password456");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        transactionWriteRequest.addPut(user1);
        transactionWriteRequest.addPut(user2);
        mapper.transactionWrite(transactionWriteRequest);
    }

    public void bad_case_3() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapperConfig config = DynamoDBMapperConfig.builder()
            .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.UPDATE_SKIP_NULL_ATTRIBUTES)
            .build();
        DynamoDBMapper mapper = new DynamoDBMapper(client, config);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.save(user);
    }

    public void bad_case_4() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.save(user, DynamoDBMapperConfig.SaveBehavior.CLOBBER.config());
    }

    public void bad_case_5() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("id", new AttributeValue().withS("123"));
        item.put("name", new AttributeValue().withS("John Doe"));
        item.put("password", new AttributeValue().withS("secret123"));
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.marshallIntoObject(User.class, item);
    }

    public void bad_case_6() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        transactionWriteRequest.addUpdate(user);
        mapper.transactionWrite(transactionWriteRequest);
    }

    public void bad_case_7() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapperConfig config = DynamoDBMapperConfig.builder()
            .withConsistentReads(DynamoDBMapperConfig.ConsistentReads.CONSISTENT)
            .build();
        DynamoDBMapper mapper = new DynamoDBMapper(client, config);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.save(user);
    }

    public void bad_case_8() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user1 = new User();
        user1.setId("123");
        user1.setName("John Doe");
        user1.setPassword("secret123");
        
        User user2 = new User();
        user2.setId("456");
        user2.setName("Jane Doe");
        user2.setPassword("password456");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.batchSave(user1, user2);
    }

    public void bad_case_9() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.save(user, DynamoDBMapperConfig.builder()
            .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.UPDATE)
            .build());
    }

    public void bad_case_10() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = mapper.load(User.class, "123");
        user.setPassword("newPassword123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.save(user);
    }

    public void bad_case_11() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        transactionWriteRequest.addDelete(user);
        transactionWriteRequest.addPut(user);
        mapper.transactionWrite(transactionWriteRequest);
    }

    public void bad_case_12() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.save(user, DynamoDBMapperConfig.DEFAULT);
    }

    public void bad_case_13() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapperConfig config = new DynamoDBMapperConfig.Builder()
            .withTableNameOverride(DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement("UserTable"))
            .build();
        DynamoDBMapper mapper = new DynamoDBMapper(client, config);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        mapper.save(user);
    }

    public void bad_case_14() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        // ruleid: java-dynamomapperencryptionsavebehavior
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        transactionWriteRequest.addPut(user);
        mapper.transactionWrite(transactionWriteRequest, DynamoDBMapperConfig.DEFAULT);
    }

    public void bad_case_15() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        User user = mapper.load(User.class, "123");
        if (user != null) {
            user.setPassword("updatedPassword");
            // ruleid: java-dynamomapperencryptionsavebehavior
            mapper.save(user);
        }
    }

    // True Negatives (Safe/Secure Code)

    public void good_case_1() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBMapper mapper = new DynamoDBMapper(new DynamoDBEncryptionClient(client, encryptor, encryptionContext));
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        mapper.save(user);
    }

    public void good_case_2() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBMapper mapper = new DynamoDBMapper(new DynamoDBEncryptionClient(client, encryptor, encryptionContext));
        
        User user1 = new User();
        user1.setId("123");
        user1.setName("John Doe");
        user1.setEmail("john@example.com");
        user1.setPassword("secret123");
        
        User user2 = new User();
        user2.setId("456");
        user2.setName("Jane Doe");
        user2.setEmail("jane@example.com");
        user2.setPassword("password456");
        
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        transactionWriteRequest.addPut(user1);
        transactionWriteRequest.addPut(user2);
        mapper.transactionWrite(transactionWriteRequest);
    }

    public void good_case_3() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        
        DynamoDBMapperConfig config = DynamoDBMapperConfig.builder()
            .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.UPDATE_SKIP_NULL_ATTRIBUTES)
            .build();
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient, config);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        mapper.save(user);
    }

    public void good_case_4() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBMapper mapper = new DynamoDBMapper(new DynamoDBEncryptionClient(client, encryptor, encryptionContext));
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        mapper.save(user, DynamoDBMapperConfig.SaveBehavior.CLOBBER.config());
    }

    public void good_case_5() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("id", new AttributeValue().withS("123"));
        item.put("name", new AttributeValue().withS("John Doe"));
        item.put("password", new AttributeValue().withS("secret123"));
        
        mapper.marshallIntoObject(User.class, item);
    }

    public void good_case_6() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        transactionWriteRequest.addUpdate(user);
        mapper.transactionWrite(transactionWriteRequest);
    }

    public void good_case_7() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        
        DynamoDBMapperConfig config = DynamoDBMapperConfig.builder()
            .withConsistentReads(DynamoDBMapperConfig.ConsistentReads.CONSISTENT)
            .build();
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient, config);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        mapper.save(user);
    }

    public void good_case_8() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        User user1 = new User();
        user1.setId("123");
        user1.setName("John Doe");
        user1.setPassword("secret123");
        
        User user2 = new User();
        user2.setId("456");
        user2.setName("Jane Doe");
        user2.setPassword("password456");
        
        mapper.batchSave(user1, user2);
    }

    public void good_case_9() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        mapper.save(user, DynamoDBMapperConfig.builder()
            .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.UPDATE)
            .build());
    }

    public void good_case_10() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        User user = mapper.load(User.class, "123");
        user.setPassword("newPassword123");
        
        mapper.save(user);
    }

    public void good_case_11() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        transactionWriteRequest.addDelete(user);
        transactionWriteRequest.addPut(user);
        mapper.transactionWrite(transactionWriteRequest);
    }

    public void good_case_12() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption with custom context
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("application", "user-management");
        encryptionContext.put("environment", "production");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        mapper.save(user, DynamoDBMapperConfig.DEFAULT);
    }

    public void good_case_13() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        
        DynamoDBMapperConfig config = new DynamoDBMapperConfig.Builder()
            .withTableNameOverride(DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement("UserTable"))
            .build();
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient, config);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        mapper.save(user);
    }

    public void good_case_14() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        User user = new User();
        user.setId("123");
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("secret123");
        
        TransactionWriteRequest transactionWriteRequest = new TransactionWriteRequest();
        transactionWriteRequest.addPut(user);
        mapper.transactionWrite(transactionWriteRequest, DynamoDBMapperConfig.DEFAULT);
    }

    public void good_case_15() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Set up encryption
        DirectKmsMaterialProvider provider = new DirectKmsMaterialProvider(kmsClient, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(provider);
        
        // ok: java-dynamomapperencryptionsavebehavior
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("purpose", "user data");
        DynamoDBEncryptionClient encryptionClient = new DynamoDBEncryptionClient(client, encryptor, encryptionContext);
        DynamoDBMapper mapper = new DynamoDBMapper(encryptionClient);
        
        User user = mapper.load(User.class, "123");
        if (user != null) {
            user.setPassword("updatedPassword");
            mapper.save(user);
        }
    }
}
// {/fact}