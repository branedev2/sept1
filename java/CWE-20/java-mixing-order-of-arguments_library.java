import java.util.*;
import java.io.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.auth.*;
import com.stripe.Stripe;
import com.stripe.model.Customer;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.sendgrid.*;
import com.mongodb.*;
import redis.clients.jedis.*;
import com.google.firebase.*;
import com.google.firebase.auth.*;
import com.braintreegateway.*;
import okhttp3.*;
import org.elasticsearch.client.*;
import software.amazon.awssdk.services.dynamodb.*;
import com.azure.storage.blob.*;
import com.paypal.api.payments.*;
import com.paypal.base.rest.*;
import com.google.cloud.storage.*;
import io.jsonwebtoken.*;
import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.*;
import org.apache.kafka.clients.producer.*;
import com.rabbitmq.client.*;
import com.slack.api.*;
import com.slack.api.methods.request.chat.*;
import com.slack.api.methods.response.chat.*;
import com.mailchimp.marketing.api.ApiClient;
import com.mailchimp.marketing.api.ApiException;
import com.hubspot.api.client.*;

// Security Issue: Mixing order of arguments when passing to methods, which can lead to logical errors and security issues

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // AWS S3 SDK - Mixing bucket name and key parameters
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = request.getParameter("bucket");
    String key = request.getParameter("key");
    String versionId = request.getParameter("version");
    
    // ruleid: java-mixing-order-of-arguments
    s3Client.getObject(key, bucketName, versionId); // Wrong order: should be (bucketName, key, versionId)
}

public void bad_case_2(HttpServletRequest request) {
    // Stripe API - Mixing customer ID and payment method parameters
    Stripe.apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
    String customerId = request.getParameter("customerId");
    String paymentMethodId = request.getParameter("paymentMethodId");
    Map<String, Object> params = new HashMap<>();
    
    // ruleid: java-mixing-order-of-arguments
    params.put("payment_method", customerId);
    params.put("customer", paymentMethodId); // Wrong order: customer and payment_method are swapped
}

public void bad_case_3(HttpServletRequest request) {
    // Twilio API - Mixing from and to phone numbers
    Twilio.init("AC_REDACTED_TWILIO_ID_SID", "AUTH_TOKEN");
    String fromNumber = request.getParameter("from");
    String toNumber = request.getParameter("to");
    String messageBody = request.getParameter("message");
    
    // ruleid: java-mixing-order-of-arguments
    Message message = Message.creator(fromNumber, toNumber, messageBody).create(); // Wrong order: to and from are swapped
}

public void bad_case_4(HttpServletRequest request) {
    // SendGrid API - Mixing sender and recipient email addresses
    String fromEmail = request.getParameter("from");
    String toEmail = request.getParameter("to");
    String subject = request.getParameter("subject");
    String content = request.getParameter("content");
    
    Email from = new Email(toEmail); // Should be fromEmail
    Email to = new Email(fromEmail); // Should be toEmail
    Content emailContent = new Content("text/plain", content);
    
    // ruleid: java-mixing-order-of-arguments
    Mail mail = new Mail(from, subject, to, emailContent); // Wrong order: from and to are using wrong variables
}

public void bad_case_5(HttpServletRequest request) {
    // MongoDB - Mixing database and collection names
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    String dbName = request.getParameter("db");
    String collectionName = request.getParameter("collection");
    
    // ruleid: java-mixing-order-of-arguments
    mongoClient.getDatabase(collectionName).getCollection(dbName); // Wrong order: db and collection are swapped
}

public void bad_case_6(HttpServletRequest request) {
    // Redis - Mixing key and value parameters
    Jedis jedis = new Jedis("localhost");
    String key = request.getParameter("key");
    String value = request.getParameter("value");
    int expireTime = Integer.parseInt(request.getParameter("expire"));
    
    // ruleid: java-mixing-order-of-arguments
    jedis.setex(value, expireTime, key); // Wrong order: should be (key, expireTime, value)
}

public void bad_case_7(HttpServletRequest request) {
    // Firebase Authentication - Mixing email and password parameters
    try {
        FirebaseAuth auth = FirebaseAuth.getInstance();
        String email = request.getParameter("email");
        String password = request.getParameter("password");
        
        // ruleid: java-mixing-order-of-arguments
        auth.createUserWithEmailAndPassword(password, email); // Wrong order: should be (email, password)
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    // Braintree Payment Gateway - Mixing amount and currency parameters
    BraintreeGateway gateway = new BraintreeGateway("environment", "merchantId", "publicKey", "privateKey");
    String amount = request.getParameter("amount");
    String currency = request.getParameter("currency");
    String customerId = request.getParameter("customerId");
    
    TransactionRequest txRequest = new TransactionRequest()
        .customerId(customerId);
    
    // ruleid: java-mixing-order-of-arguments
    txRequest.amount(new java.math.BigDecimal(currency))
             .currencyIsoCode(amount); // Wrong order: amount and currency are swapped
}

public void bad_case_9(HttpServletRequest request) {
    // OkHttp - Mixing URL and request body parameters
    OkHttpClient client = new OkHttpClient();
    String url = request.getParameter("url");
    String jsonBody = request.getParameter("jsonBody");
    
    MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    
    // ruleid: java-mixing-order-of-arguments
    RequestBody body = RequestBody.create(jsonBody, JSON); // Wrong order: should be (JSON, jsonBody)
}

public void bad_case_10(HttpServletRequest request) {
    // Elasticsearch - Mixing index and document ID parameters
    RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
    String indexName = request.getParameter("index");
    String docId = request.getParameter("docId");
    
    try {
        // ruleid: java-mixing-order-of-arguments
        client.get(new org.elasticsearch.action.get.GetRequest(docId, indexName), RequestOptions.DEFAULT); // Wrong order: should be (indexName, docId)
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    // AWS DynamoDB - Mixing table name and key parameters
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    String tableName = request.getParameter("table");
    String partitionKey = request.getParameter("partitionKey");
    String sortKey = request.getParameter("sortKey");
    
    Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> key = new HashMap<>();
    key.put("pk", software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s(partitionKey).build());
    key.put("sk", software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s(sortKey).build());
    
    // ruleid: java-mixing-order-of-arguments
    software.amazon.awssdk.services.dynamodb.model.GetItemRequest getItemRequest = 
        software.amazon.awssdk.services.dynamodb.model.GetItemRequest.builder()
            .key(tableName)
            .tableName(key) // Wrong order: tableName and key are swapped
            .build();
}

public void bad_case_12(HttpServletRequest request) {
    // Azure Blob Storage - Mixing container and blob name parameters
    String connectionString = "DefaultEndpointsProtocol=https;AccountName=account;AccountKey=key;EndpointSuffix=core.windows.net";
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString(connectionString).buildClient();
    
    String containerName = request.getParameter("container");
    String blobName = request.getParameter("blob");
    
    // ruleid: java-mixing-order-of-arguments
    BlobClient blobClient = blobServiceClient.getBlobContainerClient(blobName).getBlobClient(containerName); // Wrong order: container and blob are swapped
}

public void bad_case_13(HttpServletRequest request) {
    // PayPal SDK - Mixing payment amount and currency parameters
    try {
        APIContext apiContext = new APIContext("clientId", "secret", "mode");
        String amount = request.getParameter("amount");
        String currency = request.getParameter("currency");
        
        Amount paymentAmount = new Amount();
        // ruleid: java-mixing-order-of-arguments
        paymentAmount.setCurrency(amount);
        paymentAmount.setTotal(currency); // Wrong order: amount and currency are swapped
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    // JWT Token Creation - Mixing subject and issuer parameters
    String subject = request.getParameter("subject");
    String issuer = request.getParameter("issuer");
    
    // ruleid: java-mixing-order-of-arguments
    String token = JWT.create()
        .withSubject(issuer)
        .withIssuer(subject) // Wrong order: subject and issuer are swapped
        .sign(Algorithm.HMAC_REDACTED_TWILIO_ID("secret"));
}

public void bad_case_15(HttpServletRequest request) {
    // Kafka Producer - Mixing topic and message parameters
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    
    Producer<String, String> producer = new KafkaProducer<>(props);
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    
    // ruleid: java-mixing-order-of-arguments
    producer.send(new ProducerRecord<>(message, topic)); // Wrong order: should be (topic, message)
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // AWS S3 SDK - Correct order of bucket name and key parameters
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = request.getParameter("bucket");
    String key = request.getParameter("key");
    String versionId = request.getParameter("version");
    
    // ok: java-mixing-order-of-arguments
    s3Client.getObject(bucketName, key, versionId); // Correct order: (bucketName, key, versionId)
}

public void good_case_2(HttpServletRequest request) {
    // Stripe API - Correct order of customer ID and payment method parameters
    Stripe.apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
    String customerId = request.getParameter("customerId");
    String paymentMethodId = request.getParameter("paymentMethodId");
    Map<String, Object> params = new HashMap<>();
    
    // ok: java-mixing-order-of-arguments
    params.put("customer", customerId);
    params.put("payment_method", paymentMethodId); // Correct order
}

public void good_case_3(HttpServletRequest request) {
    // Twilio API - Correct order of from and to phone numbers
    Twilio.init("AC_REDACTED_TWILIO_ID_SID", "AUTH_TOKEN");
    String fromNumber = request.getParameter("from");
    String toNumber = request.getParameter("to");
    String messageBody = request.getParameter("message");
    
    // ok: java-mixing-order-of-arguments
    Message message = Message.creator(toNumber, fromNumber, messageBody).create(); // Correct order: (to, from, body)
}

public void good_case_4(HttpServletRequest request) {
    // SendGrid API - Correct order of sender and recipient email addresses
    String fromEmail = request.getParameter("from");
    String toEmail = request.getParameter("to");
    String subject = request.getParameter("subject");
    String content = request.getParameter("content");
    
    Email from = new Email(fromEmail);
    Email to = new Email(toEmail);
    Content emailContent = new Content("text/plain", content);
    
    // ok: java-mixing-order-of-arguments
    Mail mail = new Mail(from, subject, to, emailContent); // Correct order with proper variables
}

public void good_case_5(HttpServletRequest request) {
    // MongoDB - Correct order of database and collection names
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    String dbName = request.getParameter("db");
    String collectionName = request.getParameter("collection");
    
    // ok: java-mixing-order-of-arguments
    mongoClient.getDatabase(dbName).getCollection(collectionName); // Correct order
}

public void good_case_6(HttpServletRequest request) {
    // Redis - Correct order of key and value parameters
    Jedis jedis = new Jedis("localhost");
    String key = request.getParameter("key");
    String value = request.getParameter("value");
    int expireTime = Integer.parseInt(request.getParameter("expire"));
    
    // ok: java-mixing-order-of-arguments
    jedis.setex(key, expireTime, value); // Correct order: (key, expireTime, value)
}

public void good_case_7(HttpServletRequest request) {
    // Firebase Authentication - Correct order of email and password parameters
    try {
        FirebaseAuth auth = FirebaseAuth.getInstance();
        String email = request.getParameter("email");
        String password = request.getParameter("password");
        
        // ok: java-mixing-order-of-arguments
        auth.createUserWithEmailAndPassword(email, password); // Correct order: (email, password)
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // Braintree Payment Gateway - Correct order of amount and currency parameters
    BraintreeGateway gateway = new BraintreeGateway("environment", "merchantId", "publicKey", "privateKey");
    String amount = request.getParameter("amount");
    String currency = request.getParameter("currency");
    String customerId = request.getParameter("customerId");
    
    TransactionRequest txRequest = new TransactionRequest()
        .customerId(customerId);
    
    // ok: java-mixing-order-of-arguments
    txRequest.amount(new java.math.BigDecimal(amount))
             .currencyIsoCode(currency); // Correct order
}

public void good_case_9(HttpServletRequest request) {
    // OkHttp - Correct order of URL and request body parameters
    OkHttpClient client = new OkHttpClient();
    String url = request.getParameter("url");
    String jsonBody = request.getParameter("jsonBody");
    
    MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    
    // ok: java-mixing-order-of-arguments
    RequestBody body = RequestBody.create(JSON, jsonBody); // Correct order: (MediaType, content)
}

public void good_case_10(HttpServletRequest request) {
    // Elasticsearch - Correct order of index and document ID parameters
    RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
    String indexName = request.getParameter("index");
    String docId = request.getParameter("docId");
    
    try {
        // ok: java-mixing-order-of-arguments
        client.get(new org.elasticsearch.action.get.GetRequest(indexName, docId), RequestOptions.DEFAULT); // Correct order: (indexName, docId)
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    // AWS DynamoDB - Correct order of table name and key parameters
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    String tableName = request.getParameter("table");
    String partitionKey = request.getParameter("partitionKey");
    String sortKey = request.getParameter("sortKey");
    
    Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> key = new HashMap<>();
    key.put("pk", software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s(partitionKey).build());
    key.put("sk", software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s(sortKey).build());
    
    // ok: java-mixing-order-of-arguments
    software.amazon.awssdk.services.dynamodb.model.GetItemRequest getItemRequest = 
        software.amazon.awssdk.services.dynamodb.model.GetItemRequest.builder()
            .tableName(tableName)
            .key(key) // Correct order
            .build();
}

public void good_case_12(HttpServletRequest request) {
    // Azure Blob Storage - Correct order of container and blob name parameters
    String connectionString = "DefaultEndpointsProtocol=https;AccountName=account;AccountKey=key;EndpointSuffix=core.windows.net";
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString(connectionString).buildClient();
    
    String containerName = request.getParameter("container");
    String blobName = request.getParameter("blob");
    
    // ok: java-mixing-order-of-arguments
    BlobClient blobClient = blobServiceClient.getBlobContainerClient(containerName).getBlobClient(blobName); // Correct order
}

public void good_case_13(HttpServletRequest request) {
    // PayPal SDK - Correct order of payment amount and currency parameters
    try {
        APIContext apiContext = new APIContext("clientId", "secret", "mode");
        String amount = request.getParameter("amount");
        String currency = request.getParameter("currency");
        
        Amount paymentAmount = new Amount();
        // ok: java-mixing-order-of-arguments
        paymentAmount.setCurrency(currency);
        paymentAmount.setTotal(amount); // Correct order
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    // JWT Token Creation - Correct order of subject and issuer parameters
    String subject = request.getParameter("subject");
    String issuer = request.getParameter("issuer");
    
    // ok: java-mixing-order-of-arguments
    String token = JWT.create()
        .withSubject(subject)
        .withIssuer(issuer) // Correct order
        .sign(Algorithm.HMAC_REDACTED_TWILIO_ID("secret"));
}

public void good_case_15(HttpServletRequest request) {
    // Kafka Producer - Correct order of topic and message parameters
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    
    Producer<String, String> producer = new KafkaProducer<>(props);
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    
    // ok: java-mixing-order-of-arguments
    producer.send(new ProducerRecord<>(topic, message)); // Correct order: (topic, message)
}