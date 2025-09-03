import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.SerializationUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import com.google.gson.Gson;
import org.yaml.snakeyaml.Yaml;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestTemplate;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.HttpClient;
import redis.clients.jedis.Jedis;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import javax.jms.*;
import org.apache.activemq.ActiveMQConnectionFactory;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;

// Security Issue: Deserialization of untrusted data can lead to denial of service attacks or remote code execution

// True Positive Examples (Vulnerable/Insecure Code)

public class DeserializationVulnerabilities {

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Vulnerable implementation using Java standard ObjectInputStream with HTTP input
        try {
            InputStream inputStream = request.getInputStream();
            // ruleid: java-untrusted-load
            ObjectInputStream ois = new ObjectInputStream(inputStream);
            Object obj = ois.readObject(); // Deserializing untrusted data directly from HTTP request
            ois.close();
            
            response.getWriter().write("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request) throws Exception {
        // Vulnerable implementation using Apache Commons SerializationUtils with HTTP input
        byte[] serializedData = IOUtils.toByteArray(request.getInputStream());
        
        // ruleid: java-untrusted-load
        Object deserializedObject = SerializationUtils.deserialize(serializedData);
        System.out.println("Deserialized object: " + deserializedObject);
    }

    @RestController
    public static class Bad_case_3 {
        // Vulnerable implementation using XStream with HTTP input
        @PostMapping("/xstream-deserialize")
        public String deserializeXml(@RequestBody String xml) {
            XStream xstream = new XStream();
            // ruleid: java-untrusted-load
            Object obj = xstream.fromXML(xml); // Deserializing untrusted XML from HTTP request
            return "Deserialized: " + obj.toString();
        }
    }

    public void bad_case_4(HttpServletRequest request) throws Exception {
        // Vulnerable implementation using JMS ObjectMessage with HTTP-sourced data
        String url = "tcp://localhost:61616";
        ConnectionFactory factory = new ActiveMQConnectionFactory(url);
        Connection connection = factory.createConnection();
        Session session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
        
        // Get serialized data from HTTP request
        byte[] serializedData = IOUtils.toByteArray(request.getInputStream());
        
        // Store HTTP data in JMS message
        Queue queue = session.createQueue("deserializationQueue");
        MessageProducer producer = session.createProducer(queue);
        BytesMessage message = session.createBytesMessage();
        message.writeBytes(serializedData);
        producer.send(message);
        
        // Consumer that deserializes the untrusted data
        MessageConsumer consumer = session.createConsumer(queue);
        connection.start();
        BytesMessage receivedMessage = (BytesMessage) consumer.receive();
        byte[] receivedData = new byte[(int) receivedMessage.getBodyLength()];
        receivedMessage.readBytes(receivedData);
        
        // ruleid: java-untrusted-load
        Object deserializedObject = new ObjectInputStream(new ByteArrayInputStream(receivedData)).readObject();
        System.out.println("Processed: " + deserializedObject);
        
        connection.close();
    }

    public void bad_case_5(HttpServletRequest request) throws Exception {
        // Vulnerable implementation using Redis with HTTP-sourced data
        Jedis jedis = new Jedis("localhost");
        
        // Get serialized data from HTTP request
        byte[] serializedData = IOUtils.toByteArray(request.getInputStream());
        
        // Store HTTP data in Redis
        jedis.set("cached_object".getBytes(), serializedData);
        
        // Later retrieve and deserialize
        byte[] retrievedData = jedis.get("cached_object".getBytes());
        
        // ruleid: java-untrusted-load
        Object deserializedObject = new ObjectInputStream(new ByteArrayInputStream(retrievedData)).readObject();
        System.out.println("Retrieved object: " + deserializedObject);
        
        jedis.close();
    }

    public void bad_case_6(HttpServletRequest request) throws Exception {
        // Vulnerable implementation using Hazelcast distributed map with HTTP-sourced data
        HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance();
        IMap<String, byte[]> distributedMap = hazelcastInstance.getMap("serializedObjects");
        
        // Get serialized data from HTTP request
        byte[] serializedData = IOUtils.toByteArray(request.getInputStream());
        
        // Store HTTP data in Hazelcast
        distributedMap.put("user_object", serializedData);
        
        // Later retrieve and deserialize
        byte[] retrievedData = distributedMap.get("user_object");
        
        // ruleid: java-untrusted-load
        Object deserializedObject = new ObjectInputStream(new ByteArrayInputStream(retrievedData)).readObject();
        System.out.println("Retrieved distributed object: " + deserializedObject);
        
        hazelcastInstance.shutdown();
    }

    public void bad_case_7() throws Exception {
        // Vulnerable implementation using AWS S3 with HTTP-sourced data via OkHttp
        OkHttpClient client = new OkHttpClient();
        Request httpRequest = new Request.Builder()
            .url("http://example.com/serialized-data")
            .build();
        
        Response response = client.newCall(httpRequest).execute();
        byte[] serializedData = response.body().bytes();
        
        // Store HTTP data in S3
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(serializedData);
        s3Client.putObject("my-bucket", "serialized-object", inputStream, null);
        
        // Later retrieve and deserialize
        S3Object s3Object = s3Client.getObject("my-bucket", "serialized-object");
        S3ObjectInputStream s3InputStream = s3Object.getObjectContent();
        
        // ruleid: java-untrusted-load
        Object deserializedObject = new ObjectInputStream(s3InputStream).readObject();
        System.out.println("Retrieved S3 object: " + deserializedObject);
    }

    public void bad_case_8() throws Exception {
        // Vulnerable implementation using Kafka with HTTP-sourced data via RestTemplate
        RestTemplate restTemplate = new RestTemplate();
        byte[] serializedData = restTemplate.getForObject("http://example.com/serialized-data", byte[].class);
        
        // Configure Kafka producer
        Properties producerProps = new Properties();
        producerProps.put("bootstrap.servers", "localhost:9092");
        producerProps.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producerProps.put("value.serializer", "org.apache.kafka.common.serialization.ByteArraySerializer");
        
        // Send HTTP data to Kafka
        KafkaProducer<String, byte[]> producer = new KafkaProducer<>(producerProps);
        ProducerRecord<String, byte[]> record = new ProducerRecord<>("serialized-objects", "key1", serializedData);
        producer.send(record);
        producer.close();
        
        // Configure Kafka consumer
        Properties consumerProps = new Properties();
        consumerProps.put("bootstrap.servers", "localhost:9092");
        consumerProps.put("group.id", "deserialization-group");
        consumerProps.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        consumerProps.put("value.deserializer", "org.apache.kafka.common.serialization.ByteArrayDeserializer");
        
        // Consume and deserialize
        KafkaConsumer<String, byte[]> consumer = new KafkaConsumer<>(consumerProps);
        consumer.subscribe(Collections.singletonList("serialized-objects"));
        ConsumerRecords<String, byte[]> records = consumer.poll(1000);
        
        for (ConsumerRecord<String, byte[]> consumerRecord : records) {
            byte[] retrievedData = consumerRecord.value();
            // ruleid: java-untrusted-load
            Object deserializedObject = new ObjectInputStream(new ByteArrayInputStream(retrievedData)).readObject();
            System.out.println("Processed Kafka message: " + deserializedObject);
        }
        consumer.close();
    }

    public void bad_case_9() throws Exception {
        // Vulnerable implementation using RabbitMQ with HTTP-sourced data via Apache HttpClient
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("http://example.com/get-serialized");
        org.apache.http.HttpResponse response = httpClient.execute(httpPost);
        byte[] serializedData = IOUtils.toByteArray(response.getEntity().getContent());
        
        // Set up RabbitMQ connection
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        
        // Send HTTP data to RabbitMQ
        String queueName = "serialized_objects";
        channel.queueDeclare(queueName, false, false, false, null);
        channel.basicPublish("", queueName, null, serializedData);
        
        // Set up consumer to deserialize
        DeliverCallback deliverCallback = (consumerTag, delivery) -> {
            byte[] retrievedData = delivery.getBody();
            try {
                // ruleid: java-untrusted-load
                Object deserializedObject = new ObjectInputStream(new ByteArrayInputStream(retrievedData)).readObject();
                System.out.println("Received RabbitMQ message: " + deserializedObject);
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
        
        channel.basicConsume(queueName, true, deliverCallback, consumerTag -> {});
    }

    public void bad_case_10() throws Exception {
        // Vulnerable implementation using MongoDB with HTTP-sourced data via JAX-RS client
        ResteasyClient client = new ResteasyClientBuilder().build();
        byte[] serializedData = client.target("http://example.com/serialized-data")
                                     .request()
                                     .get(byte[].class);
        
        // Store HTTP data in MongoDB
        MongoClient mongoClient = new MongoClient("localhost", 27017);
        MongoDatabase database = mongoClient.getDatabase("app_database");
        MongoCollection<Document> collection = database.getCollection("serialized_objects");
        
        Document document = new Document("type", "user_data")
                           .append("serialized_object", serializedData);
        collection.insertOne(document);
        
        // Later retrieve and deserialize
        Document retrievedDoc = collection.find(new Document("type", "user_data")).first();
        byte[] retrievedData = (byte[]) retrievedDoc.get("serialized_object");
        
        // ruleid: java-untrusted-load
        Object deserializedObject = new ObjectInputStream(new ByteArrayInputStream(retrievedData)).readObject();
        System.out.println("Retrieved MongoDB object: " + deserializedObject);
        
        mongoClient.close();
    }

    public void bad_case_11() throws Exception {
        // Vulnerable implementation using Hibernate with HTTP-sourced data via Jetty
        Server server = new Server(8080);
        ServletHandler handler = new ServletHandler();
        server.setHandler(handler);
        
        handler.addServletWithMapping(new ServletHolder(new HttpServlet() {
            @Override
            protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                byte[] serializedData = IOUtils.toByteArray(req.getInputStream());
                
                // Store HTTP data in database using Hibernate
                SessionFactory sessionFactory = new Configuration().configure().buildSessionFactory();
                Session session = sessionFactory.openSession();
                session.beginTransaction();
                
                SerializedObject obj = new SerializedObject();
                obj.setId(1L);
                obj.setSerializedData(serializedData);
                session.save(obj);
                session.getTransaction().commit();
                
                // Later retrieve and deserialize
                session = sessionFactory.openSession();
                session.beginTransaction();
                SerializedObject retrievedObj = session.get(SerializedObject.class, 1L);
                byte[] retrievedData = retrievedObj.getSerializedData();
                session.getTransaction().commit();
                
                try {
                    // ruleid: java-untrusted-load
                    Object deserializedObject = new ObjectInputStream(new ByteArrayInputStream(retrievedData)).readObject();
                    resp.getWriter().write("Processed: " + deserializedObject);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                
                sessionFactory.close();
            }
        }), "/serialize");
        
        server.start();
    }

    public void bad_case_12() throws Exception {
        // Vulnerable implementation using Vert.x with HTTP-sourced data
        Vertx vertx = Vertx.vertx();
        HttpServer server = vertx.createHttpServer();
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.post("/process").handler(ctx -> {
            byte[] serializedData = ctx.getBody().getBytes();
            
            // Process in a separate thread
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<String> future = executor.submit(() -> {
                try {
                    // ruleid: java-untrusted-load
                    Object deserializedObject = new ObjectInputStream(new ByteArrayInputStream(serializedData)).readObject();
                    return "Processed: " + deserializedObject;
                } catch (Exception e) {
                    e.printStackTrace();
                    return "Error: " + e.getMessage();
                }
            });
            
            try {
                String result = future.get(30, TimeUnit.SECONDS);
                ctx.response().end(result);
            } catch (Exception e) {
                ctx.response().end("Processing error");
            }
            executor.shutdown();
        });
        
        server.requestHandler(router).listen(8080);
    }

    public void bad_case_13() throws Exception {
        // Vulnerable implementation using SealedObject with HTTP-sourced data
        URL url = new URL("http://example.com/encrypted-serialized");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        byte[] encryptedSerializedData = IOUtils.toByteArray(connection.getInputStream());
        
        // Decrypt and deserialize
        SecretKeySpec key = new SecretKeySpec("insecurepassword".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        ByteArrayInputStream bais = new ByteArrayInputStream(encryptedSerializedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        SealedObject sealedObject = (SealedObject) ois.readObject();
        
        // ruleid: java-untrusted-load
        Object deserializedObject = sealedObject.getObject(cipher);
        System.out.println("Decrypted and deserialized: " + deserializedObject);
    }

    public void bad_case_14(HttpServletRequest request) throws Exception {
        // Vulnerable implementation using custom ClassLoader with HTTP input
        byte[] serializedData = IOUtils.toByteArray(request.getInputStream());
        
        // Custom class loader that will be used during deserialization
        ClassLoader customClassLoader = new URLClassLoader(
            new URL[] { new URL("file:///path/to/classes/") },
            Thread.currentThread().getContextClassLoader()
        );
        
        // ruleid: java-untrusted-load
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData)) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                try {
                    return customClassLoader.loadClass(desc.getName());
                } catch (ClassNotFoundException e) {
                    return super.resolveClass(desc);
                }
            }
        };
        
        Object obj = ois.readObject();
        System.out.println("Deserialized with custom class loader: " + obj);
    }

    public void bad_case_15() throws Exception {
        // Vulnerable implementation using SnakeYAML with HTTP-sourced data
        URL url = new URL("http://example.com/serialized-yaml");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        String yamlContent = IOUtils.toString(connection.getInputStream(), "UTF-8");
        
        Yaml yaml = new Yaml();
        // ruleid: java-untrusted-load
        Object deserializedObject = yaml.load(yamlContent);
        System.out.println("Deserialized YAML: " + deserializedObject);
    }

    // True Negative Examples (Safe/Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Secure implementation using ObjectInputStream with allowlist
        try {
            InputStream inputStream = request.getInputStream();
            
            // ok: java-untrusted-load
            ObjectInputStream ois = new ObjectInputFilter.FilteredObjectInputStream(inputStream);
            ois.setObjectInputFilter(filterInfo -> {
                Class<?> clazz = filterInfo.serialClass();
                if (clazz != null) {
                    // Only allow specific safe classes
                    return (clazz.equals(String.class) || 
                            clazz.equals(Integer.class) || 
                            clazz.equals(ArrayList.class)) 
                           ? ObjectInputFilter.Status.ALLOWED 
                           : ObjectInputFilter.Status.REJECTED;
                }
                return ObjectInputFilter.Status.UNDECIDED;
            });
            
            Object obj = ois.readObject();
            ois.close();
            
            response.getWriter().write("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request) throws Exception {
        // Secure implementation using Jackson instead of raw Java serialization
        byte[] data = IOUtils.toByteArray(request.getInputStream());
        String json = new String(data, "UTF-8");
        
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-untrusted-load
        SafeObject safeObject = mapper.readValue(json, SafeObject.class);
        
        System.out.println("Deserialized object: " + safeObject);
    }

    @RestController
    public static class Good_case_3 {
        // Secure implementation using XStream with security processing
        @PostMapping("/xstream-deserialize-secure")
        public String deserializeXmlSecurely(@RequestBody String xml) {
            XStream xstream = new XStream();
            
            // ok: java-untrusted-load
            // Configure XStream security framework
            xstream.allowTypesByWildcard(new String[] {
                "com.example.safe.**"
            });
            xstream.denyTypesByWildcard(new String[] {
                "java.lang.Process",
                "java.lang.ProcessBuilder",
                "java.lang.Runtime",
                "**.*exec*",
                "**.*Exec*",
                "**.*fork*",
                "**.*Fork*",
                "**.*shell*",
                "**.*Shell*"
            });
            
            Object obj = xstream.fromXML(xml);
            return "Securely deserialized: " + obj.toString();
        }
    }

    public void good_case_4(HttpServletRequest request) throws Exception {
        // Secure implementation using JMS with data validation
        String url = "tcp://localhost:61616";
        ConnectionFactory factory = new ActiveMQConnectionFactory(url);
        Connection connection = factory.createConnection();
        Session session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
        
        // Get data from HTTP request and validate/transform it to a safe format
        String jsonData = IOUtils.toString(request.getInputStream(), "UTF-8");
        
        // Validate and convert to a safe object using Jackson
        ObjectMapper mapper = new ObjectMapper();
        SafeObject validatedObject = mapper.readValue(jsonData, SafeObject.class);
        
        // Store validated object in JMS message
        Queue queue = session.createQueue("safeQueue");
        MessageProducer producer = session.createProducer(queue);
        TextMessage message = session.createTextMessage(mapper.writeValueAsString(validatedObject));
        producer.send(message);
        
        // Consumer that safely deserializes the data
        MessageConsumer consumer = session.createConsumer(queue);
        connection.start();
        TextMessage receivedMessage = (TextMessage) consumer.receive();
        String receivedJson = receivedMessage.getText();
        
        // ok: java-untrusted-load
        SafeObject deserializedObject = mapper.readValue(receivedJson, SafeObject.class);
        System.out.println("Processed: " + deserializedObject);
        
        connection.close();
    }

    public void good_case_5(HttpServletRequest request) throws Exception {
        // Secure implementation using Redis with safe serialization
        Jedis jedis = new Jedis("localhost");
        
        // Get data from HTTP request and validate/transform it
        String jsonData = IOUtils.toString(request.getInputStream(), "UTF-8");
        
        // Validate and convert to a safe format using Gson
        Gson gson = new Gson();
        SafeObject validatedObject = gson.fromJson(jsonData, SafeObject.class);
        
        // Store validated object in Redis as JSON
        String safeJson = gson.toJson(validatedObject);
        jedis.set("cached_object", safeJson);
        
        // Later retrieve and deserialize safely
        String retrievedJson = jedis.get("cached_object");
        
        // ok: java-untrusted-load
        SafeObject deserializedObject = gson.fromJson(retrievedJson, SafeObject.class);
        System.out.println("Retrieved object: " + deserializedObject);
        
        jedis.close();
    }

    public void good_case_6(HttpServletRequest request) throws Exception {
        // Secure implementation using Hazelcast with safe serialization
        HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance();
        IMap<String, String> distributedMap = hazelcastInstance.getMap("safeObjects");
        
        // Get data from HTTP request and validate/transform it
        String jsonData = IOUtils.toString(request.getInputStream(), "UTF-8");
        
        // Validate and convert to a safe format using Jackson
        ObjectMapper mapper = new ObjectMapper();
        SafeObject validatedObject = mapper.readValue(jsonData, SafeObject.class);
        
        // Store validated object in Hazelcast as JSON
        String safeJson = mapper.writeValueAsString(validatedObject);
        distributedMap.put("user_object", safeJson);
        
        // Later retrieve and deserialize safely
        String retrievedJson = distributedMap.get("user_object");
        
        // ok: java-untrusted-load
        SafeObject deserializedObject = mapper.readValue(retrievedJson, SafeObject.class);
        System.out.println("Retrieved distributed object: " + deserializedObject);
        
        hazelcastInstance.shutdown();
    }

    public void good_case_7() throws Exception {
        // Secure implementation using AWS S3 with safe serialization
        OkHttpClient client = new OkHttpClient();
        Request httpRequest = new Request.Builder()
            .url("http://example.com/data")
            .build();
        
        Response response = client.newCall(httpRequest).execute();
        String jsonData = response.body().string();
        
        // Validate and convert to a safe format using Jackson
        ObjectMapper mapper = new ObjectMapper();
        SafeObject validatedObject = mapper.readValue(jsonData, SafeObject.class);
        
        // Store validated object in S3 as JSON
        String safeJson = mapper.writeValueAsString(validatedObject);
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        s3Client.putObject("my-bucket", "safe-object", safeJson);
        
        // Later retrieve and deserialize safely
        S3Object s3Object = s3Client.getObject("my-bucket", "safe-object");
        String retrievedJson = IOUtils.toString(s3Object.getObjectContent(), "UTF-8");
        
        // ok: java-untrusted-load
        SafeObject deserializedObject = mapper.readValue(retrievedJson, SafeObject.class);
        System.out.println("Retrieved S3 object: " + deserializedObject);
    }

    public void good_case_8() throws Exception {
        // Secure implementation using Kafka with safe serialization
        RestTemplate restTemplate = new RestTemplate();
        String jsonData = restTemplate.getForObject("http://example.com/data", String.class);
        
        // Validate and convert to a safe format using Gson
        Gson gson = new Gson();
        SafeObject validatedObject = gson.fromJson(jsonData, SafeObject.class);
        String safeJson = gson.toJson(validatedObject);
        
        // Configure Kafka producer
        Properties producerProps = new Properties();
        producerProps.put("bootstrap.servers", "localhost:9092");
        producerProps.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producerProps.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        
        // Send safe JSON to Kafka
        KafkaProducer<String, String> producer = new KafkaProducer<>(producerProps);
        ProducerRecord<String, String> record = new ProducerRecord<>("safe-objects", "key1", safeJson);
        producer.send(record);
        producer.close();
        
        // Configure Kafka consumer
        Properties consumerProps = new Properties();
        consumerProps.put("bootstrap.servers", "localhost:9092");
        consumerProps.put("group.id", "safe-group");
        consumerProps.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        consumerProps.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        
        // Consume and deserialize safely
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consumerProps);
        consumer.subscribe(Collections.singletonList("safe-objects"));
        ConsumerRecords<String, String> records = consumer.poll(1000);
        
        for (ConsumerRecord<String, String> consumerRecord : records) {
            String retrievedJson = consumerRecord.value();
            // ok: java-untrusted-load
            SafeObject deserializedObject = gson.fromJson(retrievedJson, SafeObject.class);
            System.out.println("Processed Kafka message: " + deserializedObject);
        }
        consumer.close();
    }

    public void good_case_9() throws Exception {
        // Secure implementation using RabbitMQ with safe serialization
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("http://example.com/get-data");
        org.apache.http.HttpResponse response = httpClient.execute(httpPost);
        String jsonData = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
        
        // Validate and convert to a safe format using Jackson
        ObjectMapper mapper = new ObjectMapper();
        SafeObject validatedObject = mapper.readValue(jsonData, SafeObject.class);
        String safeJson = mapper.writeValueAsString(validatedObject);
        
        // Set up RabbitMQ connection
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        
        // Send safe JSON to RabbitMQ
        String queueName = "safe_objects";
        channel.queueDeclare(queueName, false, false, false, null);
        channel.basicPublish("", queueName, null, safeJson.getBytes());
        
        // Set up consumer to deserialize safely
        DeliverCallback deliverCallback = (consumerTag, delivery) -> {
            String retrievedJson = new String(delivery.getBody(), "UTF-8");
            try {
                // ok: java-untrusted-load
                SafeObject deserializedObject = mapper.readValue(retrievedJson, SafeObject.class);
                System.out.println("Received RabbitMQ message: " + deserializedObject);
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
        
        channel.basicConsume(queueName, true, deliverCallback, consumerTag -> {});
    }

    public void good_case_10() throws Exception {
        // Secure implementation using MongoDB with safe serialization
        ResteasyClient client = new ResteasyClientBuilder().build();
        String jsonData = client.target("http://example.com/data")
                               .request()
                               .get(String.class);
        
        // Validate and convert to a safe format using Gson
        Gson gson = new Gson();
        SafeObject validatedObject = gson.fromJson(jsonData, SafeObject.class);
        
        // Store validated object in MongoDB as a document
        MongoClient mongoClient = new MongoClient("localhost", 27017);
        MongoDatabase database = mongoClient.getDatabase("app_database");
        MongoCollection<Document> collection = database.getCollection("safe_objects");
        
        Document document = new Document("type", "user_data")
                           .append("name", validatedObject.getName())
                           .append("value", validatedObject.getValue())
                           .append("timestamp", new Date());
        collection.insertOne(document);
        
        // Later retrieve and map to object
        Document retrievedDoc = collection.find(new Document("type", "user_data")).first();
        
        // ok: java-untrusted-load
        SafeObject deserializedObject = new SafeObject();
        deserializedObject.setName(retrievedDoc.getString("name"));
        deserializedObject.setValue(retrievedDoc.getInteger("value"));
        
        System.out.println("Retrieved MongoDB object: " + deserializedObject);
        
        mongoClient.close();
    }

    public void good_case_11() throws Exception {
        // Secure implementation using Hibernate with safe data handling via Jetty
        Server server = new Server(8080);
        ServletHandler handler = new ServletHandler();
        server.setHandler(handler);
        
        handler.addServletWithMapping(new ServletHolder(new HttpServlet() {
            @Override
            protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                String jsonData = IOUtils.toString(req.getInputStream(), "UTF-8");
                
                // Validate and convert to a safe format using Jackson
                ObjectMapper mapper = new ObjectMapper();
                SafeObject validatedObject = mapper.readValue(jsonData, SafeObject.class);
                
                // Store validated object in database using Hibernate
                SessionFactory sessionFactory = new Configuration().configure().buildSessionFactory();
                Session session = sessionFactory.openSession();
                session.beginTransaction();
                
                SafeEntity entity = new SafeEntity();
                entity.setName(validatedObject.getName());
                entity.setValue(validatedObject.getValue());
                session.save(entity);
                session.getTransaction().commit();
                
                // Later retrieve and map to object
                session = sessionFactory.openSession();
                session.beginTransaction();
                SafeEntity retrievedEntity = session.get(SafeEntity.class, entity.getId());
                session.getTransaction().commit();
                
                // ok: java-untrusted-load
                SafeObject retrievedObject = new SafeObject();
                retrievedObject.setName(retrievedEntity.getName());
                retrievedObject.setValue(retrievedEntity.getValue());
                
                resp.getWriter().write("Processed: " + retrievedObject);
                
                sessionFactory.close();
            }
        }), "/safe-serialize");
        
        server.start();
    }

    public void good_case_12() throws Exception {
        // Secure implementation using Vert.x with safe data handling
        Vertx vertx = Vertx.vertx();
        HttpServer server = vertx.createHttpServer();
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.post("/process-safe").handler(ctx -> {
            String jsonData = ctx.getBodyAsString();
            
            // Process in a separate thread with safe deserialization
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<String> future = executor.submit(() -> {
                try {
                    // ok: java-untrusted-load
                    ObjectMapper mapper = new ObjectMapper();
                    mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NONE); // Disable polymorphic type handling
                    SafeObject safeObject = mapper.readValue(jsonData, SafeObject.class);
                    return "Processed: " + safeObject;
                } catch (Exception e) {
                    e.printStackTrace();
                    return "Error: " + e.getMessage();
                }
            });
            
            try {
                String result = future.get(30, TimeUnit.SECONDS);
                ctx.response().end(result);
            } catch (Exception e) {
                ctx.response().end("Processing error");
            }
            executor.shutdown();
        });
        
        server.requestHandler(router).listen(8080);
    }

    public void good_case_13() throws Exception {
        // Secure implementation using encryption with safe deserialization
        URL url = new URL("http://example.com/encrypted-data");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        byte[] encryptedData = IOUtils.toByteArray(connection.getInputStream());
        
        // Decrypt data
        SecretKeySpec key = new SecretKeySpec("securepassword123".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        
        // Safely deserialize using Jackson
        String jsonData = new String(decryptedData, "UTF-8");
        
        // ok: java-untrusted-load
        ObjectMapper mapper = new ObjectMapper();
        SafeObject safeObject = mapper.readValue(jsonData, SafeObject.class);
        
        System.out.println("Decrypted and safely deserialized: " + safeObject);
    }

    public void good_case_14(HttpServletRequest request) throws Exception {
        // Secure implementation using custom validation with HTTP input
        String jsonData = IOUtils.toString(request.getInputStream(), "UTF-8");
        
        // ok: java-untrusted-load
        // Use a custom deserializer with validation
        CustomSafeDeserializer deserializer = new CustomSafeDeserializer();
        SafeObject safeObject = deserializer.deserialize(jsonData);
        
        System.out.println("Safely deserialized with custom validation: " + safeObject);
    }

    public void good_case_15() throws Exception {
        // Secure implementation using SnakeYAML with safe type restrictions
        URL url = new URL("http://example.com/yaml-data");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        String yamlContent = IOUtils.toString(connection.getInputStream(), "UTF-8");
        
        // ok: java-untrusted-load
        // Configure YAML with safe loading
        Yaml yaml = new Yaml(new SafeConstructor());
        SafeObject safeObject = yaml.loadAs(yamlContent, SafeObject.class);
        
        System.out.println("Safely deserialized YAML: " + safeObject);
    }
    
    // Helper classes
    public static class SafeObject implements Serializable {
        private String name;
        private int value;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public int getValue() { return value; }
        public void setValue(int value) { this.value = value; }
        
        @Override
        public String toString() {
            return "SafeObject{name='" + name + "', value=" + value + "}";
        }
    }
    
    public static class SafeEntity {
        private Long id;
        private String name;
        private int value;
        
        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public int getValue() { return value; }
        public void setValue(int value) { this.value = value; }
    }
    
    public static class SerializedObject implements Serializable {
        private Long id;
        private byte[] serializedData;
        
        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        public byte[] getSerializedData() { return serializedData; }
        public void setSerializedData(byte[] serializedData) { this.serializedData = serializedData; }
    }
    
    public static class CustomSafeDeserializer {
        public SafeObject deserialize(String json) throws Exception {
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
            return mapper.readValue(json, SafeObject.class);
        }
    }
    
    public static class ServletHolder {
        private HttpServlet servlet;
        
        public ServletHolder(HttpServlet servlet) {
            this.servlet = servlet;
        }
    }
}
// {/fact}