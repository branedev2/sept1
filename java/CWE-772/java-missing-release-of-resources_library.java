import java.io.*;
import java.sql.*;
import java.net.*;
import java.util.*;
import java.nio.file.*;
import java.nio.channels.*;
import javax.imageio.*;
import javax.sound.sampled.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import javax.jms.*;
import org.apache.kafka.clients.producer.*;
import org.apache.kafka.clients.consumer.*;
import redis.clients.jedis.*;
import com.mongodb.*;
import org.neo4j.driver.*;
import javax.xml.parsers.*;
import org.elasticsearch.client.*;
import com.rabbitmq.client.*;
import javax.mail.*;
import javax.mail.internet.*;
import org.apache.commons.net.ftp.*;
import com.zaxxer.hikari.*;
import org.apache.pdfbox.pdmodel.*;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

// Security Issue: Missing release of resources which can lead to resource leaks

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // JDBC Connection not properly closed
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        // ruleid: java-missing-release-of-resources
        ResultSet rs = stmt.executeQuery("SELECT * FROM users");
        
        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }
        
        // Resources not closed if an exception occurs before this point
        rs.close();
        stmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    // FileInputStream not properly closed
    FileInputStream fis = null;
    try {
        // ruleid: java-missing-release-of-resources
        fis = new FileInputStream("config.properties");
        Properties props = new Properties();
        props.load(fis);
        System.out.println(props.getProperty("app.name"));
        
        // Resource not closed if an exception occurs before this point
        fis.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // Apache HttpClient not properly closed
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        // ruleid: java-missing-release-of-resources
        CloseableHttpResponse response = httpClient.execute(new HttpGet("https://api.example.com/data"));
        
        String responseBody = EntityUtils.toString(response.getEntity());
        System.out.println(responseBody);
        
        // Resources not closed if an exception occurs before this point
        response.close();
        httpClient.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    // AWS S3 client not properly closed
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    try {
        // ruleid: java-missing-release-of-resources
        S3Object s3Object = s3Client.getObject("mybucket", "mykey");
        S3ObjectInputStream inputStream = s3Object.getObjectContent();
        
        byte[] bytes = inputStream.readAllBytes();
        System.out.println("File size: " + bytes.length);
        
        // Resources not closed if an exception occurs before this point
        inputStream.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // JMS Connection not properly closed
    try {
        ConnectionFactory factory = new com.sun.messaging.ConnectionFactory();
        // ruleid: java-missing-release-of-resources
        Connection connection = factory.createConnection();
        Session session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
        
        Queue queue = session.createQueue("myQueue");
        MessageProducer producer = session.createProducer(queue);
        
        TextMessage message = session.createTextMessage("Hello JMS");
        producer.send(message);
        
        // Resources not closed if an exception occurs before this point
        producer.close();
        session.close();
        connection.close();
    } catch (JMSException e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // Kafka Producer not properly closed
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    
    // ruleid: java-missing-release-of-resources
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    
    try {
        producer.send(new ProducerRecord<>("my-topic", "key", "value"));
        
        // Resource not closed if an exception occurs before this point
        producer.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // Redis Jedis connection not properly closed
    // ruleid: java-missing-release-of-resources
    Jedis jedis = new Jedis("localhost");
    
    try {
        jedis.set("key", "value");
        String value = jedis.get("key");
        System.out.println(value);
        
        // Resource not closed if an exception occurs before this point
        jedis.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // MongoDB client not properly closed
    // ruleid: java-missing-release-of-resources
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    
    try {
        MongoDatabase database = mongoClient.getDatabase("mydb");
        MongoCollection<Document> collection = database.getCollection("users");
        
        Document doc = collection.find().first();
        System.out.println(doc.toJson());
        
        // Resource not closed if an exception occurs before this point
        mongoClient.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // Neo4j Driver not properly closed
    // ruleid: java-missing-release-of-resources
    Driver driver = GraphDatabase.driver("bolt://localhost:7687", AuthTokens.basic("neo4j", "password"));
    
    try {
        Session session = driver.session();
        Result result = session.run("MATCH (n) RETURN n LIMIT 10");
        
        while (result.hasNext()) {
            System.out.println(result.next().get(0).asString());
        }
        
        // Resources not closed if an exception occurs before this point
        session.close();
        driver.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // XML Parser not properly closed
    try {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        // ruleid: java-missing-release-of-resources
        InputStream is = new FileInputStream("data.xml");
        Document document = builder.parse(is);
        
        System.out.println(document.getDocumentElement().getNodeName());
        
        // Resource not closed if an exception occurs before this point
        is.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Elasticsearch client not properly closed
    RestClient restClient = RestClient.builder(new HttpHost("localhost", 9200, "http")).build();
    
    try {
        // ruleid: java-missing-release-of-resources
        Response response = restClient.performRequest(new Request("GET", "/index/_search"));
        
        System.out.println(EntityUtils.toString(response.getEntity()));
        
        // Resource not closed if an exception occurs before this point
        restClient.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // RabbitMQ connection not properly closed
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    
    try {
        // ruleid: java-missing-release-of-resources
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        
        channel.queueDeclare("hello", false, false, false, null);
        channel.basicPublish("", "hello", null, "Hello World!".getBytes());
        
        // Resources not closed if an exception occurs before this point
        channel.close();
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    // JavaMail session not properly closed
    try {
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.example.com");
        Session session = Session.getInstance(props);
        
        // ruleid: java-missing-release-of-resources
        Transport transport = session.getTransport("smtp");
        transport.connect("username", "password");
        
        MimeMessage message = new MimeMessage(session);
        message.setSubject("Test Email");
        message.setText("This is a test email");
        
        transport.sendMessage(message, message.getAllRecipients());
        
        // Resource not closed if an exception occurs before this point
        transport.close();
    } catch (MessagingException e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // Apache Commons Net FTP client not properly closed
    FTPClient ftpClient = new FTPClient();
    
    try {
        // ruleid: java-missing-release-of-resources
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
        ftpClient.enterLocalPassiveMode();
        
        InputStream inputStream = ftpClient.retrieveFileStream("/remote/file.txt");
        byte[] bytes = inputStream.readAllBytes();
        System.out.println("File size: " + bytes.length);
        
        // Resources not closed if an exception occurs before this point
        inputStream.close();
        ftpClient.disconnect();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Apache PDFBox document not properly closed
    try {
        // ruleid: java-missing-release-of-resources
        PDDocument document = PDDocument.load(new File("document.pdf"));
        
        int pageCount = document.getNumberOfPages();
        System.out.println("PDF has " + pageCount + " pages");
        
        // Resource not closed if an exception occurs before this point
        document.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // JDBC Connection properly closed with try-with-resources
    // ok: java-missing-release-of-resources
    try (
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users")
    ) {
        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // FileInputStream properly closed with try-with-resources
    // ok: java-missing-release-of-resources
    try (FileInputStream fis = new FileInputStream("config.properties")) {
        Properties props = new Properties();
        props.load(fis);
        System.out.println(props.getProperty("app.name"));
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // Apache HttpClient properly closed with try-with-resources
    // ok: java-missing-release-of-resources
    try (
        CloseableHttpClient httpClient = HttpClients.createDefault();
        CloseableHttpResponse response = httpClient.execute(new HttpGet("https://api.example.com/data"))
    ) {
        String responseBody = EntityUtils.toString(response.getEntity());
        System.out.println(responseBody);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    // AWS S3 client properly closed with try-with-resources
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    // ok: java-missing-release-of-resources
    try (
        S3Object s3Object = s3Client.getObject("mybucket", "mykey");
        S3ObjectInputStream inputStream = s3Object.getObjectContent()
    ) {
        byte[] bytes = inputStream.readAllBytes();
        System.out.println("File size: " + bytes.length);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // JMS Connection properly closed with try-with-resources
    try {
        ConnectionFactory factory = new com.sun.messaging.ConnectionFactory();
        // ok: java-missing-release-of-resources
        try (
            Connection connection = factory.createConnection();
            Session session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID)
        ) {
            Queue queue = session.createQueue("myQueue");
            try (MessageProducer producer = session.createProducer(queue)) {
                TextMessage message = session.createTextMessage("Hello JMS");
                producer.send(message);
            }
        }
    } catch (JMSException e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // Kafka Producer properly closed with try-with-resources
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    
    // ok: java-missing-release-of-resources
    try (KafkaProducer<String, String> producer = new KafkaProducer<>(props)) {
        producer.send(new ProducerRecord<>("my-topic", "key", "value"));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    // Redis Jedis connection properly closed with try-with-resources
    // ok: java-missing-release-of-resources
    try (Jedis jedis = new Jedis("localhost")) {
        jedis.set("key", "value");
        String value = jedis.get("key");
        System.out.println(value);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // MongoDB client properly closed with try-with-resources
    // ok: java-missing-release-of-resources
    try (MongoClient mongoClient = new MongoClient("localhost", 27017)) {
        MongoDatabase database = mongoClient.getDatabase("mydb");
        MongoCollection<Document> collection = database.getCollection("users");
        
        Document doc = collection.find().first();
        System.out.println(doc.toJson());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    // Neo4j Driver properly closed with try-with-resources
    // ok: java-missing-release-of-resources
    try (
        Driver driver = GraphDatabase.driver("bolt://localhost:7687", AuthTokens.basic("neo4j", "password"));
        Session session = driver.session()
    ) {
        Result result = session.run("MATCH (n) RETURN n LIMIT 10");
        
        while (result.hasNext()) {
            System.out.println(result.next().get(0).asString());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    // XML Parser properly closed with try-with-resources
    try {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        // ok: java-missing-release-of-resources
        try (InputStream is = new FileInputStream("data.xml")) {
            Document document = builder.parse(is);
            System.out.println(document.getDocumentElement().getNodeName());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Elasticsearch client properly closed with try-with-resources
    // ok: java-missing-release-of-resources
    try (RestClient restClient = RestClient.builder(new HttpHost("localhost", 9200, "http")).build()) {
        Response response = restClient.performRequest(new Request("GET", "/index/_search"));
        System.out.println(EntityUtils.toString(response.getEntity()));
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // RabbitMQ connection properly closed with try-with-resources
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    
    // ok: java-missing-release-of-resources
    try (
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel()
    ) {
        channel.queueDeclare("hello", false, false, false, null);
        channel.basicPublish("", "hello", null, "Hello World!".getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    // JavaMail session properly closed with try-with-resources
    try {
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.example.com");
        Session session = Session.getInstance(props);
        
        // ok: java-missing-release-of-resources
        try (Transport transport = session.getTransport("smtp")) {
            transport.connect("username", "password");
            
            MimeMessage message = new MimeMessage(session);
            message.setSubject("Test Email");
            message.setText("This is a test email");
            
            transport.sendMessage(message, message.getAllRecipients());
        }
    } catch (MessagingException e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    // Apache Commons Net FTP client properly closed with try-with-resources and finally block
    FTPClient ftpClient = new FTPClient();
    
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
        ftpClient.enterLocalPassiveMode();
        
        // ok: java-missing-release-of-resources
        try (InputStream inputStream = ftpClient.retrieveFileStream("/remote/file.txt")) {
            byte[] bytes = inputStream.readAllBytes();
            System.out.println("File size: " + bytes.length);
        }
    } catch (IOException e) {
        e.printStackTrace();
    } finally {
        try {
            if (ftpClient.isConnected()) {
                ftpClient.disconnect();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void good_case_15() {
    // Apache PDFBox document properly closed with try-with-resources
    // ok: java-missing-release-of-resources
    try (PDDocument document = PDDocument.load(new File("document.pdf"))) {
        int pageCount = document.getNumberOfPages();
        System.out.println("PDF has " + pageCount + " pages");
    } catch (IOException e) {
        e.printStackTrace();
    }
}