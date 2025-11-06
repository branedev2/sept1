import java.io.*;
import java.sql.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import javax.imageio.*;
import java.awt.image.BufferedImage;
import javax.sound.sampled.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import java.nio.channels.*;
import javax.net.ssl.*;
import java.util.logging.*;
import java.util.concurrent.locks.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.HttpResponse;
import org.apache.commons.io.IOUtils;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.zaxxer.hikari.*;
import redis.clients.jedis.*;
import org.apache.kafka.clients.producer.*;
import org.elasticsearch.client.*;
import org.apache.pdfbox.pdmodel.*;
import org.apache.commons.net.ftp.*;
import org.apache.commons.dbcp2.*;
import com.rabbitmq.client.*;
import org.apache.commons.compress.archivers.*;
import org.apache.commons.compress.archivers.zip.*;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.*;
import org.apache.commons.vfs2.*;
import org.neo4j.driver.*;
import com.mongodb.*;
import com.mongodb.client.*;

// Security Issue: Resource Leak Detection - Improper resource management leading to resource leaks

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Java FileInputStream resource leak
    try {
        // ruleid: java-resource-leak-detector
        FileInputStream fis = new FileInputStream("config.properties");
        Properties props = new Properties();
        props.load(fis);
        System.out.println("Loaded " + props.size() + " properties");
        // Missing fis.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    // JDBC Connection resource leak
    try {
        String url = "jdbc:mysql://localhost:3306/mydb";
        String user = "username";
        String password = "password";
        // ruleid: java-resource-leak-detector
        Connection conn = DriverManager.getConnection(url, user, password);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users");
        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }
        // Missing conn.close(), stmt.close(), rs.close()
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // Apache HttpClient resource leak
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/data");
        // ruleid: java-resource-leak-detector
        CloseableHttpResponse response = httpClient.execute(request);
        String responseBody = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
        System.out.println("Response: " + responseBody);
        // Missing response.close() and httpClient.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    // AWS S3 Client resource leak
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withRegion("us-west-2")
            .build();
    try {
        // ruleid: java-resource-leak-detector
        S3Object s3Object = s3Client.getObject("mybucket", "mykey");
        InputStream inputStream = s3Object.getObjectContent();
        byte[] data = IOUtils.toByteArray(inputStream);
        System.out.println("Downloaded " + data.length + " bytes");
        // Missing inputStream.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // ZipFile resource leak
    try {
        // ruleid: java-resource-leak-detector
        ZipFile zipFile = new ZipFile("archive.zip");
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            System.out.println("Found: " + entry.getName());
        }
        // Missing zipFile.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // BufferedReader resource leak
    try {
        URL url = new URL("https://example.com/data.txt");
        // ruleid: java-resource-leak-detector
        BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        // Missing reader.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // ImageIO resource leak
    try {
        // ruleid: java-resource-leak-detector
        InputStream is = new URL("https://example.com/image.jpg").openStream();
        BufferedImage image = ImageIO.read(is);
        System.out.println("Image dimensions: " + image.getWidth() + "x" + image.getHeight());
        // Missing is.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // AudioSystem resource leak
    try {
        File audioFile = new File("sound.wav");
        // ruleid: java-resource-leak-detector
        AudioInputStream audioStream = AudioSystem.getAudioInputStream(audioFile);
        AudioFormat format = audioStream.getFormat();
        System.out.println("Audio format: " + format.toString());
        // Missing audioStream.close()
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // SAX Parser resource leak
    try {
        // ruleid: java-resource-leak-detector
        InputStream xmlInput = new FileInputStream("data.xml");
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser saxParser = factory.newSAXParser();
        DefaultHandler handler = new DefaultHandler();
        saxParser.parse(xmlInput, handler);
        // Missing xmlInput.close()
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // FileChannel resource leak
    try {
        // ruleid: java-resource-leak-detector
        FileChannel channel = FileChannel.open(Paths.get("data.bin"), StandardOpenOption.READ);
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int bytesRead = channel.read(buffer);
        System.out.println("Read " + bytesRead + " bytes");
        // Missing channel.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // HikariCP Connection Pool resource leak
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
    config.setUsername("user");
    config.setPassword("password");
    
    try {
        HikariDataSource dataSource = new HikariDataSource(config);
        // ruleid: java-resource-leak-detector
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setInt(1, 123);
        ResultSet rs = pstmt.executeQuery();
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
        // Missing rs.close(), pstmt.close(), conn.close(), dataSource.close()
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Redis Jedis resource leak
    // ruleid: java-resource-leak-detector
    Jedis jedis = new Jedis("localhost", 6379);
    jedis.auth("password");
    String value = jedis.get("mykey");
    System.out.println("Retrieved value: " + value);
    // Missing jedis.close()
}

public void bad_case_13() {
    // Kafka Producer resource leak
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    
    // ruleid: java-resource-leak-detector
    Producer<String, String> producer = new KafkaProducer<>(props);
    producer.send(new ProducerRecord<>("topic", "key", "value"));
    // Missing producer.close()
}

public void bad_case_14() {
    // Elasticsearch Client resource leak
    RestClient restClient = RestClient.builder(
            new HttpHost("localhost", 9200, "http")).build();
    // ruleid: java-resource-leak-detector
    RestHighLevelClient client = new RestHighLevelClient(restClient);
    try {
        SearchRequest searchRequest = new SearchRequest("index");
        client.search(searchRequest);
        // Missing client.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Apache PDFBox resource leak
    try {
        // ruleid: java-resource-leak-detector
        PDDocument document = PDDocument.load(new File("document.pdf"));
        int pageCount = document.getNumberOfPages();
        System.out.println("PDF has " + pageCount + " pages");
        // Missing document.close()
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Java FileInputStream with try-with-resources
    try (
        // ok: java-resource-leak-detector
        FileInputStream fis = new FileInputStream("config.properties")
    ) {
        Properties props = new Properties();
        props.load(fis);
        System.out.println("Loaded " + props.size() + " properties");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // JDBC Connection with try-with-resources
    String url = "jdbc:mysql://localhost:3306/mydb";
    String user = "username";
    String password = "password";
    
    try (
        // ok: java-resource-leak-detector
        Connection conn = DriverManager.getConnection(url, user, password);
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

public void good_case_3() {
    // Apache HttpClient with try-with-resources
    try (
        // ok: java-resource-leak-detector
        CloseableHttpClient httpClient = HttpClients.createDefault();
        CloseableHttpResponse response = httpClient.execute(new HttpGet("https://api.example.com/data"))
    ) {
        String responseBody = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
        System.out.println("Response: " + responseBody);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    // AWS S3 Client with proper resource management
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withRegion("us-west-2")
            .build();
    S3Object s3Object = null;
    InputStream inputStream = null;
    try {
        s3Object = s3Client.getObject("mybucket", "mykey");
        // ok: java-resource-leak-detector
        inputStream = s3Object.getObjectContent();
        byte[] data = IOUtils.toByteArray(inputStream);
        System.out.println("Downloaded " + data.length + " bytes");
    } catch (IOException e) {
        e.printStackTrace();
    } finally {
        IOUtils.closeQuietly(inputStream);
    }
}

public void good_case_5() {
    // ZipFile with try-with-resources
    try (
        // ok: java-resource-leak-detector
        ZipFile zipFile = new ZipFile("archive.zip")
    ) {
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            System.out.println("Found: " + entry.getName());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // BufferedReader with try-with-resources
    try (
        // ok: java-resource-leak-detector
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(new URL("https://example.com/data.txt").openStream()))
    ) {
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    // ImageIO with try-with-resources
    try (
        // ok: java-resource-leak-detector
        InputStream is = new URL("https://example.com/image.jpg").openStream()
    ) {
        BufferedImage image = ImageIO.read(is);
        System.out.println("Image dimensions: " + image.getWidth() + "x" + image.getHeight());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // AudioSystem with try-with-resources
    try (
        // ok: java-resource-leak-detector
        AudioInputStream audioStream = AudioSystem.getAudioInputStream(new File("sound.wav"))
    ) {
        AudioFormat format = audioStream.getFormat();
        System.out.println("Audio format: " + format.toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    // SAX Parser with try-with-resources
    try (
        // ok: java-resource-leak-detector
        InputStream xmlInput = new FileInputStream("data.xml")
    ) {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser saxParser = factory.newSAXParser();
        DefaultHandler handler = new DefaultHandler();
        saxParser.parse(xmlInput, handler);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    // FileChannel with try-with-resources
    try (
        // ok: java-resource-leak-detector
        FileChannel channel = FileChannel.open(Paths.get("data.bin"), StandardOpenOption.READ)
    ) {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int bytesRead = channel.read(buffer);
        System.out.println("Read " + bytesRead + " bytes");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // HikariCP Connection Pool with proper resource management
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
    config.setUsername("user");
    config.setPassword("password");
    
    try (
        // ok: java-resource-leak-detector
        HikariDataSource dataSource = new HikariDataSource(config);
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ResultSet rs = pstmt.executeQuery()
    ) {
        pstmt.setInt(1, 123);
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // Redis Jedis with try-with-resources
    try (
        // ok: java-resource-leak-detector
        Jedis jedis = new Jedis("localhost", 6379)
    ) {
        jedis.auth("password");
        String value = jedis.get("mykey");
        System.out.println("Retrieved value: " + value);
    }
}

public void good_case_13() {
    // Kafka Producer with try-with-resources
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    
    try (
        // ok: java-resource-leak-detector
        Producer<String, String> producer = new KafkaProducer<>(props)
    ) {
        producer.send(new ProducerRecord<>("topic", "key", "value"));
    }
}

public void good_case_14() {
    // Elasticsearch Client with try-with-resources
    try (
        // ok: java-resource-leak-detector
        RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")))
    ) {
        SearchRequest searchRequest = new SearchRequest("index");
        client.search(searchRequest);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    // Apache PDFBox with try-with-resources
    try (
        // ok: java-resource-leak-detector
        PDDocument document = PDDocument.load(new File("document.pdf"))
    ) {
        int pageCount = document.getNumberOfPages();
        System.out.println("PDF has " + pageCount + " pages");
    } catch (IOException e) {
        e.printStackTrace();
    }
}