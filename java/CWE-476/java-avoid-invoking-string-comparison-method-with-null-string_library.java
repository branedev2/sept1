import java.util.*;
import java.io.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.google.gson.Gson;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import org.apache.commons.lang3.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.apache.commons.io.FileUtils;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.BlobContainerClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.Query;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.File;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import redis.clients.jedis.Jedis;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.Channel;

// Security Issue: Comparing a String with null using the equals() method can lead to a NullPointerException

// True Positive Examples (Vulnerable/Insecure Code)
public class StringComparisonVulnerabilities {

// {fact rule=inconsistent-null-check@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Spring MVC web framework example
        String username = request.getParameter("username");
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (username.equals("admin")) {
            System.out.println("Admin user detected");
        }
    }

    public void bad_case_2() throws Exception {
        // Apache HttpClient example
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/user");
        String response = EntityUtils.toString(httpClient.execute(request).getEntity());
        String userId = extractUserIdFromResponse(response);
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (userId.equals("12345")) {
            System.out.println("Special user detected");
        }
    }

    public void bad_case_3() throws Exception {
        // OkHttp client example
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/product")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            String productId = extractProductId(response.body().string());
            
            // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            if (productId.equals("premium")) {
                System.out.println("Premium product");
            }
        }
    }

    public void bad_case_4() {
        // AWS S3 SDK example
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        S3Object object = s3Client.getObject("mybucket", "config.txt");
        String configContent = readInputStream(object.getObjectContent());
        String apiKey = parseApiKey(configContent);
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (apiKey.equals("default-key")) {
            System.out.println("Using default API key");
        }
    }

    public void bad_case_5() throws Exception {
        // Retrofit API client example
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        
        ApiService service = retrofit.create(ApiService.class);
        Call<UserResponse> call = service.getUser("123");
        UserResponse user = call.execute().body();
        String role = user.getRole();
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (role.equals("manager")) {
            System.out.println("User is a manager");
        }
    }

    public void bad_case_6() throws Exception {
        // Jackson JSON processing example
        ObjectMapper mapper = new ObjectMapper();
        String jsonResponse = fetchJsonFromApi("https://api.example.com/settings");
        Settings settings = mapper.readValue(jsonResponse, Settings.class);
        String theme = settings.getTheme();
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (theme.equals("dark")) {
            System.out.println("Dark theme enabled");
        }
    }

    public void bad_case_7() throws Exception {
        // JSoup HTML parsing example
        Document doc = Jsoup.connect("https://example.com/profile").get();
        String userStatus = doc.select("span.status").text();
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (userStatus.equals("online")) {
            System.out.println("User is online");
        }
    }

    public void bad_case_8() throws Exception {
        // Apache Commons Exec example
        CommandLine cmdLine = CommandLine.parse("git status");
        DefaultExecutor executor = new DefaultExecutor();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        executor.setStreamHandler(new PumpStreamHandler(outputStream));
        executor.execute(cmdLine);
        String output = outputStream.toString();
        String branchName = extractBranchName(output);
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (branchName.equals("master")) {
            System.out.println("On master branch");
        }
    }

    public void bad_case_9() throws Exception {
        // JSch SSH client example
        JSch jsch = new JSch();
        Session session = jsch.getSession("username", "hostname", 22);
        session.setPassword("password");
        session.connect();
        
        Channel channel = session.openChannel("exec");
        ((ChannelExec)channel).setCommand("hostname");
        
        InputStream in = channel.getInputStream();
        channel.connect();
        String hostname = readInputStream(in);
        channel.disconnect();
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (hostname.equals("prod-server")) {
            System.out.println("Connected to production server");
        }
    }

    public void bad_case_10() {
        // AWS Lambda SDK example
        LambdaClient lambdaClient = LambdaClient.builder().build();
        InvokeRequest request = InvokeRequest.builder()
            .functionName("getEnvironment")
            .build();
        
        String result = new String(lambdaClient.invoke(request).payload().asByteArray());
        String environment = parseEnvironment(result);
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (environment.equals("production")) {
            System.out.println("Running in production");
        }
    }

    public void bad_case_11() {
        // Azure Blob Storage SDK example
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
        
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("config");
        String configContent = downloadBlobContent(containerClient, "settings.txt");
        String region = parseRegion(configContent);
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (region.equals("us-west")) {
            System.out.println("Using US West region");
        }
    }

    public void bad_case_12() {
        // Log4j logging example
        Logger logger = LogManager.getLogger(StringComparisonVulnerabilities.class);
        String logLevel = fetchLogLevelFromApi("https://api.example.com/logging");
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (logLevel.equals("DEBUG")) {
            logger.debug("Debug logging enabled");
        }
    }

    public void bad_case_13() {
        // Hibernate ORM example
        SessionFactory sessionFactory = getSessionFactory();
        org.hibernate.Session session = sessionFactory.openSession();
        Query<User> query = session.createQuery("from User where id = :id", User.class);
        query.setParameter("id", 1);
        User user = query.uniqueResult();
        String userType = user.getType();
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (userType.equals("admin")) {
            System.out.println("Admin user found");
        }
    }

    public void bad_case_14() throws Exception {
        // Google Drive API example
        Drive driveService = new Drive.Builder(
            GoogleNetHttpTransport.newTrustedTransport(),
            JacksonFactory.getDefaultInstance(),
            getCredentials())
            .build();
        
        List<File> files = driveService.files().list().execute().getFiles();
        String fileName = files.isEmpty() ? null : files.get(0).getName();
        
        // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
        if (fileName.equals("important.txt")) {
            System.out.println("Important file found");
        }
    }

    public void bad_case_15() {
        // Kafka consumer example
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("group.id", "test");
        props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
        consumer.subscribe(Arrays.asList("test-topic"));
        
        ConsumerRecords<String, String> records = consumer.poll(100);
        for (ConsumerRecord<String, String> record : records) {
            String value = record.value();
            
            // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            if (value.equals("SHUTDOWN")) {
                System.out.println("Shutdown command received");
            }
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) {
        // Spring MVC web framework example - safe version
        String username = request.getParameter("username");
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if ("admin".equals(username)) {
            System.out.println("Admin user detected");
        }
    }

    public void good_case_2() throws Exception {
        // Apache HttpClient example - safe version
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/user");
        String response = EntityUtils.toString(httpClient.execute(request).getEntity());
        String userId = extractUserIdFromResponse(response);
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if ("12345".equals(userId)) {
            System.out.println("Special user detected");
        }
    }

    public void good_case_3() throws Exception {
        // OkHttp client example - safe version
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/product")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            String productId = extractProductId(response.body().string());
            
            // ok: java-avoid-invoking-string-comparison-method-with-null-string
            if ("premium".equals(productId)) {
                System.out.println("Premium product");
            }
        }
    }

    public void good_case_4() {
        // AWS S3 SDK example - safe version
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        S3Object object = s3Client.getObject("mybucket", "config.txt");
        String configContent = readInputStream(object.getObjectContent());
        String apiKey = parseApiKey(configContent);
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if ("default-key".equals(apiKey)) {
            System.out.println("Using default API key");
        }
    }

    public void good_case_5() throws Exception {
        // Retrofit API client example - safe version
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        
        ApiService service = retrofit.create(ApiService.class);
        Call<UserResponse> call = service.getUser("123");
        UserResponse user = call.execute().body();
        String role = user.getRole();
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if ("manager".equals(role)) {
            System.out.println("User is a manager");
        }
    }

    public void good_case_6() throws Exception {
        // Jackson JSON processing example - safe version
        ObjectMapper mapper = new ObjectMapper();
        String jsonResponse = fetchJsonFromApi("https://api.example.com/settings");
        Settings settings = mapper.readValue(jsonResponse, Settings.class);
        String theme = settings.getTheme();
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if (theme != null && theme.equals("dark")) {
            System.out.println("Dark theme enabled");
        }
    }

    public void good_case_7() throws Exception {
        // JSoup HTML parsing example - safe version
        Document doc = Jsoup.connect("https://example.com/profile").get();
        String userStatus = doc.select("span.status").text();
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if (StringUtils.equals(userStatus, "online")) {
            System.out.println("User is online");
        }
    }

    public void good_case_8() throws Exception {
        // Apache Commons Exec example - safe version
        CommandLine cmdLine = CommandLine.parse("git status");
        DefaultExecutor executor = new DefaultExecutor();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        executor.setStreamHandler(new PumpStreamHandler(outputStream));
        executor.execute(cmdLine);
        String output = outputStream.toString();
        String branchName = extractBranchName(output);
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if (Objects.equals(branchName, "master")) {
            System.out.println("On master branch");
        }
    }

    public void good_case_9() throws Exception {
        // JSch SSH client example - safe version
        JSch jsch = new JSch();
        Session session = jsch.getSession("username", "hostname", 22);
        session.setPassword("password");
        session.connect();
        
        Channel channel = session.openChannel("exec");
        ((ChannelExec)channel).setCommand("hostname");
        
        InputStream in = channel.getInputStream();
        channel.connect();
        String hostname = readInputStream(in);
        channel.disconnect();
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if (hostname != null && hostname.equals("prod-server")) {
            System.out.println("Connected to production server");
        }
    }

    public void good_case_10() {
        // AWS Lambda SDK example - safe version
        LambdaClient lambdaClient = LambdaClient.builder().build();
        InvokeRequest request = InvokeRequest.builder()
            .functionName("getEnvironment")
            .build();
        
        String result = new String(lambdaClient.invoke(request).payload().asByteArray());
        String environment = parseEnvironment(result);
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if (environment != null && environment.equals("production")) {
            System.out.println("Running in production");
        }
    }

    public void good_case_11() {
        // Azure Blob Storage SDK example - safe version
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
        
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("config");
        String configContent = downloadBlobContent(containerClient, "settings.txt");
        String region = parseRegion(configContent);
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if ("us-west".equals(region)) {
            System.out.println("Using US West region");
        }
    }

    public void good_case_12() {
        // Log4j logging example - safe version
        Logger logger = LogManager.getLogger(StringComparisonVulnerabilities.class);
        String logLevel = fetchLogLevelFromApi("https://api.example.com/logging");
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if (logLevel != null && "DEBUG".equals(logLevel)) {
            logger.debug("Debug logging enabled");
        }
    }

    public void good_case_13() {
        // Hibernate ORM example - safe version
        SessionFactory sessionFactory = getSessionFactory();
        org.hibernate.Session session = sessionFactory.openSession();
        Query<User> query = session.createQuery("from User where id = :id", User.class);
        query.setParameter("id", 1);
        User user = query.uniqueResult();
        String userType = user.getType();
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if (userType != null && userType.equals("admin")) {
            System.out.println("Admin user found");
        }
    }

    public void good_case_14() throws Exception {
        // Google Drive API example - safe version
        Drive driveService = new Drive.Builder(
            GoogleNetHttpTransport.newTrustedTransport(),
            JacksonFactory.getDefaultInstance(),
            getCredentials())
            .build();
        
        List<File> files = driveService.files().list().execute().getFiles();
        String fileName = files.isEmpty() ? null : files.get(0).getName();
        
        // ok: java-avoid-invoking-string-comparison-method-with-null-string
        if (fileName != null && fileName.equals("important.txt")) {
            System.out.println("Important file found");
        }
    }

    public void good_case_15() {
        // Kafka consumer example - safe version
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("group.id", "test");
        props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
        consumer.subscribe(Arrays.asList("test-topic"));
        
        ConsumerRecords<String, String> records = consumer.poll(100);
        for (ConsumerRecord<String, String> record : records) {
            String value = record.value();
            
            // ok: java-avoid-invoking-string-comparison-method-with-null-string
            if ("SHUTDOWN".equals(value)) {
                System.out.println("Shutdown command received");
            }
        }
    }

    // Helper methods (implementations not shown for brevity)
    private String extractUserIdFromResponse(String response) { return null; }
    private String extractProductId(String responseBody) { return null; }
    private String readInputStream(InputStream is) { return null; }
    private String parseApiKey(String content) { return null; }
    private String fetchJsonFromApi(String url) { return null; }
    private Settings getSessionFactory() { return null; }
    private String parseEnvironment(String result) { return null; }
    private String downloadBlobContent(BlobContainerClient client, String blobName) { return null; }
    private String parseRegion(String content) { return null; }
    private String fetchLogLevelFromApi(String url) { return null; }
    private Object getCredentials() { return null; }
    private String extractBranchName(String output) { return null; }

    // Mock classes for compilation
    private interface ApiService {
        Call<UserResponse> getUser(String id);
    }
    
    private class UserResponse {
        public String getRole() { return null; }
    }
    
    private class Settings {
        public String getTheme() { return null; }
    }
    
    private class User {
        public String getType() { return null; }
    }
}
// {/fact}