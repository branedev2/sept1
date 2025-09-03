import java.io.*;
import java.net.*;
import java.util.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.validation.*;
import org.springframework.validation.annotation.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.*;
import org.apache.commons.exec.*;
import javax.validation.constraints.*;
import javax.validation.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import com.fasterxml.jackson.databind.*;
import org.apache.commons.io.*;
import org.apache.commons.lang3.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.*;
import org.hibernate.validator.constraints.*;
import org.hibernate.*;
import org.hibernate.validator.*;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import io.vertx.core.*;
import io.vertx.core.http.*;
import io.vertx.ext.web.*;
import io.vertx.ext.web.handler.*;
import io.micronaut.http.*;
import io.micronaut.http.annotation.*;
import io.micronaut.validation.*;
import io.javalin.*;
import io.javalin.http.*;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import org.apache.commons.cli.*;
import com.google.cloud.storage.*;
import org.apache.logging.log4j.*;
import org.apache.commons.configuration2.*;
import org.apache.commons.net.ftp.*;
import com.jcraft.jsch.*;
import org.apache.commons.vfs2.*;

// Security Issue: Public method parameters should be validated to prevent nullness, unexpected, and malicious values

// True Positive Examples (Vulnerable/Insecure Code)

public class InputValidationExamples {

    // Spring Web MVC example - no validation
    @Controller
    public class bad_case_1 {
        @PostMapping("/user")
        public String createUser(HttpServletRequest request) {
            // ruleid: java-inputvalidation-v1
            String username = request.getParameter("username");
            String email = request.getParameter("email");
            
            // Using parameters without validation
            return "User created: " + username + " with email: " + email;
        }
    }

    // Apache HttpClient example - no validation
    public class bad_case_2 {
        public void fetchExternalResource(HttpServletRequest request) throws Exception {
            // ruleid: java-inputvalidation-v1
            String url = request.getParameter("resourceUrl");
            
            HttpGet httpGet = new HttpGet(url); // Potential SSRF vulnerability
            CloseableHttpClient httpClient = HttpClients.createDefault();
            httpClient.execute(httpGet);
        }
    }

    // AWS SDK example - no validation
    public class bad_case_3 {
        public void downloadS3Object(HttpServletRequest request) {
            // ruleid: java-inputvalidation-v1
            String bucketName = request.getParameter("bucket");
            String objectKey = request.getParameter("key");
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            S3Object s3Object = s3Client.getObject(bucketName, objectKey);
            // Process the object without validating input parameters
        }
    }

    // Apache Commons Exec example - no validation
    public class bad_case_4 {
        public void executeCommand(HttpServletRequest request) throws Exception {
            // ruleid: java-inputvalidation-v1
            String command = request.getParameter("cmd");
            
            CommandLine cmdLine = CommandLine.parse(command);
            DefaultExecutor executor = new DefaultExecutor();
            executor.execute(cmdLine); // Command injection vulnerability
        }
    }

    // OkHttp example - no validation
    public class bad_case_5 {
        public void makeHttpRequest(HttpServletRequest request) throws Exception {
            // ruleid: java-inputvalidation-v1
            String url = request.getParameter("targetUrl");
            
            OkHttpClient client = new OkHttpClient();
            Request okRequest = new Request.Builder()
                .url(url) // Potential SSRF vulnerability
                .build();
            client.newCall(okRequest).execute();
        }
    }

    // Jackson ObjectMapper example - no validation
    public class bad_case_6 {
        public void deserializeJson(HttpServletRequest request) throws Exception {
            // ruleid: java-inputvalidation-v1
            String json = request.getParameter("jsonData");
            
            ObjectMapper mapper = new ObjectMapper();
            Object obj = mapper.readValue(json, Object.class); // Potential deserialization vulnerability
        }
    }

    // JDBC example - no validation
    public class bad_case_7 {
        public void queryDatabase(HttpServletRequest request) throws Exception {
            // ruleid: java-inputvalidation-v1
            String userId = request.getParameter("id");
            
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId); // SQL injection vulnerability
        }
    }

    // Apache Commons VFS example - no validation
    public class bad_case_8 {
        public void accessFile(HttpServletRequest request) throws Exception {
            // ruleid: java-inputvalidation-v1
            String filePath = request.getParameter("path");
            
            FileSystemManager fsManager = VFS.getManager();
            FileObject file = fsManager.resolveFile(filePath); // Path traversal vulnerability
            // Process file without validation
        }
    }

    // JSch (SSH) example - no validation
    public class bad_case_9 {
        public void sshConnect(HttpServletRequest request) throws Exception {
            // ruleid: java-inputvalidation-v1
            String host = request.getParameter("host");
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            
            JSch jsch = new JSch();
            Session session = jsch.getSession(username, host, 22);
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(); // Potential SSH injection vulnerability
        }
    }

    // Apache FTP Client example - no validation
    public class bad_case_10 {
        public void ftpDownload(HttpServletRequest request) throws Exception {
            // ruleid: java-inputvalidation-v1
            String server = request.getParameter("server");
            String filePath = request.getParameter("filePath");
            
            FTPClient ftpClient = new FTPClient();
            ftpClient.connect(server);
            ftpClient.login("anonymous", "");
            InputStream inputStream = ftpClient.retrieveFileStream(filePath); // Path traversal vulnerability
        }
    }

    // Google Cloud Storage example - no validation
    public class bad_case_11 {
        public void accessGcsObject(HttpServletRequest request) {
            // ruleid: java-inputvalidation-v1
            String bucketName = request.getParameter("bucket");
            String objectName = request.getParameter("object");
            
            Storage storage = StorageOptions.getDefaultInstance().getService();
            BlobId blobId = BlobId.of(bucketName, objectName);
            Blob blob = storage.get(blobId); // Accessing storage without validation
        }
    }

    // Azure Blob Storage example - no validation
    public class bad_case_12 {
        public void downloadBlobContent(HttpServletRequest request) {
            // ruleid: java-inputvalidation-v1
            String containerName = request.getParameter("container");
            String blobName = request.getParameter("blob");
            
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
            BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);
            BlobClient blobClient = containerClient.getBlobClient(blobName);
            // Download blob without validation
        }
    }

    // Apache Commons CLI example - no validation
    public class bad_case_13 {
        public void processCliArguments(HttpServletRequest request) {
            // ruleid: java-inputvalidation-v1
            String args = request.getParameter("arguments");
            String[] argsArray = args.split(" ");
            
            Options options = new Options();
            options.addOption("f", "file", true, "File to process");
            CommandLineParser parser = new DefaultParser();
            try {
                CommandLine cmd = parser.parse(options, argsArray);
                String filePath = cmd.getOptionValue("f");
                // Process file path without validation
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Log4j example - no validation
    public class bad_case_14 {
        private static final Logger logger = LogManager.getLogger(bad_case_14.class);
        
        public void logUserActivity(HttpServletRequest request) {
            // ruleid: java-inputvalidation-v1
            String username = request.getParameter("username");
            String action = request.getParameter("action");
            
            logger.info("User {} performed action: {}", username, action); // Log injection vulnerability
        }
    }

    // JAX-RS example - no validation
    @Path("/api")
    public class bad_case_15 {
        @GET
        @Path("/resource/{id}")
        public Response getResource(@PathParam("id") String resourceId, @QueryParam("format") String format) {
            // ruleid: java-inputvalidation-v1
            // No validation of resourceId or format
            return Response.ok("Resource: " + resourceId + " in format: " + format).build();
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Spring Web MVC example - with validation
    @Controller
    public class good_case_1 {
        @PostMapping("/user")
        public String createUser(@Valid @ModelAttribute UserForm userForm, BindingResult bindingResult) {
            // ok: java-inputvalidation-v1
            if (bindingResult.hasErrors()) {
                return "userForm";
            }
            
            // Process validated input
            return "User created: " + userForm.getUsername() + " with email: " + userForm.getEmail();
        }
        
        public class UserForm {
            @NotBlank(message = "Username is required")
            @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
            private String username;
            
            @NotBlank(message = "Email is required")
            @Email(message = "Email should be valid")
            private String email;
            
            // Getters and setters
            public String getUsername() { return username; }
            public void setUsername(String username) { this.username = username; }
            public String getEmail() { return email; }
            public void setEmail(String email) { this.email = email; }
        }
    }

    // Apache HttpClient example - with validation
    public class good_case_2 {
        public void fetchExternalResource(HttpServletRequest request) throws Exception {
            String rawUrl = request.getParameter("resourceUrl");
            
            // ok: java-inputvalidation-v1
            if (rawUrl == null || rawUrl.isEmpty()) {
                throw new IllegalArgumentException("Resource URL cannot be empty");
            }
            
            // Validate URL format
            try {
                URL url = new URL(rawUrl);
                // Whitelist allowed domains
                if (!isAllowedDomain(url.getHost())) {
                    throw new IllegalArgumentException("Domain not allowed");
                }
                
                HttpGet httpGet = new HttpGet(url.toString());
                CloseableHttpClient httpClient = HttpClients.createDefault();
                httpClient.execute(httpGet);
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("Invalid URL format", e);
            }
        }
        
        private boolean isAllowedDomain(String host) {
            List<String> allowedDomains = Arrays.asList("api.example.com", "data.example.org");
            return allowedDomains.contains(host);
        }
    }

    // AWS SDK example - with validation
    public class good_case_3 {
        public void downloadS3Object(HttpServletRequest request) {
            String bucketName = request.getParameter("bucket");
            String objectKey = request.getParameter("key");
            
            // ok: java-inputvalidation-v1
            // Validate bucket name
            if (bucketName == null || !bucketName.matches("^[a-z0-9.-]{3,63}$")) {
                throw new IllegalArgumentException("Invalid bucket name format");
            }
            
            // Validate object key
            if (objectKey == null || objectKey.isEmpty() || objectKey.contains("../")) {
                throw new IllegalArgumentException("Invalid object key");
            }
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            S3Object s3Object = s3Client.getObject(bucketName, objectKey);
            // Process the validated object
        }
    }

    // Apache Commons Exec example - with validation
    public class good_case_4 {
        public void executeCommand(HttpServletRequest request) throws Exception {
            String command = request.getParameter("cmd");
            
            // ok: java-inputvalidation-v1
            // Validate command against whitelist
            List<String> allowedCommands = Arrays.asList("ls", "dir", "echo");
            if (command == null || !allowedCommands.contains(command)) {
                throw new IllegalArgumentException("Command not allowed");
            }
            
            CommandLine cmdLine = CommandLine.parse(command);
            DefaultExecutor executor = new DefaultExecutor();
            executor.execute(cmdLine);
        }
    }

    // OkHttp example - with validation
    public class good_case_5 {
        public void makeHttpRequest(HttpServletRequest request) throws Exception {
            String rawUrl = request.getParameter("targetUrl");
            
            // ok: java-inputvalidation-v1
            // Validate URL
            if (rawUrl == null || rawUrl.isEmpty()) {
                throw new IllegalArgumentException("URL cannot be empty");
            }
            
            try {
                URL url = new URL(rawUrl);
                // Validate protocol (only allow HTTPS)
                if (!"https".equals(url.getProtocol())) {
                    throw new IllegalArgumentException("Only HTTPS protocol is allowed");
                }
                
                // Validate domain against whitelist
                if (!isAllowedDomain(url.getHost())) {
                    throw new IllegalArgumentException("Domain not allowed");
                }
                
                OkHttpClient client = new OkHttpClient();
                Request okRequest = new Request.Builder()
                    .url(url.toString())
                    .build();
                client.newCall(okRequest).execute();
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("Invalid URL format", e);
            }
        }
        
        private boolean isAllowedDomain(String host) {
            List<String> allowedDomains = Arrays.asList("api.example.com", "data.example.org");
            return allowedDomains.contains(host);
        }
    }

    // Jackson ObjectMapper example - with validation
    public class good_case_6 {
        public void deserializeJson(HttpServletRequest request) throws Exception {
            String json = request.getParameter("jsonData");
            
            // ok: java-inputvalidation-v1
            // Validate JSON input
            if (json == null || json.isEmpty()) {
                throw new IllegalArgumentException("JSON data cannot be empty");
            }
            
            // Validate JSON structure before deserialization
            try {
                ObjectMapper mapper = new ObjectMapper();
                // Disable features that can lead to security issues
                mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NONE);
                
                // Use specific class instead of Object.class
                UserData userData = mapper.readValue(json, UserData.class);
                // Further validate deserialized object
                if (!userData.isValid()) {
                    throw new IllegalArgumentException("Invalid user data");
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid JSON format", e);
            }
        }
        
        public class UserData {
            private String name;
            private String email;
            
            public boolean isValid() {
                return name != null && !name.isEmpty() && 
                       email != null && email.matches("^[A-Za-z0-9+_.-]+@(.+)$");
            }
            
            // Getters and setters
            public String getName() { return name; }
            public void setName(String name) { this.name = name; }
            public String getEmail() { return email; }
            public void setEmail(String email) { this.email = email; }
        }
    }

    // JDBC example - with validation
    public class good_case_7 {
        public void queryDatabase(HttpServletRequest request) throws Exception {
            String userIdParam = request.getParameter("id");
            
            // ok: java-inputvalidation-v1
            // Validate user ID
            if (userIdParam == null || !userIdParam.matches("^\\d+$")) {
                throw new IllegalArgumentException("User ID must be a number");
            }
            
            int userId = Integer.parseInt(userIdParam);
            
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
            // Use prepared statement to prevent SQL injection
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
        }
    }

    // Apache Commons VFS example - with validation
    public class good_case_8 {
        public void accessFile(HttpServletRequest request) throws Exception {
            String filePath = request.getParameter("path");
            
            // ok: java-inputvalidation-v1
            // Validate file path
            if (filePath == null || filePath.isEmpty()) {
                throw new IllegalArgumentException("File path cannot be empty");
            }
            
            // Prevent path traversal
            if (filePath.contains("..") || filePath.contains("~") || !filePath.startsWith("/safe/dir/")) {
                throw new IllegalArgumentException("Invalid file path");
            }
            
            FileSystemManager fsManager = VFS.getManager();
            FileObject file = fsManager.resolveFile("file:///safe/dir/" + filePath);
            // Process validated file
        }
    }

    // JSch (SSH) example - with validation
    public class good_case_9 {
        public void sshConnect(HttpServletRequest request) throws Exception {
            String host = request.getParameter("host");
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            
            // ok: java-inputvalidation-v1
            // Validate host
            if (host == null || !isAllowedHost(host)) {
                throw new IllegalArgumentException("Invalid or disallowed host");
            }
            
            // Validate username
            if (username == null || !username.matches("^[a-zA-Z0-9_-]{3,20}$")) {
                throw new IllegalArgumentException("Invalid username format");
            }
            
            // Validate password
            if (password == null || password.length() < 8) {
                throw new IllegalArgumentException("Password too short");
            }
            
            JSch jsch = new JSch();
            Session session = jsch.getSession(username, host, 22);
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "yes");
            session.connect();
        }
        
        private boolean isAllowedHost(String host) {
            List<String> allowedHosts = Arrays.asList("server1.example.com", "server2.example.com");
            return allowedHosts.contains(host);
        }
    }

    // Apache FTP Client example - with validation
    public class good_case_10 {
        public void ftpDownload(HttpServletRequest request) throws Exception {
            String server = request.getParameter("server");
            String filePath = request.getParameter("filePath");
            
            // ok: java-inputvalidation-v1
            // Validate server
            if (server == null || !isAllowedFtpServer(server)) {
                throw new IllegalArgumentException("Invalid or disallowed FTP server");
            }
            
            // Validate file path
            if (filePath == null || filePath.isEmpty() || 
                filePath.contains("..") || !filePath.matches("^[a-zA-Z0-9/_.-]+$")) {
                throw new IllegalArgumentException("Invalid file path");
            }
            
            FTPClient ftpClient = new FTPClient();
            ftpClient.connect(server);
            ftpClient.login("anonymous", "");
            InputStream inputStream = ftpClient.retrieveFileStream(filePath);
        }
        
        private boolean isAllowedFtpServer(String server) {
            List<String> allowedServers = Arrays.asList("ftp.example.com", "files.example.org");
            return allowedServers.contains(server);
        }
    }

    // Google Cloud Storage example - with validation
    public class good_case_11 {
        public void accessGcsObject(HttpServletRequest request) {
            String bucketName = request.getParameter("bucket");
            String objectName = request.getParameter("object");
            
            // ok: java-inputvalidation-v1
            // Validate bucket name
            if (bucketName == null || !bucketName.matches("^[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]$")) {
                throw new IllegalArgumentException("Invalid bucket name format");
            }
            
            // Validate object name
            if (objectName == null || objectName.isEmpty() || objectName.contains("../")) {
                throw new IllegalArgumentException("Invalid object name");
            }
            
            // Check if bucket is in allowed list
            List<String> allowedBuckets = Arrays.asList("app-assets", "app-data");
            if (!allowedBuckets.contains(bucketName)) {
                throw new IllegalArgumentException("Access to bucket not allowed");
            }
            
            Storage storage = StorageOptions.getDefaultInstance().getService();
            BlobId blobId = BlobId.of(bucketName, objectName);
            Blob blob = storage.get(blobId);
        }
    }

    // Azure Blob Storage example - with validation
    public class good_case_12 {
        public void downloadBlobContent(HttpServletRequest request) {
            String containerName = request.getParameter("container");
            String blobName = request.getParameter("blob");
            
            // ok: java-inputvalidation-v1
            // Validate container name
            if (containerName == null || !containerName.matches("^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$")) {
                throw new IllegalArgumentException("Invalid container name format");
            }
            
            // Validate blob name
            if (blobName == null || blobName.isEmpty() || blobName.contains("../")) {
                throw new IllegalArgumentException("Invalid blob name");
            }
            
            // Check if container is in allowed list
            List<String> allowedContainers = Arrays.asList("public-assets", "user-uploads");
            if (!allowedContainers.contains(containerName)) {
                throw new IllegalArgumentException("Access to container not allowed");
            }
            
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
            BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);
            BlobClient blobClient = containerClient.getBlobClient(blobName);
            // Download validated blob
        }
    }

    // Apache Commons CLI example - with validation
    public class good_case_13 {
        public void processCliArguments(HttpServletRequest request) {
            String args = request.getParameter("arguments");
            
            // ok: java-inputvalidation-v1
            // Validate arguments
            if (args == null || args.isEmpty()) {
                throw new IllegalArgumentException("Arguments cannot be empty");
            }
            
            // Sanitize and validate arguments
            String sanitizedArgs = args.replaceAll("[;&|]", "");
            if (!sanitizedArgs.matches("^[a-zA-Z0-9\\s-=_]+$")) {
                throw new IllegalArgumentException("Arguments contain invalid characters");
            }
            
            String[] argsArray = sanitizedArgs.split(" ");
            
            Options options = new Options();
            options.addOption("f", "file", true, "File to process");
            CommandLineParser parser = new DefaultParser();
            try {
                CommandLine cmd = parser.parse(options, argsArray);
                String filePath = cmd.getOptionValue("f");
                
                // Validate file path if present
                if (filePath != null && !filePath.matches("^[a-zA-Z0-9/_.-]+$")) {
                    throw new IllegalArgumentException("Invalid file path");
                }
                // Process validated arguments
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid arguments", e);
            }
        }
    }

    // Log4j example - with validation
    public class good_case_14 {
        private static final Logger logger = LogManager.getLogger(good_case_14.class);
        
        public void logUserActivity(HttpServletRequest request) {
            String username = request.getParameter("username");
            String action = request.getParameter("action");
            
            // ok: java-inputvalidation-v1
            // Validate username
            if (username == null || !username.matches("^[a-zA-Z0-9_]{3,20}$")) {
                username = "unknown_user";
            }
            
            // Validate action
            List<String> validActions = Arrays.asList("login", "logout", "view", "edit", "delete");
            if (action == null || !validActions.contains(action)) {
                action = "unknown_action";
            }
            
            // Sanitize inputs for logging
            String sanitizedUsername = username.replaceAll("[\\r\\n]", "");
            String sanitizedAction = action.replaceAll("[\\r\\n]", "");
            
            logger.info("User {} performed action: {}", sanitizedUsername, sanitizedAction);
        }
    }

    // JAX-RS example - with validation
    @Path("/api")
    public class good_case_15 {
        @GET
        @Path("/resource/{id}")
        public Response getResource(
                @PathParam("id") @NotNull @Pattern(regexp = "^[a-zA-Z0-9-]+$") String resourceId,
                @QueryParam("format") @Pattern(regexp = "^(json|xml|text)$", message = "Format must be json, xml, or text") String format) {
            
            // ok: java-inputvalidation-v1
            // Additional validation if needed
            if (resourceId.length() > 50) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Resource ID too long").build();
            }
            
            // Use default format if not specified or invalid
            if (format == null) {
                format = "json";
            }
            
            return Response.ok("Resource: " + resourceId + " in format: " + format).build();
        }
    }
}