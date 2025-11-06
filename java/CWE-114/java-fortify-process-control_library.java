import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FileUtils;
import org.springframework.web.bind.annotation.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import spark.Request;
import spark.Response;
import spark.Route;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import org.apache.http.HttpRequest;
import okhttp3.OkHttpClient;
import retrofit2.Retrofit;
import com.google.gson.Gson;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.apache.commons.net.ftp.FTPClient;
import software.amazon.awssdk.services.s3.S3Client;
import com.azure.storage.blob.BlobServiceClient;
import com.google.cloud.storage.Storage;

// Security Issue: Using System.loadLibrary() without specifying an absolute path could lead to loading a malicious library

// True Positive Examples (Vulnerable/Insecure Code)
class VulnerableExamples {
    
// {fact rule=assembly-path-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Spring Web MVC example
        String libraryName = request.getParameter("lib");
        if (libraryName != null && !libraryName.isEmpty()) {
            try {
                // ruleid: java-fortify-process-control
                System.loadLibrary(libraryName);
                // Process using the loaded library
            } catch (UnsatisfiedLinkError e) {
                System.err.println("Failed to load library: " + e.getMessage());
            }
        }
    }
    
    public void bad_case_2() {
        // Spark framework example
        spark.Spark.get("/load-library", new Route() {
            @Override
            public Object handle(Request request, Response response) {
                String libraryName = request.queryParams("libName");
                try {
                    // ruleid: java-fortify-process-control
                    System.loadLibrary(libraryName);
                    return "Library loaded successfully";
                } catch (UnsatisfiedLinkError e) {
                    return "Error loading library: " + e.getMessage();
                }
            }
        });
    }
    
    public void bad_case_3() {
        // Javalin framework example
        io.javalin.Javalin app = io.javalin.Javalin.create();
        app.get("/native-lib", new Handler() {
            @Override
            public void handle(Context ctx) {
                String libName = ctx.queryParam("name");
                try {
                    // ruleid: java-fortify-process-control
                    System.loadLibrary(libName);
                    ctx.result("Library loaded successfully");
                } catch (Exception e) {
                    ctx.result("Error: " + e.getMessage());
                }
            }
        });
    }
    
    public void bad_case_4() {
        // Vert.x framework example
        io.vertx.ext.web.Router router = io.vertx.ext.web.Router.router(null);
        router.get("/load").handler(new io.vertx.core.Handler<RoutingContext>() {
            @Override
            public void handle(RoutingContext ctx) {
                HttpServerRequest request = ctx.request();
                String libName = request.getParam("lib");
                try {
                    // ruleid: java-fortify-process-control
                    System.loadLibrary(libName);
                    ctx.response().end("Library loaded");
                } catch (Exception e) {
                    ctx.response().end("Error: " + e.getMessage());
                }
            }
        });
    }
    
    public class bad_case_5 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        // AWS Lambda example
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            String libName = input.getQueryStringParameters().get("library");
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            
            try {
                // ruleid: java-fortify-process-control
                System.loadLibrary(libName);
                response.setStatusCode(200);
                response.setBody("Library loaded successfully");
            } catch (Exception e) {
                response.setStatusCode(500);
                response.setBody("Error: " + e.getMessage());
            }
            
            return response;
        }
    }
    
    @RestController
    public class bad_case_6 {
        // Spring Boot REST controller example
        @GetMapping("/api/load-native")
        public String loadNativeLibrary(@RequestParam String libName) {
            try {
                // ruleid: java-fortify-process-control
                System.loadLibrary(libName);
                return "Library loaded: " + libName;
            } catch (UnsatisfiedLinkError e) {
                return "Failed to load library: " + e.getMessage();
            }
        }
    }
    
    public void bad_case_7() {
        // OkHttp client example
        OkHttpClient client = new OkHttpClient();
        okhttp3.Request request = new okhttp3.Request.Builder()
            .url("https://example.com/api/library-name")
            .build();
            
        try {
            okhttp3.Response response = client.newCall(request).execute();
            String libName = response.body().string().trim();
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (IOException | UnsatisfiedLinkError e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() {
        // Retrofit API client example
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
            
        LibraryService service = retrofit.create(LibraryService.class);
        try {
            retrofit2.Response<String> response = service.getLibraryName().execute();
            if (response.isSuccessful()) {
                String libName = response.body();
                // ruleid: java-fortify-process-control
                System.loadLibrary(libName);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    interface LibraryService {
        @retrofit2.http.GET("library-name")
        retrofit2.Call<String> getLibraryName();
    }
    
    public void bad_case_9() {
        // Apache Commons Exec example
        try {
            CommandLine cmdLine = new CommandLine("curl");
            cmdLine.addArgument("https://example.com/api/lib-name");
            DefaultExecutor executor = new DefaultExecutor();
            
            // Execute command to get library name from remote server
            java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
            org.apache.commons.exec.PumpStreamHandler streamHandler = new org.apache.commons.exec.PumpStreamHandler(outputStream);
            executor.setStreamHandler(streamHandler);
            executor.execute(cmdLine);
            
            String libName = outputStream.toString().trim();
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_10() {
        // JSch SSH library example
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("user", "example.com", 22);
            session.setPassword("password");
            session.connect();
            
            com.jcraft.jsch.ChannelExec channel = (com.jcraft.jsch.ChannelExec) session.openChannel("exec");
            channel.setCommand("cat /path/to/library-name.txt");
            
            java.io.InputStream in = channel.getInputStream();
            channel.connect();
            
            byte[] tmp = new byte[1024];
            StringBuilder libName = new StringBuilder();
            while (true) {
                int i = in.read(tmp, 0, 1024);
                if (i < 0) break;
                libName.append(new String(tmp, 0, i));
            }
            
            channel.disconnect();
            session.disconnect();
            
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName.toString().trim());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        // Apache Commons Net FTP example
        FTPClient ftpClient = new FTPClient();
        try {
            ftpClient.connect("ftp.example.com");
            ftpClient.login("user", "password");
            
            java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
            ftpClient.retrieveFile("/path/to/library-name.txt", outputStream);
            
            String libName = outputStream.toString().trim();
            ftpClient.disconnect();
            
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12() {
        // AWS S3 SDK example
        try {
            S3Client s3Client = S3Client.builder().build();
            software.amazon.awssdk.services.s3.model.GetObjectRequest getObjectRequest = 
                software.amazon.awssdk.services.s3.model.GetObjectRequest.builder()
                    .bucket("my-bucket")
                    .key("library-name.txt")
                    .build();
                    
            software.amazon.awssdk.core.ResponseInputStream<software.amazon.awssdk.services.s3.model.GetObjectResponse> response = 
                s3Client.getObject(getObjectRequest);
                
            java.util.Scanner scanner = new java.util.Scanner(response).useDelimiter("\\A");
            String libName = scanner.hasNext() ? scanner.next().trim() : "";
            
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_13() {
        // Azure Blob Storage example
        try {
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
                
            String containerName = "libraries";
            String blobName = "library-name.txt";
            
            com.azure.storage.blob.BlobContainerClient containerClient = 
                blobServiceClient.getBlobContainerClient(containerName);
            com.azure.storage.blob.BlobClient blobClient = 
                containerClient.getBlobClient(blobName);
                
            java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
            blobClient.download(outputStream);
            String libName = outputStream.toString().trim();
            
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        // Google Cloud Storage example
        try {
            Storage storage = com.google.cloud.storage.StorageOptions.getDefaultInstance().getService();
            com.google.cloud.storage.Blob blob = storage.get(
                com.google.cloud.storage.BlobId.of("bucket-name", "library-name.txt"));
                
            String libName = new String(blob.getContent()).trim();
            
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_15() {
        // Jersey Client example
        try {
            javax.ws.rs.client.Client client = javax.ws.rs.client.ClientBuilder.newClient();
            String libName = client.target("https://example.com/api/library")
                .request(javax.ws.rs.core.MediaType.TEXT_PLAIN)
                .get(String.class)
                .trim();
                
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)
class SecureExamples {
    
// {fact rule=assembly-path-injection@v1.0 defects=0}
    public void good_case_1(HttpServletRequest request) {
        // Spring Web MVC example with secure library loading
        String libraryName = request.getParameter("lib");
        if (libraryName != null && !libraryName.isEmpty()) {
            try {
                // Define a secure location for libraries
                String secureLibPath = "/opt/secure/libs/" + libraryName + ".so";
                File libFile = new File(secureLibPath);
                
                // Validate the path is within the expected directory
                if (libFile.getCanonicalPath().startsWith("/opt/secure/libs/")) {
                    // ok: java-fortify-process-control
                    System.load(libFile.getAbsolutePath());
                } else {
                    throw new SecurityException("Invalid library path");
                }
            } catch (Exception e) {
                System.err.println("Failed to load library: " + e.getMessage());
            }
        }
    }
    
    public void good_case_2() {
        // Spark framework example with secure library loading
        spark.Spark.get("/load-library", new Route() {
            @Override
            public Object handle(Request request, Response response) {
                String libraryName = request.queryParams("libName");
                try {
                    // Whitelist approach for allowed libraries
                    Properties allowedLibs = new Properties();
                    allowedLibs.load(getClass().getResourceAsStream("/allowed-libs.properties"));
                    
                    if (allowedLibs.containsKey(libraryName)) {
                        String fullPath = allowedLibs.getProperty(libraryName);
                        // ok: java-fortify-process-control
                        System.load(fullPath);
                        return "Library loaded successfully";
                    } else {
                        return "Library not in allowed list";
                    }
                } catch (Exception e) {
                    return "Error loading library: " + e.getMessage();
                }
            }
        });
    }
    
    public void good_case_3() {
        // Javalin framework example with secure library loading
        io.javalin.Javalin app = io.javalin.Javalin.create();
        app.get("/native-lib", new Handler() {
            @Override
            public void handle(Context ctx) {
                String libName = ctx.queryParam("name");
                try {
                    // Map of allowed libraries with their full paths
                    java.util.Map<String, String> allowedLibs = new java.util.HashMap<>();
                    allowedLibs.put("mylib1", "/usr/local/lib/mylib1.so");
                    allowedLibs.put("mylib2", "/usr/local/lib/mylib2.so");
                    
                    if (allowedLibs.containsKey(libName)) {
                        // ok: java-fortify-process-control
                        System.load(allowedLibs.get(libName));
                        ctx.result("Library loaded successfully");
                    } else {
                        ctx.result("Library not allowed");
                    }
                } catch (Exception e) {
                    ctx.result("Error: " + e.getMessage());
                }
            }
        });
    }
    
    public void good_case_4() {
        // Vert.x framework example with secure library loading
        io.vertx.ext.web.Router router = io.vertx.ext.web.Router.router(null);
        router.get("/load").handler(new io.vertx.core.Handler<RoutingContext>() {
            @Override
            public void handle(RoutingContext ctx) {
                HttpServerRequest request = ctx.request();
                String libName = request.getParam("lib");
                
                try {
                    // Use a predefined base directory for libraries
                    File libDir = new File("/opt/app/libs");
                    File libFile = new File(libDir, libName + ".so");
                    
                    // Validate the path is within the expected directory
                    if (libFile.getCanonicalPath().startsWith(libDir.getCanonicalPath())) {
                        // ok: java-fortify-process-control
                        System.load(libFile.getAbsolutePath());
                        ctx.response().end("Library loaded");
                    } else {
                        ctx.response().end("Invalid library path");
                    }
                } catch (Exception e) {
                    ctx.response().end("Error: " + e.getMessage());
                }
            }
        });
    }
    
    public class good_case_5 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        // AWS Lambda example with secure library loading
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            String libName = input.getQueryStringParameters().get("library");
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            
            try {
                // Lambda functions have a read-only filesystem except for /tmp
                // Libraries should be included in the deployment package
                String libPath = Paths.get(System.getenv("LAMBDA_TASK_ROOT"), "lib", libName + ".so").toString();
                File libFile = new File(libPath);
                
                if (libFile.exists() && libFile.getCanonicalPath().startsWith(System.getenv("LAMBDA_TASK_ROOT"))) {
                    // ok: java-fortify-process-control
                    System.load(libFile.getAbsolutePath());
                    response.setStatusCode(200);
                    response.setBody("Library loaded successfully");
                } else {
                    response.setStatusCode(400);
                    response.setBody("Library not found or invalid path");
                }
            } catch (Exception e) {
                response.setStatusCode(500);
                response.setBody("Error: " + e.getMessage());
            }
            
            return response;
        }
    }
    
    @RestController
    public class good_case_6 {
        // Spring Boot REST controller example with secure library loading
        private final java.util.Set<String> allowedLibraries = java.util.Set.of("lib1", "lib2", "lib3");
        
        @GetMapping("/api/load-native")
        public String loadNativeLibrary(@RequestParam String libName) {
            try {
                if (allowedLibraries.contains(libName)) {
                    String libPath = "/opt/myapp/native/" + libName + ".so";
                    // ok: java-fortify-process-control
                    System.load(libPath);
                    return "Library loaded: " + libName;
                } else {
                    return "Library not in allowed list";
                }
            } catch (UnsatisfiedLinkError e) {
                return "Failed to load library: " + e.getMessage();
            }
        }
    }
    
    public void good_case_7() {
        // OkHttp client example with secure library loading
        OkHttpClient client = new OkHttpClient();
        okhttp3.Request request = new okhttp3.Request.Builder()
            .url("https://example.com/api/library-name")
            .build();
            
        try {
            okhttp3.Response response = client.newCall(request).execute();
            String libName = response.body().string().trim();
            
            // Validate against a whitelist and use absolute path
            java.util.Map<String, String> validLibs = new java.util.HashMap<>();
            validLibs.put("lib1", "/usr/lib/lib1.so");
            validLibs.put("lib2", "/usr/lib/lib2.so");
            
            if (validLibs.containsKey(libName)) {
                // ok: java-fortify-process-control
                System.load(validLibs.get(libName));
            } else {
                throw new SecurityException("Requested library not in whitelist");
            }
        } catch (IOException | UnsatisfiedLinkError e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        // Retrofit API client example with secure library loading
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
            
        LibraryService service = retrofit.create(LibraryService.class);
        try {
            retrofit2.Response<String> response = service.getLibraryName().execute();
            if (response.isSuccessful()) {
                String libName = response.body();
                
                // Use a configuration file to map library names to absolute paths
                Properties libConfig = new Properties();
                libConfig.load(new java.io.FileInputStream("/etc/app/libraries.properties"));
                
                if (libConfig.containsKey(libName)) {
                    String absolutePath = libConfig.getProperty(libName);
                    // ok: java-fortify-process-control
                    System.load(absolutePath);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    interface LibraryService {
        @retrofit2.http.GET("library-name")
        retrofit2.Call<String> getLibraryName();
    }
    
    public void good_case_9() {
        // Apache Commons Exec example with secure library loading
        try {
            CommandLine cmdLine = new CommandLine("curl");
            cmdLine.addArgument("https://example.com/api/lib-name");
            DefaultExecutor executor = new DefaultExecutor();
            
            // Execute command to get library name from remote server
            java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
            org.apache.commons.exec.PumpStreamHandler streamHandler = new org.apache.commons.exec.PumpStreamHandler(outputStream);
            executor.setStreamHandler(streamHandler);
            executor.execute(cmdLine);
            
            String libName = outputStream.toString().trim();
            
            // Validate and sanitize the library name
            if (libName.matches("[a-zA-Z0-9_-]+")) {
                String absolutePath = "/opt/secure/libs/" + libName + ".so";
                File libFile = new File(absolutePath);
                
                if (libFile.exists() && libFile.getCanonicalPath().startsWith("/opt/secure/libs/")) {
                    // ok: java-fortify-process-control
                    System.load(absolutePath);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_10() {
        // JSch SSH library example with secure library loading
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("user", "example.com", 22);
            session.setPassword("password");
            session.connect();
            
            com.jcraft.jsch.ChannelExec channel = (com.jcraft.jsch.ChannelExec) session.openChannel("exec");
            channel.setCommand("cat /path/to/library-name.txt");
            
            java.io.InputStream in = channel.getInputStream();
            channel.connect();
            
            byte[] tmp = new byte[1024];
            StringBuilder libName = new StringBuilder();
            while (true) {
                int i = in.read(tmp, 0, 1024);
                if (i < 0) break;
                libName.append(new String(tmp, 0, i));
            }
            
            channel.disconnect();
            session.disconnect();
            
            // Use a secure mapping to absolute paths
            String sanitizedName = libName.toString().trim().replaceAll("[^a-zA-Z0-9_-]", "");
            String absolutePath = "/usr/local/lib/" + sanitizedName + ".so";
            
            // Verify the file exists and is in the expected directory
            File libFile = new File(absolutePath);
            if (libFile.exists() && libFile.getCanonicalPath().startsWith("/usr/local/lib/")) {
                // ok: java-fortify-process-control
                System.load(absolutePath);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11() {
        // Apache Commons Net FTP example with secure library loading
        FTPClient ftpClient = new FTPClient();
        try {
            ftpClient.connect("ftp.example.com");
            ftpClient.login("user", "password");
            
            java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
            ftpClient.retrieveFile("/path/to/library-name.txt", outputStream);
            
            String libName = outputStream.toString().trim();
            ftpClient.disconnect();
            
            // Use a predefined set of allowed libraries with absolute paths
            java.util.Map<String, String> allowedLibs = new java.util.HashMap<>();
            allowedLibs.put("lib1", "/usr/lib/lib1.so");
            allowedLibs.put("lib2", "/usr/lib/lib2.so");
            
            if (allowedLibs.containsKey(libName)) {
                // ok: java-fortify-process-control
                System.load(allowedLibs.get(libName));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12() {
        // AWS S3 SDK example with secure library loading
        try {
            S3Client s3Client = S3Client.builder().build();
            software.amazon.awssdk.services.s3.model.GetObjectRequest getObjectRequest = 
                software.amazon.awssdk.services.s3.model.GetObjectRequest.builder()
                    .bucket("my-bucket")
                    .key("library-name.txt")
                    .build();
                    
            software.amazon.awssdk.core.ResponseInputStream<software.amazon.awssdk.services.s3.model.GetObjectResponse> response = 
                s3Client.getObject(getObjectRequest);
                
            java.util.Scanner scanner = new java.util.Scanner(response).useDelimiter("\\A");
            String libName = scanner.hasNext() ? scanner.next().trim() : "";
            
            // Use a secure directory with absolute paths
            String libDir = "/opt/application/native/";
            File libFile = new File(libDir + libName + ".so");
            
            // Validate the path is within the expected directory
            if (libFile.exists() && libFile.getCanonicalPath().startsWith(libDir)) {
                // ok: java-fortify-process-control
                System.load(libFile.getAbsolutePath());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13() {
        // Azure Blob Storage example with secure library loading
        try {
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
                
            String containerName = "libraries";
            String blobName = "library-name.txt";
            
            com.azure.storage.blob.BlobContainerClient containerClient = 
                blobServiceClient.getBlobContainerClient(containerName);
            com.azure.storage.blob.BlobClient blobClient = 
                containerClient.getBlobClient(blobName);
                
            java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
            blobClient.download(outputStream);
            String libName = outputStream.toString().trim();
            
            // Use a secure validation approach
            if (libName.matches("^[a-zA-Z0-9_-]+$")) {
                // Map to predefined absolute paths
                String basePath = "/usr/lib/";
                File libFile = new File(basePath + libName + ".so");
                
                if (libFile.exists() && libFile.getCanonicalPath().startsWith(basePath)) {
                    // ok: java-fortify-process-control
                    System.load(libFile.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14() {
        // Google Cloud Storage example with secure library loading
        try {
            Storage storage = com.google.cloud.storage.StorageOptions.getDefaultInstance().getService();
            com.google.cloud.storage.Blob blob = storage.get(
                com.google.cloud.storage.BlobId.of("bucket-name", "library-name.txt"));
                
            String libName = new String(blob.getContent()).trim();
            
            // Use a configuration file to map library names to absolute paths
            java.util.Properties config = new java.util.Properties();
            config.load(new java.io.FileInputStream("/etc/app/lib-paths.properties"));
            
            if (config.containsKey(libName)) {
                String absolutePath = config.getProperty(libName);
                File libFile = new File(absolutePath);
                
                if (libFile.exists()) {
                    // ok: java-fortify-process-control
                    System.load(absolutePath);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15() {
        // Jersey Client example with secure library loading
        try {
            javax.ws.rs.client.Client client = javax.ws.rs.client.ClientBuilder.newClient();
            String libName = client.target("https://example.com/api/library")
                .request(javax.ws.rs.core.MediaType.TEXT_PLAIN)
                .get(String.class)
                .trim();
                
            // Use a secure approach with predefined library paths
            String[] allowedLibs = {"lib1", "lib2", "lib3", "lib4"};
            boolean isAllowed = false;
            
            for (String allowed : allowedLibs) {
                if (allowed.equals(libName)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (isAllowed) {
                String absolutePath = "/usr/local/lib/" + libName + ".so";
                File libFile = new File(absolutePath);
                
                if (libFile.exists() && libFile.getCanonicalPath().startsWith("/usr/local/lib/")) {
                    // ok: java-fortify-process-control
                    System.load(absolutePath);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}