import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.apache.commons.io.FileUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.commons.io.FilenameUtils;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import org.apache.commons.vfs2.*;
import org.apache.commons.vfs2.provider.local.LocalFile;
import org.apache.commons.vfs2.impl.StandardFileSystemManager;
import com.google.cloud.storage.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.commons.validator.routines.UrlValidator;
import java.net.URI;
import java.net.URL;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import retrofit2.converter.gson.GsonConverterFactory;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.Configuration;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.codec.binary.Hex;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.PathHandler;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.apache.commons.net.ftp.FTPClient;
import com.jcraft.jsch.*;

// Security Issue: Path Traversal Vulnerabilities in Java Applications

// True Positive Examples (Vulnerable/Insecure Code)

// Using Java IO with servlet request parameter
public void bad_case_1(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("file");
        // ruleid: java-path-traversal-exp
        File file = new File("/var/data/" + fileName);
        FileInputStream fis = new FileInputStream(file);
        // Read and process file...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// Using Spring MVC with path variable
@Controller
class bad_case_2 {
    @GetMapping("/download/{filename}")
    public void downloadFile(@PathVariable String filename, HttpServletResponse response) {
        try {
            String basePath = "/usr/local/tomcat/webapps/files/";
            // ruleid: java-path-traversal-exp
            File file = new File(basePath + filename);
            FileUtils.copyFile(file, response.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// Using Apache Commons VFS
public void bad_case_3(HttpServletRequest request) {
    try {
        String userFile = request.getParameter("document");
        StandardFileSystemManager manager = new StandardFileSystemManager();
        manager.init();
        
        // ruleid: java-path-traversal-exp
        FileObject fileObject = manager.resolveFile("/opt/app/documents/" + userFile);
        FileContent content = fileObject.getContent();
        // Process file content...
        manager.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Using Java NIO with query parameter
@RestController
class bad_case_4 {
    @GetMapping("/view")
    public String viewFile(@RequestParam String path) {
        try {
            // ruleid: java-path-traversal-exp
            Path filePath = Paths.get("/data/user/files/" + path);
            byte[] data = Files.readAllBytes(filePath);
            return new String(data);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}

// Using AWS S3 Client with path traversal in key
public void bad_case_5(HttpServletRequest request) {
    String userKey = request.getParameter("key");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    // ruleid: java-path-traversal-exp
    GetObjectRequest getObjectRequest = new GetObjectRequest("my-bucket", "user-files/" + userKey);
    s3Client.getObject(getObjectRequest);
}

// Using Google Cloud Storage with path traversal
public void bad_case_6(HttpServletRequest request) {
    String fileName = request.getParameter("file");
    Storage storage = StorageOptions.getDefaultInstance().getService();
    
    // ruleid: java-path-traversal-exp
    BlobId blobId = BlobId.of("my-bucket", "user-data/" + fileName);
    Blob blob = storage.get(blobId);
    // Process blob...
}

// Using Apache Hadoop FileSystem
public void bad_case_7(HttpServletRequest request) throws IOException {
    String filePath = request.getParameter("path");
    Configuration conf = new Configuration();
    FileSystem fs = FileSystem.get(conf);
    
    // ruleid: java-path-traversal-exp
    Path path = new Path("/user/hadoop/data/" + filePath);
    if (fs.exists(path)) {
        // Process file...
    }
}

// Using ZipFile with path traversal
public void bad_case_8(HttpServletRequest request) {
    try {
        String entryName = request.getParameter("entry");
        ZipFile zipFile = new ZipFile("/tmp/archive.zip");
        
        // ruleid: java-path-traversal-exp
        ZipArchiveEntry entry = zipFile.getEntry(entryName);
        InputStream inputStream = zipFile.getInputStream(entry);
        // Process input stream...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// Using FTP client with path traversal
public void bad_case_9(HttpServletRequest request) {
    String remotePath = request.getParameter("path");
    FTPClient ftpClient = new FTPClient();
    
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("user", "password");
        
        // ruleid: java-path-traversal-exp
        InputStream inputStream = ftpClient.retrieveFileStream("/public/" + remotePath);
        // Process input stream...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// Using JSch (SSH/SFTP) with path traversal
public void bad_case_10(HttpServletRequest request) {
    String remoteFile = request.getParameter("file");
    
    try {
        JSch jsch = new JSch();
        Session session = jsch.getSession("user", "example.com", 22);
        session.setPassword("password");
        session.connect();
        
        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp) channel;
        
        // ruleid: java-path-traversal-exp
        InputStream stream = sftpChannel.get("/home/user/files/" + remoteFile);
        // Process stream...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Using Jetty server handler with path traversal
public class bad_case_11 extends AbstractHandler {
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) {
        String fileName = request.getParameter("file");
        
        try {
            // ruleid: java-path-traversal-exp
            File file = new File("/var/www/html/" + fileName);
            FileInputStream fis = new FileInputStream(file);
            // Process file...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// Using Undertow server with path traversal
public void bad_case_12() {
    PathHandler handler = new PathHandler();
    handler.addExactPath("/file", exchange -> {
        String fileName = exchange.getQueryParameters().get("name").getFirst();
        
        try {
            // ruleid: java-path-traversal-exp
            File file = new File("/opt/data/" + fileName);
            exchange.getResponseSender().send(FileUtils.readFileToString(file));
        } catch (IOException e) {
            exchange.getResponseSender().send("Error: " + e.getMessage());
        }
    });
}

// Using Vert.x with path traversal
public void bad_case_13() {
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    
    router.get("/download").handler(ctx -> {
        String file = ctx.request().getParam("file");
        
        // ruleid: java-path-traversal-exp
        vertx.fileSystem().readFile("/usr/share/files/" + file, result -> {
            if (result.succeeded()) {
                ctx.response().end(result.result());
            } else {
                ctx.response().end("Error reading file");
            }
        });
    });
}

// Using Tomcat with path traversal
public void bad_case_14() throws Exception {
    Tomcat tomcat = new Tomcat();
    Context ctx = tomcat.addContext("", new File(".").getAbsolutePath());
    
    Tomcat.addServlet(ctx, "fileServlet", new HttpServlet() {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            String fileName = req.getParameter("file");
            
            // ruleid: java-path-traversal-exp
            File file = new File("/opt/tomcat/webapps/data/" + fileName);
            FileInputStream fis = new FileInputStream(file);
            // Process file...
        }
    });
    ctx.addServletMappingDecoded("/file", "fileServlet");
}

// Using OkHttp to download file with path traversal
public void bad_case_15(HttpServletRequest request) {
    String filePath = request.getParameter("path");
    OkHttpClient client = new OkHttpClient();
    
    try {
        // ruleid: java-path-traversal-exp
        File destination = new File("/tmp/downloads/" + filePath);
        Request okRequest = new Request.Builder()
            .url("https://example.com/files/download")
            .build();
        
        try (Response response = client.newCall(okRequest).execute()) {
            FileOutputStream fos = new FileOutputStream(destination);
            fos.write(response.body().bytes());
            fos.close();
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

// Using Java IO with path normalization
public void good_case_1(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("file");
        String normalizedFileName = new File(fileName).getName(); // Get just the filename, not path
        
        // ok: java-path-traversal-exp
        File file = new File("/var/data/" + normalizedFileName);
        FileInputStream fis = new FileInputStream(file);
        // Read and process file...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// Using Spring MVC with path validation
@Controller
class good_case_2 {
    @GetMapping("/download/{filename}")
    public void downloadFile(@PathVariable String filename, HttpServletResponse response) {
        try {
            // Validate filename doesn't contain path traversal sequences
            if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
                return;
            }
            
            String basePath = "/usr/local/tomcat/webapps/files/";
            // ok: java-path-traversal-exp
            File file = new File(basePath, filename); // Using two-argument constructor for safe path joining
            FileUtils.copyFile(file, response.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// Using Apache Commons VFS with path sanitization
public void good_case_3(HttpServletRequest request) {
    try {
        String userFile = request.getParameter("document");
        // Sanitize path
        userFile = FilenameUtils.getName(userFile);
        
        StandardFileSystemManager manager = new StandardFileSystemManager();
        manager.init();
        
        // ok: java-path-traversal-exp
        FileObject fileObject = manager.resolveFile(new File("/opt/app/documents", userFile).getPath());
        FileContent content = fileObject.getContent();
        // Process file content...
        manager.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Using Java NIO with path validation
@RestController
class good_case_4 {
    @GetMapping("/view")
    public String viewFile(@RequestParam String path) {
        try {
            // Validate and sanitize path
            Path requestedPath = Paths.get(path).normalize();
            Path basePath = Paths.get("/data/user/files").normalize();
            Path resolvedPath = basePath.resolve(requestedPath).normalize();
            
            // Check for path traversal
            if (!resolvedPath.startsWith(basePath)) {
                return "Access denied: Invalid path";
            }
            
            // ok: java-path-traversal-exp
            byte[] data = Files.readAllBytes(resolvedPath);
            return new String(data);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}

// Using AWS S3 Client with key validation
public void good_case_5(HttpServletRequest request) {
    String userKey = request.getParameter("key");
    
    // Validate key doesn't contain path traversal sequences
    if (userKey.contains("..") || userKey.startsWith("/")) {
        throw new IllegalArgumentException("Invalid key");
    }
    
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    // ok: java-path-traversal-exp
    GetObjectRequest getObjectRequest = new GetObjectRequest("my-bucket", "user-files/" + userKey.replaceAll("[/\\\\]", ""));
    s3Client.getObject(getObjectRequest);
}

// Using Google Cloud Storage with safe path handling
public void good_case_6(HttpServletRequest request) {
    String fileName = request.getParameter("file");
    
    // Sanitize filename
    fileName = new File(fileName).getName();
    
    Storage storage = StorageOptions.getDefaultInstance().getService();
    
    // ok: java-path-traversal-exp
    BlobId blobId = BlobId.of("my-bucket", "user-data/" + fileName);
    Blob blob = storage.get(blobId);
    // Process blob...
}

// Using Apache Hadoop FileSystem with path validation
public void good_case_7(HttpServletRequest request) throws IOException {
    String filePath = request.getParameter("path");
    
    // Validate path
    if (filePath.contains("..") || filePath.startsWith("/")) {
        throw new IllegalArgumentException("Invalid path");
    }
    
    Configuration conf = new Configuration();
    FileSystem fs = FileSystem.get(conf);
    
    // ok: java-path-traversal-exp
    Path basePath = new Path("/user/hadoop/data");
    Path fullPath = new Path(basePath, filePath);
    
    // Ensure the resolved path is within the base directory
    if (!fullPath.toString().startsWith(basePath.toString())) {
        throw new IllegalArgumentException("Path traversal attempt detected");
    }
    
    if (fs.exists(fullPath)) {
        // Process file...
    }
}

// Using ZipFile with entry validation
public void good_case_8(HttpServletRequest request) {
    try {
        String entryName = request.getParameter("entry");
        
        // Validate entry name doesn't contain path traversal sequences
        if (entryName.contains("..") || entryName.startsWith("/")) {
            throw new IllegalArgumentException("Invalid entry name");
        }
        
        ZipFile zipFile = new ZipFile("/tmp/archive.zip");
        
        // ok: java-path-traversal-exp
        ZipArchiveEntry entry = zipFile.getEntry(entryName);
        if (entry != null && !entry.isDirectory()) {
            InputStream inputStream = zipFile.getInputStream(entry);
            // Process input stream...
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// Using FTP client with path validation
public void good_case_9(HttpServletRequest request) {
    String remotePath = request.getParameter("path");
    
    // Sanitize path
    remotePath = new File(remotePath).getName();
    
    FTPClient ftpClient = new FTPClient();
    
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("user", "password");
        
        // ok: java-path-traversal-exp
        InputStream inputStream = ftpClient.retrieveFileStream("/public/" + remotePath);
        // Process input stream...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// Using JSch (SSH/SFTP) with path validation
public void good_case_10(HttpServletRequest request) {
    String remoteFile = request.getParameter("file");
    
    // Validate and sanitize path
    if (remoteFile.contains("..") || remoteFile.startsWith("/")) {
        throw new IllegalArgumentException("Invalid file path");
    }
    
    try {
        JSch jsch = new JSch();
        Session session = jsch.getSession("user", "example.com", 22);
        session.setPassword("password");
        session.connect();
        
        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp) channel;
        
        // ok: java-path-traversal-exp
        InputStream stream = sftpChannel.get("/home/user/files/" + remoteFile.replaceAll("[/\\\\]", ""));
        // Process stream...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Using Jetty server handler with path validation
public class good_case_11 extends AbstractHandler {
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) {
        String fileName = request.getParameter("file");
        
        // Validate filename
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
            try {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
            } catch (IOException e) {
                e.printStackTrace();
            }
            return;
        }
        
        try {
            // ok: java-path-traversal-exp
            File file = new File(new File("/var/www/html"), fileName);
            if (!file.getCanonicalPath().startsWith("/var/www/html")) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
            FileInputStream fis = new FileInputStream(file);
            // Process file...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// Using Undertow server with path validation
public void good_case_12() {
    PathHandler handler = new PathHandler();
    handler.addExactPath("/file", exchange -> {
        String fileName = exchange.getQueryParameters().get("name").getFirst();
        
        // Validate filename
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
            exchange.getResponseSender().send("Invalid filename");
            return;
        }
        
        try {
            // ok: java-path-traversal-exp
            File file = new File("/opt/data", fileName);
            if (!file.getCanonicalPath().startsWith("/opt/data")) {
                exchange.getResponseSender().send("Access denied");
                return;
            }
            exchange.getResponseSender().send(FileUtils.readFileToString(file));
        } catch (IOException e) {
            exchange.getResponseSender().send("Error: " + e.getMessage());
        }
    });
}

// Using Vert.x with path validation
public void good_case_13() {
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    
    router.get("/download").handler(ctx -> {
        String file = ctx.request().getParam("file");
        
        // Validate filename
        if (file.contains("..") || file.contains("/") || file.contains("\\")) {
            ctx.response().setStatusCode(400).end("Invalid filename");
            return;
        }
        
        // ok: java-path-traversal-exp
        String safePath = "/usr/share/files/" + FilenameUtils.getName(file);
        vertx.fileSystem().readFile(safePath, result -> {
            if (result.succeeded()) {
                ctx.response().end(result.result());
            } else {
                ctx.response().end("Error reading file");
            }
        });
    });
}

// Using Tomcat with path validation
public void good_case_14() throws Exception {
    Tomcat tomcat = new Tomcat();
    Context ctx = tomcat.addContext("", new File(".").getAbsolutePath());
    
    Tomcat.addServlet(ctx, "fileServlet", new HttpServlet() {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            String fileName = req.getParameter("file");
            
            // Validate filename
            if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
                return;
            }
            
            // ok: java-path-traversal-exp
            File baseDir = new File("/opt/tomcat/webapps/data");
            File file = new File(baseDir, fileName);
            
            // Double-check that we're still in the intended directory
            if (!file.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
                resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }
            
            FileInputStream fis = new FileInputStream(file);
            // Process file...
        }
    });
    ctx.addServletMappingDecoded("/file", "fileServlet");
}

// Using OkHttp to download file with path validation
public void good_case_15(HttpServletRequest request) {
    String filePath = request.getParameter("path");
    
    // Sanitize path
    String safeFilename = new File(filePath).getName();
    
    OkHttpClient client = new OkHttpClient();
    
    try {
        // ok: java-path-traversal-exp
        File destination = new File("/tmp/downloads", safeFilename);
        Request okRequest = new Request.Builder()
            .url("https://example.com/files/download")
            .build();
        
        try (Response response = client.newCall(okRequest).execute()) {
            FileOutputStream fos = new FileOutputStream(destination);
            fos.write(response.body().bytes());
            fos.close();
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}