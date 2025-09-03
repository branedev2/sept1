import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.apache.commons.io.FileUtils;
import org.springframework.web.bind.annotation.*;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path as HadoopPath;
import org.apache.hadoop.conf.Configuration;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;
import com.box.sdk.BoxAPIConnection;
import com.box.sdk.BoxFolder;
import com.dropbox.core.DbxRequestConfig;
import com.dropbox.core.v2.DbxClientV2;
import com.dropbox.core.v2.files.CreateFolderResult;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// Security Issue: Not checking the result of File.mkdir() can lead to silent failures and security vulnerabilities
// when the directory creation fails but the code continues as if it succeeded.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Standard Java File API - Basic case
    String dirPath = request.getParameter("directory");
    File directory = new File(dirPath);
    
    // ruleid: java-checkresultoffilemkdir
    directory.mkdir();
    
    // Code continues assuming directory was created
    File logFile = new File(directory, "app.log");
    // This might fail if directory wasn't created
}

public void bad_case_2(HttpServletRequest request) {
    // Spring MVC web application directory creation
    String uploadDir = request.getParameter("uploadDir");
    File mediaDir = new File(uploadDir + "/media");
    
    // ruleid: java-checkresultoffilemkdir
    mediaDir.mkdir();
    
    // Continues with file operations without checking if directory exists
    try {
        // This operation might fail if directory creation failed
        FileUtils.cleanDirectory(mediaDir);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) throws IOException {
    // Apache Commons IO with nested directories
    String basePath = request.getParameter("basePath");
    File baseDir = new File(basePath);
    File configDir = new File(baseDir, "config");
    
    // ruleid: java-checkresultoffilemkdir
    configDir.mkdir();
    
    // Write to a file in the potentially non-existent directory
    FileUtils.writeStringToFile(new File(configDir, "settings.json"), "{}", "UTF-8");
}

public void bad_case_4(@RequestParam String path) {
    // Spring Boot REST API handling directory creation
    Logger logger = Logger.getLogger("DirectoryService");
    File tempDir = new File(path);
    
    // ruleid: java-checkresultoffilemkdir
    tempDir.mkdir();
    
    logger.info("Created directory at: " + tempDir.getAbsolutePath());
    // Log message is misleading if directory wasn't actually created
}

public void bad_case_5(HttpServletRequest request) throws Exception {
    // Apache Hadoop filesystem directory creation
    String hdfsPath = request.getParameter("hdfsPath");
    Configuration conf = new Configuration();
    FileSystem fs = FileSystem.get(conf);
    HadoopPath dirPath = new HadoopPath(hdfsPath);
    
    // ruleid: java-checkresultoffilemkdir
    fs.mkdirs(dirPath);
    
    // Continue with operations assuming directory exists
    fs.createNewFile(new HadoopPath(dirPath, "data.txt"));
}

public void bad_case_6(HttpServletRequest request) {
    // AWS S3 SDK bucket folder creation simulation using local file
    String bucketPath = request.getParameter("bucketPath");
    File localBucketDir = new File(bucketPath);
    
    // ruleid: java-checkresultoffilemkdir
    localBucketDir.mkdir();
    
    // Proceed with local file operations before S3 upload
    try {
        FileUtils.touch(new File(localBucketDir, "placeholder.txt"));
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    // Google Cloud Storage local staging directory
    String stagingPath = request.getParameter("stagingPath");
    File stagingDir = new File(stagingPath);
    
    // ruleid: java-checkresultoffilemkdir
    stagingDir.mkdir();
    
    // Attempt to use the directory that might not exist
    try {
        Path filePath = Paths.get(stagingDir.getPath(), "upload.tmp");
        Files.createFile(filePath);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) throws Exception {
    // Apache Commons VFS with local directory
    String vfsPath = request.getParameter("vfsPath");
    File localDir = new File(vfsPath);
    
    // ruleid: java-checkresultoffilemkdir
    localDir.mkdir();
    
    // Set up VFS using potentially non-existent directory
    FileSystemManager fsManager = VFS.getManager();
    FileObject fileObject = fsManager.resolveFile(localDir.getAbsolutePath());
    fileObject.createFile();
}

public void bad_case_9(HttpServletRequest request) {
    // Box SDK local cache directory
    String cachePath = request.getParameter("cachePath");
    File cacheDir = new File(cachePath);
    
    // ruleid: java-checkresultoffilemkdir
    cacheDir.mkdir();
    
    // Attempt to write to cache directory
    try {
        FileUtils.writeStringToFile(new File(cacheDir, "box_token.json"), "{}", "UTF-8");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // Dropbox API local sync directory
    String syncPath = request.getParameter("syncPath");
    File syncDir = new File(syncPath);
    
    // ruleid: java-checkresultoffilemkdir
    syncDir.mkdir();
    
    // Proceed with operations in the directory
    try {
        Files.write(Paths.get(syncDir.getPath(), "sync_status.log"), "Initialized".getBytes());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) throws Exception {
    // JGit repository initialization
    String repoPath = request.getParameter("repoPath");
    File repoDir = new File(repoPath);
    
    // ruleid: java-checkresultoffilemkdir
    repoDir.mkdir();
    
    // Initialize Git repository in potentially non-existent directory
    Git.init().setDirectory(repoDir).call();
}

public void bad_case_12(HttpServletRequest request) {
    // Apache HttpClient with local output directory
    String outputPath = request.getParameter("outputPath");
    File outputDir = new File(outputPath);
    
    // ruleid: java-checkresultoffilemkdir
    outputDir.mkdir();
    
    // Prepare to download file to potentially non-existent directory
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpPost httpPost = new HttpPost("https://api.example.com/download");
    // Download operation might fail if directory doesn't exist
}

public void bad_case_13(HttpServletRequest request) {
    // OkHttp client with cache directory
    String cachePath = request.getParameter("cachePath");
    File cacheDir = new File(cachePath);
    
    // ruleid: java-checkresultoffilemkdir
    cacheDir.mkdir();
    
    // Set up OkHttp client with cache in potentially non-existent directory
    OkHttpClient client = new OkHttpClient.Builder()
        .cache(new okhttp3.Cache(cacheDir, 10 * 1024 * 1024))
        .build();
}

public void bad_case_14(HttpServletRequest request) {
    // Retrofit API client with local data directory
    String dataPath = request.getParameter("dataPath");
    File dataDir = new File(dataPath);
    
    // ruleid: java-checkresultoffilemkdir
    dataDir.mkdir();
    
    // Create files in the potentially non-existent directory
    try {
        FileUtils.touch(new File(dataDir, "api_response.json"));
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Vert.x web server with static files directory
    String staticPath = request.getParameter("staticPath");
    File staticDir = new File(staticPath);
    
    // ruleid: java-checkresultoffilemkdir
    staticDir.mkdir();
    
    // Set up Vert.x to serve files from potentially non-existent directory
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    router.route("/static/*").handler(routingContext -> {
        // This might fail if directory doesn't exist
        routingContext.response().sendFile(staticDir.getPath() + "/" + routingContext.request().path().substring(8));
    });
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Standard Java File API - Basic case with result checking
    String dirPath = request.getParameter("directory");
    File directory = new File(dirPath);
    
    // ok: java-checkresultoffilemkdir
    boolean created = directory.mkdir();
    
    if (created) {
        File logFile = new File(directory, "app.log");
        // Proceed with file operations
    } else {
        System.err.println("Failed to create directory: " + dirPath);
    }
}

public void good_case_2(HttpServletRequest request) {
    // Spring MVC web application directory creation with proper checking
    String uploadDir = request.getParameter("uploadDir");
    File mediaDir = new File(uploadDir + "/media");
    
    // ok: java-checkresultoffilemkdir
    if (mediaDir.mkdir()) {
        try {
            FileUtils.cleanDirectory(mediaDir);
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create media directory");
    }
}

public void good_case_3(HttpServletRequest request) throws IOException {
    // Apache Commons IO with nested directories and proper checking
    String basePath = request.getParameter("basePath");
    File baseDir = new File(basePath);
    File configDir = new File(baseDir, "config");
    
    // ok: java-checkresultoffilemkdir
    if (configDir.mkdir()) {
        FileUtils.writeStringToFile(new File(configDir, "settings.json"), "{}", "UTF-8");
    } else {
        throw new IOException("Failed to create config directory");
    }
}

public void good_case_4(@RequestParam String path) {
    // Spring Boot REST API handling directory creation with logging
    Logger logger = Logger.getLogger("DirectoryService");
    File tempDir = new File(path);
    
    // ok: java-checkresultoffilemkdir
    boolean dirCreated = tempDir.mkdir();
    
    if (dirCreated) {
        logger.info("Created directory at: " + tempDir.getAbsolutePath());
    } else {
        logger.log(Level.SEVERE, "Failed to create directory at: " + tempDir.getAbsolutePath());
    }
}

public void good_case_5(HttpServletRequest request) throws Exception {
    // Apache Hadoop filesystem directory creation with result checking
    String hdfsPath = request.getParameter("hdfsPath");
    Configuration conf = new Configuration();
    FileSystem fs = FileSystem.get(conf);
    HadoopPath dirPath = new HadoopPath(hdfsPath);
    
    // ok: java-checkresultoffilemkdir
    boolean created = fs.mkdirs(dirPath);
    
    if (created) {
        fs.createNewFile(new HadoopPath(dirPath, "data.txt"));
    } else {
        throw new IOException("Failed to create HDFS directory: " + hdfsPath);
    }
}

public void good_case_6(HttpServletRequest request) {
    // AWS S3 SDK bucket folder creation simulation with proper checking
    String bucketPath = request.getParameter("bucketPath");
    File localBucketDir = new File(bucketPath);
    
    // ok: java-checkresultoffilemkdir
    boolean created = localBucketDir.mkdir();
    
    if (created) {
        try {
            FileUtils.touch(new File(localBucketDir, "placeholder.txt"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create local bucket directory: " + bucketPath);
    }
}

public void good_case_7(HttpServletRequest request) {
    // Google Cloud Storage local staging directory with proper checking
    String stagingPath = request.getParameter("stagingPath");
    File stagingDir = new File(stagingPath);
    
    // ok: java-checkresultoffilemkdir
    if (stagingDir.mkdir()) {
        try {
            Path filePath = Paths.get(stagingDir.getPath(), "upload.tmp");
            Files.createFile(filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create staging directory: " + stagingPath);
    }
}

public void good_case_8(HttpServletRequest request) throws Exception {
    // Apache Commons VFS with local directory and proper checking
    String vfsPath = request.getParameter("vfsPath");
    File localDir = new File(vfsPath);
    
    // ok: java-checkresultoffilemkdir
    boolean created = localDir.mkdir();
    
    if (created) {
        FileSystemManager fsManager = VFS.getManager();
        FileObject fileObject = fsManager.resolveFile(localDir.getAbsolutePath());
        fileObject.createFile();
    } else {
        throw new IOException("Failed to create VFS directory: " + vfsPath);
    }
}

public void good_case_9(HttpServletRequest request) {
    // Box SDK local cache directory with proper checking
    String cachePath = request.getParameter("cachePath");
    File cacheDir = new File(cachePath);
    
    // ok: java-checkresultoffilemkdir
    if (cacheDir.mkdir()) {
        try {
            FileUtils.writeStringToFile(new File(cacheDir, "box_token.json"), "{}", "UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create Box cache directory: " + cachePath);
    }
}

public void good_case_10(HttpServletRequest request) {
    // Dropbox API local sync directory with proper checking
    String syncPath = request.getParameter("syncPath");
    File syncDir = new File(syncPath);
    
    // ok: java-checkresultoffilemkdir
    boolean created = syncDir.mkdir();
    
    if (created) {
        try {
            Files.write(Paths.get(syncDir.getPath(), "sync_status.log"), "Initialized".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create Dropbox sync directory: " + syncPath);
    }
}

public void good_case_11(HttpServletRequest request) throws Exception {
    // JGit repository initialization with proper directory checking
    String repoPath = request.getParameter("repoPath");
    File repoDir = new File(repoPath);
    
    // ok: java-checkresultoffilemkdir
    if (repoDir.mkdir()) {
        Git.init().setDirectory(repoDir).call();
    } else {
        throw new IOException("Failed to create Git repository directory: " + repoPath);
    }
}

public void good_case_12(HttpServletRequest request) {
    // Apache HttpClient with local output directory and proper checking
    String outputPath = request.getParameter("outputPath");
    File outputDir = new File(outputPath);
    
    // ok: java-checkresultoffilemkdir
    boolean created = outputDir.mkdir();
    
    if (created) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.example.com/download");
        // Download operation can proceed
    } else {
        System.err.println("Failed to create output directory for HTTP download: " + outputPath);
    }
}

public void good_case_13(HttpServletRequest request) {
    // OkHttp client with cache directory and proper checking
    String cachePath = request.getParameter("cachePath");
    File cacheDir = new File(cachePath);
    
    // ok: java-checkresultoffilemkdir
    if (cacheDir.mkdir()) {
        OkHttpClient client = new OkHttpClient.Builder()
            .cache(new okhttp3.Cache(cacheDir, 10 * 1024 * 1024))
            .build();
    } else {
        System.err.println("Failed to create OkHttp cache directory: " + cachePath);
    }
}

public void good_case_14(HttpServletRequest request) {
    // Retrofit API client with local data directory and proper checking
    String dataPath = request.getParameter("dataPath");
    File dataDir = new File(dataPath);
    
    // ok: java-checkresultoffilemkdir
    boolean created = dataDir.mkdir();
    
    if (created) {
        try {
            FileUtils.touch(new File(dataDir, "api_response.json"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create Retrofit data directory: " + dataPath);
    }
}

public void good_case_15(HttpServletRequest request) {
    // Vert.x web server with static files directory and proper checking
    String staticPath = request.getParameter("staticPath");
    File staticDir = new File(staticPath);
    
    // ok: java-checkresultoffilemkdir
    if (staticDir.mkdir()) {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        router.route("/static/*").handler(routingContext -> {
            routingContext.response().sendFile(staticDir.getPath() + "/" + routingContext.request().path().substring(8));
        });
    } else {
        System.err.println("Failed to create Vert.x static files directory: " + staticPath);
    }
}