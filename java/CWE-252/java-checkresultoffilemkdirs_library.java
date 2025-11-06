import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import com.google.common.io.MoreFiles;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path as HadoopPath;
import org.apache.hadoop.conf.Configuration;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletRequest;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.http.GET;
import java.util.concurrent.CompletableFuture;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.apache.commons.net.ftp.FTPClient;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.SFTPClient;
import io.vertx.core.Vertx;
import io.vertx.core.file.FileSystem as VertxFileSystem;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;

// Security Issue: Failing to check the result of File.mkdirs() can lead to silent failures
// where directories are not created as expected, potentially causing security issues or data loss.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Standard Java File API - Not checking result of mkdirs()
    String uploadPath = request.getParameter("path");
    File directory = new File("/var/uploads/" + uploadPath);
    // ruleid: java-checkresultoffilemkdirs
    directory.mkdirs();
    // Proceed with file operations assuming directory exists
    try {
        File file = new File(directory, "uploaded.txt");
        // This might fail if directory wasn't created
        file.createNewFile();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) throws IOException {
    // Spring Framework MultipartFile handling - Not checking directory creation
    String userFolder = request.getParameter("username");
    File targetDir = new File("/app/user_files/" + userFolder);
    // ruleid: java-checkresultoffilemkdirs
    targetDir.mkdirs();
    
    // Simulating Spring MultipartFile handling
    byte[] fileContent = request.getParameter("fileContent").getBytes();
    File targetFile = new File(targetDir, "profile.jpg");
    FileUtils.writeByteArrayToFile(targetFile, fileContent);
}

public void bad_case_3(HttpServletRequest request) {
    // Apache Commons IO - Not checking directory creation
    String projectName = request.getParameter("project");
    File projectDir = new File("/var/projects/" + projectName);
    // ruleid: java-checkresultoffilemkdirs
    projectDir.mkdirs();
    
    try {
        // Using Apache Commons IO for file operations
        File sourceFile = new File("/tmp/template.json");
        File destFile = new File(projectDir, "config.json");
        FileUtils.copyFile(sourceFile, destFile);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    // Google Guava file operations - Not checking directory creation
    String logDir = request.getParameter("logDirectory");
    File logsPath = new File("/var/logs/" + logDir);
    // ruleid: java-checkresultoffilemkdirs
    logsPath.mkdirs();
    
    try {
        // Using Guava for file operations
        File logFile = new File(logsPath, "application.log");
        com.google.common.io.Files.touch(logFile);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) throws IOException {
    // Apache Hadoop FileSystem - Not checking directory creation
    String datasetName = request.getParameter("dataset");
    File localDir = new File("/tmp/hadoop_staging/" + datasetName);
    // ruleid: java-checkresultoffilemkdirs
    localDir.mkdirs();
    
    // Preparing for Hadoop upload
    Configuration conf = new Configuration();
    FileSystem fs = FileSystem.get(conf);
    HadoopPath hdfsPath = new HadoopPath("/user/hadoop/datasets/" + datasetName);
    fs.copyFromLocalFile(new HadoopPath(localDir.getAbsolutePath()), hdfsPath);
}

public void bad_case_6(HttpServletRequest request) {
    // AWS S3 SDK with local staging - Not checking directory creation
    String bucketName = request.getParameter("bucket");
    String objectKey = request.getParameter("key");
    File tempDir = new File("/tmp/s3_staging/" + bucketName);
    // ruleid: java-checkresultoffilemkdirs
    tempDir.mkdirs();
    
    try {
        // Create a temporary file in the directory
        File tempFile = new File(tempDir, "temp_object.dat");
        FileUtils.writeStringToFile(tempFile, "Test data", "UTF-8");
        
        // Upload to S3
        S3Client s3 = S3Client.builder().build();
        s3.putObject(PutObjectRequest.builder()
                .bucket(bucketName)
                .key(objectKey)
                .build(), 
                tempFile.toPath());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    // OkHttp client with file download - Not checking directory creation
    String downloadUrl = request.getParameter("url");
    String saveDir = request.getParameter("saveDir");
    File directory = new File("/downloads/" + saveDir);
    // ruleid: java-checkresultoffilemkdirs
    directory.mkdirs();
    
    try {
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
                .url(downloadUrl)
                .build();
        
        try (Response response = client.newCall(okRequest).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                File downloadFile = new File(directory, "downloaded_file.bin");
                FileUtils.writeByteArrayToFile(downloadFile, response.body().bytes());
            }
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    // Apache Commons VFS - Not checking directory creation
    String virtualPath = request.getParameter("path");
    File localDir = new File("/var/vfs_cache/" + virtualPath);
    // ruleid: java-checkresultoffilemkdirs
    localDir.mkdirs();
    
    try {
        // Using Apache Commons VFS
        FileSystemManager fsManager = VFS.getManager();
        FileObject fileObject = fsManager.resolveFile("sftp://example.com/files/data.txt");
        File localFile = new File(localDir, "data.txt");
        FileUtils.copyInputStreamToFile(fileObject.getContent().getInputStream(), localFile);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    // JSch SFTP operations - Not checking directory creation
    String remoteServer = request.getParameter("server");
    File keyDir = new File("/home/user/.ssh/custom_keys/" + remoteServer);
    // ruleid: java-checkresultoffilemkdirs
    keyDir.mkdirs();
    
    try {
        // Generate and save a key file
        File keyFile = new File(keyDir, "id_rsa");
        FileUtils.writeStringToFile(keyFile, "PRIVATE KEY CONTENT", "UTF-8");
        
        // Use JSch with the key
        JSch jsch = new JSch();
        jsch.addIdentity(keyFile.getAbsolutePath());
        Session session = jsch.getSession("user", remoteServer, 22);
        session.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // JGit operations - Not checking directory creation
    String repoName = request.getParameter("repo");
    File gitDir = new File("/var/git_repos/" + repoName);
    // ruleid: java-checkresultoffilemkdirs
    gitDir.mkdirs();
    
    try {
        // Clone a Git repository
        Git.cloneRepository()
           .setURI("https://github.com/example/repo.git")
           .setDirectory(gitDir)
           .call();
    } catch (GitAPIException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    // Apache Commons Net FTP - Not checking directory creation
    String ftpServer = request.getParameter("ftpServer");
    File downloadDir = new File("/var/ftp_downloads/" + ftpServer);
    // ruleid: java-checkresultoffilemkdirs
    downloadDir.mkdirs();
    
    try {
        FTPClient ftpClient = new FTPClient();
        ftpClient.connect(ftpServer);
        ftpClient.login("user", "password");
        
        File downloadFile = new File(downloadDir, "data.zip");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(downloadFile)) {
            ftpClient.retrieveFile("/public/data.zip", fos);
        }
        ftpClient.disconnect();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // SSHJ library - Not checking directory creation
    String sshHost = request.getParameter("host");
    File configDir = new File("/etc/sshj_configs/" + sshHost);
    // ruleid: java-checkresultoffilemkdirs
    configDir.mkdirs();
    
    try {
        // Create config file
        File configFile = new File(configDir, "config.json");
        FileUtils.writeStringToFile(configFile, "{\"timeout\": 30000}", "UTF-8");
        
        // Use SSHJ
        SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect(sshHost);
        ssh.authPassword("username", "password");
        SFTPClient sftp = ssh.newSFTPClient();
        // Further SFTP operations would go here
        ssh.disconnect();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Vert.x file operations - Not checking directory creation
    String appName = request.getParameter("app");
    File appDir = new File("/var/vertx_apps/" + appName);
    // ruleid: java-checkresultoffilemkdirs
    appDir.mkdirs();
    
    // Using Vert.x file system operations
    Vertx vertx = Vertx.vertx();
    VertxFileSystem fs = vertx.fileSystem();
    File configFile = new File(appDir, "config.json");
    fs.writeFile(configFile.getAbsolutePath(), 
                 io.vertx.core.buffer.Buffer.buffer("{\"port\": 8080}"), 
                 result -> {
                     if (result.succeeded()) {
                         System.out.println("File written");
                     } else {
                         result.cause().printStackTrace();
                     }
                 });
}

public void bad_case_14(HttpServletRequest request) {
    // Apache Commons Exec - Not checking directory creation
    String scriptName = request.getParameter("script");
    File scriptDir = new File("/var/scripts/" + scriptName);
    // ruleid: java-checkresultoffilemkdirs
    scriptDir.mkdirs();
    
    try {
        // Create a script file
        File scriptFile = new File(scriptDir, "run.sh");
        FileUtils.writeStringToFile(scriptFile, "#!/bin/bash\necho 'Hello World'", "UTF-8");
        scriptFile.setExecutable(true);
        
        // Execute the script
        CommandLine cmdLine = new CommandLine(scriptFile.getAbsolutePath());
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(cmdLine);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // CompletableFuture with async file operations - Not checking directory creation
    String userId = request.getParameter("userId");
    File userDir = new File("/var/user_data/" + userId);
    // ruleid: java-checkresultoffilemkdirs
    userDir.mkdirs();
    
    CompletableFuture.runAsync(() -> {
        try {
            // Create user data files asynchronously
            File profileFile = new File(userDir, "profile.json");
            FileUtils.writeStringToFile(profileFile, "{\"name\": \"User\"}", "UTF-8");
            
            File settingsFile = new File(userDir, "settings.json");
            FileUtils.writeStringToFile(settingsFile, "{\"theme\": \"dark\"}", "UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
        }
    });
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Standard Java File API - Checking result of mkdirs()
    String uploadPath = request.getParameter("path");
    File directory = new File("/var/uploads/" + uploadPath);
    // ok: java-checkresultoffilemkdirs
    boolean dirCreated = directory.mkdirs();
    if (!dirCreated && !directory.exists()) {
        throw new RuntimeException("Failed to create directory: " + directory.getAbsolutePath());
    }
    
    try {
        File file = new File(directory, "uploaded.txt");
        file.createNewFile();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) throws IOException {
    // Spring Framework MultipartFile handling - Checking directory creation
    String userFolder = request.getParameter("username");
    File targetDir = new File("/app/user_files/" + userFolder);
    // ok: java-checkresultoffilemkdirs
    if (!targetDir.mkdirs() && !targetDir.exists()) {
        throw new IOException("Could not create directory: " + targetDir.getAbsolutePath());
    }
    
    // Simulating Spring MultipartFile handling
    byte[] fileContent = request.getParameter("fileContent").getBytes();
    File targetFile = new File(targetDir, "profile.jpg");
    FileUtils.writeByteArrayToFile(targetFile, fileContent);
}

public void good_case_3(HttpServletRequest request) {
    // Apache Commons IO - Checking directory creation
    String projectName = request.getParameter("project");
    File projectDir = new File("/var/projects/" + projectName);
    // ok: java-checkresultoffilemkdirs
    boolean created = projectDir.mkdirs();
    if (!created && !projectDir.exists()) {
        Logger.getLogger(getClass().getName()).warning("Failed to create directory: " + projectDir);
        return;
    }
    
    try {
        // Using Apache Commons IO for file operations
        File sourceFile = new File("/tmp/template.json");
        File destFile = new File(projectDir, "config.json");
        FileUtils.copyFile(sourceFile, destFile);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    // Google Guava file operations - Checking directory creation
    String logDir = request.getParameter("logDirectory");
    File logsPath = new File("/var/logs/" + logDir);
    // ok: java-checkresultoffilemkdirs
    if (!logsPath.mkdirs() && !logsPath.exists()) {
        System.err.println("Failed to create log directory: " + logsPath.getAbsolutePath());
        return;
    }
    
    try {
        // Using Guava for file operations
        File logFile = new File(logsPath, "application.log");
        com.google.common.io.Files.touch(logFile);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) throws IOException {
    // Apache Hadoop FileSystem - Checking directory creation
    String datasetName = request.getParameter("dataset");
    File localDir = new File("/tmp/hadoop_staging/" + datasetName);
    // ok: java-checkresultoffilemkdirs
    boolean dirCreated = localDir.mkdirs();
    if (!dirCreated && !localDir.exists()) {
        throw new IOException("Failed to create staging directory for Hadoop upload");
    }
    
    // Preparing for Hadoop upload
    Configuration conf = new Configuration();
    FileSystem fs = FileSystem.get(conf);
    HadoopPath hdfsPath = new HadoopPath("/user/hadoop/datasets/" + datasetName);
    fs.copyFromLocalFile(new HadoopPath(localDir.getAbsolutePath()), hdfsPath);
}

public void good_case_6(HttpServletRequest request) {
    // AWS S3 SDK with local staging - Checking directory creation
    String bucketName = request.getParameter("bucket");
    String objectKey = request.getParameter("key");
    File tempDir = new File("/tmp/s3_staging/" + bucketName);
    // ok: java-checkresultoffilemkdirs
    if (tempDir.mkdirs() || tempDir.exists()) {
        try {
            // Create a temporary file in the directory
            File tempFile = new File(tempDir, "temp_object.dat");
            FileUtils.writeStringToFile(tempFile, "Test data", "UTF-8");
            
            // Upload to S3
            S3Client s3 = S3Client.builder().build();
            s3.putObject(PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build(), 
                    tempFile.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create temporary directory for S3 upload");
    }
}

public void good_case_7(HttpServletRequest request) {
    // OkHttp client with file download - Checking directory creation
    String downloadUrl = request.getParameter("url");
    String saveDir = request.getParameter("saveDir");
    File directory = new File("/downloads/" + saveDir);
    // ok: java-checkresultoffilemkdirs
    boolean dirCreated = directory.mkdirs();
    if (!dirCreated && !directory.exists()) {
        System.err.println("Failed to create download directory: " + directory.getAbsolutePath());
        return;
    }
    
    try {
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
                .url(downloadUrl)
                .build();
        
        try (Response response = client.newCall(okRequest).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                File downloadFile = new File(directory, "downloaded_file.bin");
                FileUtils.writeByteArrayToFile(downloadFile, response.body().bytes());
            }
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // Apache Commons VFS - Checking directory creation
    String virtualPath = request.getParameter("path");
    File localDir = new File("/var/vfs_cache/" + virtualPath);
    // ok: java-checkresultoffilemkdirs
    if (localDir.mkdirs() || localDir.exists()) {
        try {
            // Using Apache Commons VFS
            FileSystemManager fsManager = VFS.getManager();
            FileObject fileObject = fsManager.resolveFile("sftp://example.com/files/data.txt");
            File localFile = new File(localDir, "data.txt");
            FileUtils.copyInputStreamToFile(fileObject.getContent().getInputStream(), localFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create VFS cache directory");
    }
}

public void good_case_9(HttpServletRequest request) {
    // JSch SFTP operations - Checking directory creation
    String remoteServer = request.getParameter("server");
    File keyDir = new File("/home/user/.ssh/custom_keys/" + remoteServer);
    // ok: java-checkresultoffilemkdirs
    boolean dirCreated = keyDir.mkdirs();
    if (!dirCreated && !keyDir.exists()) {
        System.err.println("Failed to create SSH key directory");
        return;
    }
    
    try {
        // Generate and save a key file
        File keyFile = new File(keyDir, "id_rsa");
        FileUtils.writeStringToFile(keyFile, "PRIVATE KEY CONTENT", "UTF-8");
        
        // Use JSch with the key
        JSch jsch = new JSch();
        jsch.addIdentity(keyFile.getAbsolutePath());
        Session session = jsch.getSession("user", remoteServer, 22);
        session.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // JGit operations - Checking directory creation
    String repoName = request.getParameter("repo");
    File gitDir = new File("/var/git_repos/" + repoName);
    // ok: java-checkresultoffilemkdirs
    if (gitDir.mkdirs() || gitDir.exists()) {
        try {
            // Clone a Git repository
            Git.cloneRepository()
               .setURI("https://github.com/example/repo.git")
               .setDirectory(gitDir)
               .call();
        } catch (GitAPIException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create Git repository directory");
    }
}

public void good_case_11(HttpServletRequest request) {
    // Apache Commons Net FTP - Checking directory creation
    String ftpServer = request.getParameter("ftpServer");
    File downloadDir = new File("/var/ftp_downloads/" + ftpServer);
    // ok: java-checkresultoffilemkdirs
    boolean dirCreated = downloadDir.mkdirs();
    if (!dirCreated && !downloadDir.exists()) {
        System.err.println("Failed to create FTP download directory");
        return;
    }
    
    try {
        FTPClient ftpClient = new FTPClient();
        ftpClient.connect(ftpServer);
        ftpClient.login("user", "password");
        
        File downloadFile = new File(downloadDir, "data.zip");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(downloadFile)) {
            ftpClient.retrieveFile("/public/data.zip", fos);
        }
        ftpClient.disconnect();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // SSHJ library - Checking directory creation
    String sshHost = request.getParameter("host");
    File configDir = new File("/etc/sshj_configs/" + sshHost);
    // ok: java-checkresultoffilemkdirs
    if (!configDir.mkdirs() && !configDir.exists()) {
        System.err.println("Failed to create SSH config directory");
        return;
    }
    
    try {
        // Create config file
        File configFile = new File(configDir, "config.json");
        FileUtils.writeStringToFile(configFile, "{\"timeout\": 30000}", "UTF-8");
        
        // Use SSHJ
        SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect(sshHost);
        ssh.authPassword("username", "password");
        SFTPClient sftp = ssh.newSFTPClient();
        // Further SFTP operations would go here
        ssh.disconnect();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    // Vert.x file operations - Checking directory creation
    String appName = request.getParameter("app");
    File appDir = new File("/var/vertx_apps/" + appName);
    // ok: java-checkresultoffilemkdirs
    boolean dirCreated = appDir.mkdirs();
    if (!dirCreated && !appDir.exists()) {
        System.err.println("Failed to create Vert.x application directory");
        return;
    }
    
    // Using Vert.x file system operations
    Vertx vertx = Vertx.vertx();
    VertxFileSystem fs = vertx.fileSystem();
    File configFile = new File(appDir, "config.json");
    fs.writeFile(configFile.getAbsolutePath(), 
                 io.vertx.core.buffer.Buffer.buffer("{\"port\": 8080}"), 
                 result -> {
                     if (result.succeeded()) {
                         System.out.println("File written");
                     } else {
                         result.cause().printStackTrace();
                     }
                 });
}

public void good_case_14(HttpServletRequest request) {
    // Apache Commons Exec - Checking directory creation
    String scriptName = request.getParameter("script");
    File scriptDir = new File("/var/scripts/" + scriptName);
    // ok: java-checkresultoffilemkdirs
    if (scriptDir.mkdirs() || scriptDir.exists()) {
        try {
            // Create a script file
            File scriptFile = new File(scriptDir, "run.sh");
            FileUtils.writeStringToFile(scriptFile, "#!/bin/bash\necho 'Hello World'", "UTF-8");
            scriptFile.setExecutable(true);
            
            // Execute the script
            CommandLine cmdLine = new CommandLine(scriptFile.getAbsolutePath());
            DefaultExecutor executor = new DefaultExecutor();
            executor.execute(cmdLine);
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Failed to create script directory");
    }
}

public void good_case_15(HttpServletRequest request) {
    // CompletableFuture with async file operations - Checking directory creation
    String userId = request.getParameter("userId");
    File userDir = new File("/var/user_data/" + userId);
    // ok: java-checkresultoffilemkdirs
    boolean dirCreated = userDir.mkdirs();
    if (!dirCreated && !userDir.exists()) {
        System.err.println("Failed to create user data directory");
        return;
    }
    
    CompletableFuture.runAsync(() -> {
        try {
            // Create user data files asynchronously
            File profileFile = new File(userDir, "profile.json");
            FileUtils.writeStringToFile(profileFile, "{\"name\": \"User\"}", "UTF-8");
            
            File settingsFile = new File(userDir, "settings.json");
            FileUtils.writeStringToFile(settingsFile, "{\"theme\": \"dark\"}", "UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
        }
    });
}