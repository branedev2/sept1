import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FileUtils;
import org.springframework.web.bind.annotation.*;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.conf.Configuration;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.VFS;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import java.util.logging.Logger;
import org.apache.commons.net.ftp.FTPClient;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.SFTPClient;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.PropertiesConfiguration;

// Security Issue: Not checking the return value of File.createNewFile() can lead to race conditions and security vulnerabilities
// as the method returns false if the file already exists, which could indicate a potential file collision or manipulation.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Standard Java IO - Not checking createNewFile result
    String fileName = request.getParameter("filename");
    File file = new File("/tmp/" + fileName);
    try {
        // ruleid: java-checkresultofcreatenewfile
        file.createNewFile();
        // Write to file without checking if it was actually created or already existed
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Spring Web context - Not checking createNewFile result
    String uploadDir = "/uploads/";
    String fileName = request.getParameter("document");
    File directory = new File(uploadDir);
    if (!directory.exists()) {
        directory.mkdirs();
    }
    
    File file = new File(uploadDir + fileName);
    try {
        // ruleid: java-checkresultofcreatenewfile
        file.createNewFile();
        // Proceed without checking if file was created successfully
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    // Apache Commons IO context - Not checking createNewFile result
    String configName = request.getParameter("config");
    File configFile = new File("/app/configs/" + configName);
    try {
        // ruleid: java-checkresultofcreatenewfile
        configFile.createNewFile();
        FileUtils.writeStringToFile(configFile, "default=true", "UTF-8");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    // AWS S3 SDK context - Not checking createNewFile result
    String bucketName = request.getParameter("bucket");
    String objectKey = request.getParameter("key");
    
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    File tempFile = new File("/tmp/" + objectKey);
    try {
        // ruleid: java-checkresultofcreatenewfile
        tempFile.createNewFile();
        // Upload file to S3 without checking if it was created
        s3Client.putObject(bucketName, objectKey, tempFile);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    // Apache Hadoop context - Not checking createNewFile result
    String hdfsPath = request.getParameter("path");
    try {
        Configuration conf = new Configuration();
        FileSystem hdfs = FileSystem.get(conf);
        
        // Local staging file
        File localFile = new File("/tmp/hdfs_staging_" + UUID.randomUUID().toString());
        // ruleid: java-checkresultofcreatenewfile
        localFile.createNewFile();
        
        // Upload to HDFS without checking if local file was created
        org.apache.hadoop.fs.Path hdfsFilePath = new org.apache.hadoop.fs.Path(hdfsPath);
        hdfs.copyFromLocalFile(new org.apache.hadoop.fs.Path(localFile.getAbsolutePath()), hdfsFilePath);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    // Google Cloud Storage context - Not checking createNewFile result
    String blobName = request.getParameter("blob");
    Storage storage = StorageOptions.getDefaultInstance().getService();
    
    File tempFile = new File("/tmp/gcs_" + blobName);
    try {
        // ruleid: java-checkresultofcreatenewfile
        tempFile.createNewFile();
        // Use the file without checking if it was created
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    // Apache Commons VFS context - Not checking createNewFile result
    String vfsPath = request.getParameter("vfsPath");
    try {
        // Create a local file first
        File localFile = new File("/tmp/vfs_" + UUID.randomUUID().toString());
        // ruleid: java-checkresultofcreatenewfile
        localFile.createNewFile();
        
        // Use Commons VFS to copy to remote location without checking if local file was created
        FileObject localFileObj = VFS.getManager().resolveFile(localFile.getAbsolutePath());
        FileObject remoteFile = VFS.getManager().resolveFile(vfsPath);
        remoteFile.copyFrom(localFileObj, null);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    // JGit context - Not checking createNewFile result
    String repoPath = request.getParameter("repo");
    String fileName = request.getParameter("file");
    
    try {
        File gitDir = new File(repoPath + "/.git");
        Repository repository = new FileRepositoryBuilder().setGitDir(gitDir).build();
        Git git = new Git(repository);
        
        // Create a file to add to git
        File fileToAdd = new File(repoPath + "/" + fileName);
        // ruleid: java-checkresultofcreatenewfile
        fileToAdd.createNewFile();
        
        // Add to git without checking if file was created
        git.add().addFilepattern(fileName).call();
        git.commit().setMessage("Added " + fileName).call();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    // Logger context - Not checking createNewFile result
    String logFileName = request.getParameter("logfile");
    Logger logger = Logger.getLogger("CustomLogger");
    
    try {
        File logFile = new File("/var/log/" + logFileName);
        // ruleid: java-checkresultofcreatenewfile
        logFile.createNewFile();
        
        // Configure logger without checking if file was created
        // This is simplified; actual logger configuration would be more complex
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // Apache Commons Net FTP context - Not checking createNewFile result
    String ftpFile = request.getParameter("ftpfile");
    FTPClient ftpClient = new FTPClient();
    
    try {
        File localFile = new File("/tmp/ftp_" + ftpFile);
        // ruleid: java-checkresultofcreatenewfile
        localFile.createNewFile();
        
        // Upload via FTP without checking if local file was created
        ftpClient.connect("ftp.example.com");
        ftpClient.login("user", "password");
        ftpClient.storeFile(ftpFile, new java.io.FileInputStream(localFile));
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    // SSHJ SFTP context - Not checking createNewFile result
    String remoteFile = request.getParameter("remotefile");
    
    try {
        File localFile = new File("/tmp/sftp_" + UUID.randomUUID().toString());
        // ruleid: java-checkresultofcreatenewfile
        localFile.createNewFile();
        
        // Upload via SFTP without checking if local file was created
        SSHClient ssh = new SSHClient();
        ssh.connect("example.com");
        ssh.authPassword("user", "password");
        SFTPClient sftp = ssh.newSFTPClient();
        sftp.put(localFile.getPath(), remoteFile);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // Apache Lucene context - Not checking createNewFile result
    String indexName = request.getParameter("index");
    
    try {
        File indexDir = new File("/var/indexes/" + indexName);
        if (!indexDir.exists()) {
            indexDir.mkdirs();
        }
        
        File lockFile = new File(indexDir, "write.lock");
        // ruleid: java-checkresultofcreatenewfile
        lockFile.createNewFile();
        
        // Use for Lucene index without checking if lock file was created
        Directory directory = FSDirectory.open(indexDir.toPath());
        // Further Lucene operations...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Apache Commons Configuration context - Not checking createNewFile result
    String configName = request.getParameter("configname");
    
    try {
        File configFile = new File("/etc/app/" + configName + ".properties");
        // ruleid: java-checkresultofcreatenewfile
        configFile.createNewFile();
        
        // Use for configuration without checking if file was created
        Parameters params = new Parameters();
        FileBasedConfigurationBuilder<Configuration> builder =
            new FileBasedConfigurationBuilder<Configuration>(PropertiesConfiguration.class)
                .configure(params.fileBased().setFile(configFile));
        Configuration config = builder.getConfiguration();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    // Java NIO context - Not checking createNewFile result
    String dataFileName = request.getParameter("datafile");
    
    try {
        File dataFile = new File("/data/" + dataFileName);
        // ruleid: java-checkresultofcreatenewfile
        dataFile.createNewFile();
        
        // Use NIO to write to file without checking if it was created
        Path path = dataFile.toPath();
        Files.write(path, "Data content".getBytes());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Servlet context - Not checking createNewFile result
    String reportName = request.getParameter("report");
    
    try {
        File reportFile = new File(System.getProperty("java.io.tmpdir"), reportName);
        // ruleid: java-checkresultofcreatenewfile
        reportFile.createNewFile();
        
        // Generate report without checking if file was created
        // This would typically involve writing data to the file
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Standard Java IO - Properly checking createNewFile result
    String fileName = request.getParameter("filename");
    File file = new File("/tmp/" + fileName);
    try {
        // ok: java-checkresultofcreatenewfile
        boolean created = file.createNewFile();
        if (created) {
            // File was created successfully, proceed with writing
        } else {
            // File already exists, handle appropriately
            System.out.println("File already exists: " + file.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    // Spring Web context - Properly checking createNewFile result
    String uploadDir = "/uploads/";
    String fileName = request.getParameter("document");
    File directory = new File(uploadDir);
    if (!directory.exists()) {
        directory.mkdirs();
    }
    
    File file = new File(uploadDir + fileName);
    try {
        // ok: java-checkresultofcreatenewfile
        if (file.createNewFile()) {
            // File was created successfully
            System.out.println("Created new file: " + file.getAbsolutePath());
        } else {
            // File already exists
            System.out.println("File already exists: " + file.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    // Apache Commons IO context - Properly checking createNewFile result
    String configName = request.getParameter("config");
    File configFile = new File("/app/configs/" + configName);
    try {
        // ok: java-checkresultofcreatenewfile
        boolean fileCreated = configFile.createNewFile();
        if (fileCreated) {
            // File was created, write default config
            FileUtils.writeStringToFile(configFile, "default=true", "UTF-8");
        } else {
            // File already exists, maybe read existing config
            System.out.println("Config file already exists: " + configFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    // AWS S3 SDK context - Properly checking createNewFile result
    String bucketName = request.getParameter("bucket");
    String objectKey = request.getParameter("key");
    
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    File tempFile = new File("/tmp/" + objectKey);
    try {
        // ok: java-checkresultofcreatenewfile
        boolean created = tempFile.createNewFile();
        if (created) {
            // File was created, upload to S3
            s3Client.putObject(bucketName, objectKey, tempFile);
        } else {
            // File already exists, handle appropriately
            System.out.println("Temp file already exists: " + tempFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // Apache Hadoop context - Properly checking createNewFile result
    String hdfsPath = request.getParameter("path");
    try {
        Configuration conf = new Configuration();
        FileSystem hdfs = FileSystem.get(conf);
        
        // Local staging file
        File localFile = new File("/tmp/hdfs_staging_" + UUID.randomUUID().toString());
        // ok: java-checkresultofcreatenewfile
        if (localFile.createNewFile()) {
            // File was created, upload to HDFS
            org.apache.hadoop.fs.Path hdfsFilePath = new org.apache.hadoop.fs.Path(hdfsPath);
            hdfs.copyFromLocalFile(new org.apache.hadoop.fs.Path(localFile.getAbsolutePath()), hdfsFilePath);
        } else {
            // File already exists, handle appropriately
            System.out.println("Local staging file already exists: " + localFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    // Google Cloud Storage context - Properly checking createNewFile result
    String blobName = request.getParameter("blob");
    Storage storage = StorageOptions.getDefaultInstance().getService();
    
    File tempFile = new File("/tmp/gcs_" + blobName);
    try {
        // ok: java-checkresultofcreatenewfile
        boolean created = tempFile.createNewFile();
        if (created) {
            // File was created, proceed with GCS operations
            System.out.println("Created temp file for GCS: " + tempFile.getAbsolutePath());
        } else {
            // File already exists, handle appropriately
            System.out.println("GCS temp file already exists: " + tempFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    // Apache Commons VFS context - Properly checking createNewFile result
    String vfsPath = request.getParameter("vfsPath");
    try {
        // Create a local file first
        File localFile = new File("/tmp/vfs_" + UUID.randomUUID().toString());
        // ok: java-checkresultofcreatenewfile
        boolean created = localFile.createNewFile();
        
        if (created) {
            // File was created, use Commons VFS to copy to remote location
            FileObject localFileObj = VFS.getManager().resolveFile(localFile.getAbsolutePath());
            FileObject remoteFile = VFS.getManager().resolveFile(vfsPath);
            remoteFile.copyFrom(localFileObj, null);
        } else {
            // File already exists, handle appropriately
            System.out.println("VFS local file already exists: " + localFile.getAbsolutePath());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // JGit context - Properly checking createNewFile result
    String repoPath = request.getParameter("repo");
    String fileName = request.getParameter("file");
    
    try {
        File gitDir = new File(repoPath + "/.git");
        Repository repository = new FileRepositoryBuilder().setGitDir(gitDir).build();
        Git git = new Git(repository);
        
        // Create a file to add to git
        File fileToAdd = new File(repoPath + "/" + fileName);
        // ok: java-checkresultofcreatenewfile
        if (fileToAdd.createNewFile()) {
            // File was created, add to git
            git.add().addFilepattern(fileName).call();
            git.commit().setMessage("Added " + fileName).call();
        } else {
            // File already exists, handle appropriately
            System.out.println("Git file already exists: " + fileToAdd.getAbsolutePath());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    // Logger context - Properly checking createNewFile result
    String logFileName = request.getParameter("logfile");
    Logger logger = Logger.getLogger("CustomLogger");
    
    try {
        File logFile = new File("/var/log/" + logFileName);
        // ok: java-checkresultofcreatenewfile
        boolean created = logFile.createNewFile();
        
        if (created) {
            // File was created, configure logger
            System.out.println("Created log file: " + logFile.getAbsolutePath());
            // Configure logger with the new file
        } else {
            // File already exists, handle appropriately
            System.out.println("Log file already exists: " + logFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // Apache Commons Net FTP context - Properly checking createNewFile result
    String ftpFile = request.getParameter("ftpfile");
    FTPClient ftpClient = new FTPClient();
    
    try {
        File localFile = new File("/tmp/ftp_" + ftpFile);
        // ok: java-checkresultofcreatenewfile
        if (localFile.createNewFile()) {
            // File was created, upload via FTP
            ftpClient.connect("ftp.example.com");
            ftpClient.login("user", "password");
            ftpClient.storeFile(ftpFile, new java.io.FileInputStream(localFile));
        } else {
            // File already exists, handle appropriately
            System.out.println("FTP local file already exists: " + localFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    // SSHJ SFTP context - Properly checking createNewFile result
    String remoteFile = request.getParameter("remotefile");
    
    try {
        File localFile = new File("/tmp/sftp_" + UUID.randomUUID().toString());
        // ok: java-checkresultofcreatenewfile
        boolean created = localFile.createNewFile();
        
        if (created) {
            // File was created, upload via SFTP
            SSHClient ssh = new SSHClient();
            ssh.connect("example.com");
            ssh.authPassword("user", "password");
            SFTPClient sftp = ssh.newSFTPClient();
            sftp.put(localFile.getPath(), remoteFile);
        } else {
            // File already exists, handle appropriately
            System.out.println("SFTP local file already exists: " + localFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // Apache Lucene context - Properly checking createNewFile result
    String indexName = request.getParameter("index");
    
    try {
        File indexDir = new File("/var/indexes/" + indexName);
        if (!indexDir.exists()) {
            indexDir.mkdirs();
        }
        
        File lockFile = new File(indexDir, "write.lock");
        // ok: java-checkresultofcreatenewfile
        if (lockFile.createNewFile()) {
            // Lock file was created, proceed with Lucene operations
            Directory directory = FSDirectory.open(indexDir.toPath());
            // Further Lucene operations...
        } else {
            // Lock file already exists, handle appropriately
            System.out.println("Lucene lock file already exists: " + lockFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    // Apache Commons Configuration context - Properly checking createNewFile result
    String configName = request.getParameter("configname");
    
    try {
        File configFile = new File("/etc/app/" + configName + ".properties");
        // ok: java-checkresultofcreatenewfile
        boolean created = configFile.createNewFile();
        
        if (created) {
            // Config file was created, initialize with defaults
            System.out.println("Created new config file: " + configFile.getAbsolutePath());
        } else {
            // Config file already exists, load existing configuration
            System.out.println("Config file already exists: " + configFile.getAbsolutePath());
        }
        
        Parameters params = new Parameters();
        FileBasedConfigurationBuilder<Configuration> builder =
            new FileBasedConfigurationBuilder<Configuration>(PropertiesConfiguration.class)
                .configure(params.fileBased().setFile(configFile));
        Configuration config = builder.getConfiguration();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    // Java NIO context - Properly checking createNewFile result
    String dataFileName = request.getParameter("datafile");
    
    try {
        File dataFile = new File("/data/" + dataFileName);
        // ok: java-checkresultofcreatenewfile
        if (dataFile.createNewFile()) {
            // File was created, write data using NIO
            Path path = dataFile.toPath();
            Files.write(path, "Data content".getBytes());
        } else {
            // File already exists, handle appropriately
            System.out.println("Data file already exists: " + dataFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    // Servlet context - Properly checking createNewFile result
    String reportName = request.getParameter("report");
    
    try {
        File reportFile = new File(System.getProperty("java.io.tmpdir"), reportName);
        // ok: java-checkresultofcreatenewfile
        boolean created = reportFile.createNewFile();
        
        if (created) {
            // File was created, generate report
            System.out.println("Created report file: " + reportFile.getAbsolutePath());
            // Generate report by writing data to the file
        } else {
            // File already exists, handle appropriately
            System.out.println("Report file already exists: " + reportFile.getAbsolutePath());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}