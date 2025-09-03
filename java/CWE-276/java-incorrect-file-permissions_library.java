import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.conf.Configuration;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.google.cloud.storage.*;
import org.apache.commons.vfs2.*;
import org.apache.commons.vfs2.provider.local.LocalFile;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.net.ftp.FTPClient;
import com.jcraft.jsch.*;
import java.io.OutputStream;
import java.io.InputStream;
import javax.servlet.http.HttpServletResponse;
import org.apache.tomcat.util.http.fileupload.FileItem;
import org.apache.tomcat.util.http.fileupload.disk.DiskFileItemFactory;
import org.apache.tomcat.util.http.fileupload.servlet.ServletFileUpload;
import org.apache.tomcat.util.http.fileupload.servlet.ServletRequestContext;
import okhttp3.*;

// Security Issue: Incorrect file permissions that can grant excessive access

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("filename");
        File file = new File("/tmp/" + fileName);
        
        // ruleid: java-incorrect-file-permissions
        file.setReadable(true, false); // Makes file readable by everyone
        file.setWritable(true, false); // Makes file writable by everyone
        file.setExecutable(true, false); // Makes file executable by everyone
        
        FileOutputStream fos = new FileOutputStream(file);
        fos.write("Sensitive data".getBytes());
        fos.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    try {
        String filePath = request.getParameter("path");
        Path path = Paths.get(filePath);
        Files.createFile(path);
        
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_WRITE);
        perms.add(PosixFilePermission.GROUP_EXECUTE);
        perms.add(PosixFilePermission.OTHERS_READ);
        perms.add(PosixFilePermission.OTHERS_WRITE);
        
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(path, perms);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("file");
        File file = new File("/var/data/" + fileName);
        
        // ruleid: java-incorrect-file-permissions
        FileUtils.touch(file);
        file.setReadable(true, false);
        file.setWritable(true, false);
        
        FileUtils.writeStringToFile(file, "Secret information", "UTF-8");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    try {
        String hdfsPath = request.getParameter("hdfsPath");
        Configuration conf = new Configuration();
        FileSystem hdfs = FileSystem.get(conf);
        
        org.apache.hadoop.fs.Path path = new org.apache.hadoop.fs.Path(hdfsPath);
        FSDataOutputStream outputStream = hdfs.create(path);
        outputStream.writeUTF("Sensitive HDFS data");
        outputStream.close();
        
        // ruleid: java-incorrect-file-permissions
        FsPermission permission = new FsPermission(FsAction.ALL, FsAction.ALL, FsAction.ALL);
        hdfs.setPermission(path, permission);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(@RequestParam("filename") String fileName) {
    try {
        Path path = Paths.get("/opt/data/" + fileName);
        Files.createFile(path);
        
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxrwxrwx"));
        
        Files.write(path, "API key data".getBytes());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    try {
        String vfsPath = request.getParameter("vfsPath");
        FileSystemManager fsManager = VFS.getManager();
        FileObject fileObject = fsManager.resolveFile(vfsPath);
        
        if (fileObject instanceof LocalFile) {
            File file = new File(fileObject.getName().getPath());
            
            // ruleid: java-incorrect-file-permissions
            file.setReadable(true, false);
            file.setWritable(true, false);
        }
        
        OutputStream os = fileObject.getContent().getOutputStream();
        os.write("VFS stored data".getBytes());
        os.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("file");
        File tempFile = new File("/tmp/" + fileName);
        
        // ruleid: java-incorrect-file-permissions
        boolean success = tempFile.createNewFile();
        if (success) {
            tempFile.setReadable(true, false);
            tempFile.setWritable(true, false);
        }
        
        FileOutputStream fos = new FileOutputStream(tempFile);
        fos.write("Temporary data".getBytes());
        fos.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        String sftpPath = request.getParameter("path");
        JSch jsch = new JSch();
        Session session = jsch.getSession("username", "hostname", 22);
        session.setPassword("password");
        session.connect();
        
        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp) channel;
        
        // ruleid: java-incorrect-file-permissions
        sftpChannel.put(new ByteArrayInputStream("SFTP data".getBytes()), sftpPath);
        sftpChannel.chmod(0777, sftpPath); // World-writable permissions
        
        sftpChannel.disconnect();
        session.disconnect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    try {
        String ftpPath = request.getParameter("ftpPath");
        FTPClient ftpClient = new FTPClient();
        ftpClient.connect("ftpserver.example.com");
        ftpClient.login("username", "password");
        
        InputStream inputStream = new ByteArrayInputStream("FTP data".getBytes());
        ftpClient.storeFile(ftpPath, inputStream);
        inputStream.close();
        
        // ruleid: java-incorrect-file-permissions
        ftpClient.chmod(777, ftpPath); // World-writable permissions
        
        ftpClient.logout();
        ftpClient.disconnect();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        String uploadDir = "/var/uploads/";
        String fileName = request.getParameter("filename");
        
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        
        List<FileItem> items = upload.parseRequest(new ServletRequestContext(request));
        for (FileItem item : items) {
            if (!item.isFormField()) {
                File file = new File(uploadDir + fileName);
                item.write(file);
                
                // ruleid: java-incorrect-file-permissions
                file.setReadable(true, false);
                file.setWritable(true, false);
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@PostMapping("/upload")
public void bad_case_11(@RequestParam("file") MultipartFile file, @RequestParam("path") String path) {
    try {
        File destFile = new File(path);
        file.transferTo(destFile);
        
        // ruleid: java-incorrect-file-permissions
        destFile.setReadable(true, false); // Readable by everyone
        destFile.setWritable(true, false); // Writable by everyone
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("filename");
        Path path = Paths.get("/data/" + fileName);
        Files.createFile(path);
        
        // ruleid: java-incorrect-file-permissions
        AclFileAttributeView aclView = Files.getFileAttributeView(path, AclFileAttributeView.class);
        UserPrincipal everyone = FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName("Everyone");
        AclEntry entry = AclEntry.newBuilder()
            .setType(AclEntryType.ALLOW)
            .setPrincipal(everyone)
            .setPermissions(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA, AclEntryPermission.EXECUTE)
            .build();
        
        List<AclEntry> acl = aclView.getAcl();
        acl.add(entry);
        aclView.setAcl(acl);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    try {
        OkHttpClient client = new OkHttpClient();
        Request httpRequest = new Request.Builder()
            .url("https://example.com/download")
            .build();
        
        Response response = client.newCall(httpRequest).execute();
        if (response.isSuccessful() && response.body() != null) {
            String fileName = request.getParameter("saveAs");
            File downloadedFile = new File("/downloads/" + fileName);
            FileOutputStream fos = new FileOutputStream(downloadedFile);
            fos.write(response.body().bytes());
            fos.close();
            
            // ruleid: java-incorrect-file-permissions
            downloadedFile.setReadable(true, false);
            downloadedFile.setWritable(true, false);
            downloadedFile.setExecutable(true, false);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        String bucketName = "my-bucket";
        String objectKey = request.getParameter("objectKey");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // Download from S3
        com.amazonaws.services.s3.model.S3Object s3Object = s3Client.getObject(bucketName, objectKey);
        InputStream inputStream = s3Object.getObjectContent();
        
        // Save locally with insecure permissions
        File localFile = new File("/tmp/" + objectKey);
        FileOutputStream outputStream = new FileOutputStream(localFile);
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        outputStream.close();
        inputStream.close();
        
        // ruleid: java-incorrect-file-permissions
        localFile.setReadable(true, false);
        localFile.setWritable(true, false);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("filename");
        String content = request.getParameter("content");
        
        // Using Google Cloud Storage to download and then save locally
        Storage storage = StorageOptions.getDefaultInstance().getService();
        BlobId blobId = BlobId.of("my-bucket", fileName);
        Blob blob = storage.get(blobId);
        
        if (blob != null) {
            File localFile = new File("/tmp/gcs-" + fileName);
            blob.downloadTo(Paths.get(localFile.toURI()));
            
            // ruleid: java-incorrect-file-permissions
            localFile.setReadable(true, false);
            localFile.setWritable(true, false);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("filename");
        File file = new File("/tmp/" + fileName);
        
        // ok: java-incorrect-file-permissions
        file.setReadable(true, true); // Makes file readable only by owner
        file.setWritable(true, true); // Makes file writable only by owner
        file.setExecutable(true, true); // Makes file executable only by owner
        
        FileOutputStream fos = new FileOutputStream(file);
        fos.write("Sensitive data".getBytes());
        fos.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    try {
        String filePath = request.getParameter("path");
        Path path = Paths.get(filePath);
        Files.createFile(path);
        
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        // No group or others permissions
        
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(path, perms);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("file");
        File file = new File("/var/data/" + fileName);
        
        // ok: java-incorrect-file-permissions
        FileUtils.touch(file);
        file.setReadable(false, false);
        file.setReadable(true, true);
        file.setWritable(false, false);
        file.setWritable(true, true);
        
        FileUtils.writeStringToFile(file, "Secret information", "UTF-8");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    try {
        String hdfsPath = request.getParameter("hdfsPath");
        Configuration conf = new Configuration();
        FileSystem hdfs = FileSystem.get(conf);
        
        org.apache.hadoop.fs.Path path = new org.apache.hadoop.fs.Path(hdfsPath);
        FSDataOutputStream outputStream = hdfs.create(path);
        outputStream.writeUTF("Sensitive HDFS data");
        outputStream.close();
        
        // ok: java-incorrect-file-permissions
        FsPermission permission = new FsPermission(FsAction.READ_WRITE, FsAction.NONE, FsAction.NONE);
        hdfs.setPermission(path, permission);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_5(@RequestParam("filename") String fileName) {
    try {
        Path path = Paths.get("/opt/data/" + fileName);
        Files.createFile(path);
        
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
        
        Files.write(path, "API key data".getBytes());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    try {
        String vfsPath = request.getParameter("vfsPath");
        FileSystemManager fsManager = VFS.getManager();
        FileObject fileObject = fsManager.resolveFile(vfsPath);
        
        if (fileObject instanceof LocalFile) {
            File file = new File(fileObject.getName().getPath());
            
            // ok: java-incorrect-file-permissions
            file.setReadable(false, false);
            file.setReadable(true, true);
            file.setWritable(false, false);
            file.setWritable(true, true);
        }
        
        OutputStream os = fileObject.getContent().getOutputStream();
        os.write("VFS stored data".getBytes());
        os.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("file");
        File tempFile = new File("/tmp/" + fileName);
        
        // ok: java-incorrect-file-permissions
        boolean success = tempFile.createNewFile();
        if (success) {
            tempFile.setReadable(false, false);
            tempFile.setReadable(true, true);
            tempFile.setWritable(false, false);
            tempFile.setWritable(true, true);
        }
        
        FileOutputStream fos = new FileOutputStream(tempFile);
        fos.write("Temporary data".getBytes());
        fos.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        String sftpPath = request.getParameter("path");
        JSch jsch = new JSch();
        Session session = jsch.getSession("username", "hostname", 22);
        session.setPassword("password");
        session.connect();
        
        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp) channel;
        
        // ok: java-incorrect-file-permissions
        sftpChannel.put(new ByteArrayInputStream("SFTP data".getBytes()), sftpPath);
        sftpChannel.chmod(0600, sftpPath); // Owner read/write only
        
        sftpChannel.disconnect();
        session.disconnect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    try {
        String ftpPath = request.getParameter("ftpPath");
        FTPClient ftpClient = new FTPClient();
        ftpClient.connect("ftpserver.example.com");
        ftpClient.login("username", "password");
        
        InputStream inputStream = new ByteArrayInputStream("FTP data".getBytes());
        ftpClient.storeFile(ftpPath, inputStream);
        inputStream.close();
        
        // ok: java-incorrect-file-permissions
        ftpClient.chmod(600, ftpPath); // Owner read/write only
        
        ftpClient.logout();
        ftpClient.disconnect();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        String uploadDir = "/var/uploads/";
        String fileName = request.getParameter("filename");
        
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        
        List<FileItem> items = upload.parseRequest(new ServletRequestContext(request));
        for (FileItem item : items) {
            if (!item.isFormField()) {
                File file = new File(uploadDir + fileName);
                item.write(file);
                
                // ok: java-incorrect-file-permissions
                file.setReadable(false, false);
                file.setReadable(true, true);
                file.setWritable(false, false);
                file.setWritable(true, true);
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@PostMapping("/upload")
public void good_case_11(@RequestParam("file") MultipartFile file, @RequestParam("path") String path) {
    try {
        File destFile = new File(path);
        file.transferTo(destFile);
        
        // ok: java-incorrect-file-permissions
        destFile.setReadable(false, false);
        destFile.setReadable(true, true);
        destFile.setWritable(false, false);
        destFile.setWritable(true, true);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("filename");
        Path path = Paths.get("/data/" + fileName);
        Files.createFile(path);
        
        // ok: java-incorrect-file-permissions
        AclFileAttributeView aclView = Files.getFileAttributeView(path, AclFileAttributeView.class);
        UserPrincipal owner = FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
        AclEntry entry = AclEntry.newBuilder()
            .setType(AclEntryType.ALLOW)
            .setPrincipal(owner)
            .setPermissions(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA)
            .build();
        
        List<AclEntry> acl = new ArrayList<>();
        acl.add(entry);
        aclView.setAcl(acl);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    try {
        OkHttpClient client = new OkHttpClient();
        Request httpRequest = new Request.Builder()
            .url("https://example.com/download")
            .build();
        
        Response response = client.newCall(httpRequest).execute();
        if (response.isSuccessful() && response.body() != null) {
            String fileName = request.getParameter("saveAs");
            File downloadedFile = new File("/downloads/" + fileName);
            FileOutputStream fos = new FileOutputStream(downloadedFile);
            fos.write(response.body().bytes());
            fos.close();
            
            // ok: java-incorrect-file-permissions
            downloadedFile.setReadable(false, false);
            downloadedFile.setReadable(true, true);
            downloadedFile.setWritable(false, false);
            downloadedFile.setWritable(true, true);
            downloadedFile.setExecutable(false, false);
            downloadedFile.setExecutable(true, true);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        String bucketName = "my-bucket";
        String objectKey = request.getParameter("objectKey");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // Download from S3
        com.amazonaws.services.s3.model.S3Object s3Object = s3Client.getObject(bucketName, objectKey);
        InputStream inputStream = s3Object.getObjectContent();
        
        // Save locally with secure permissions
        File localFile = new File("/tmp/" + objectKey);
        FileOutputStream outputStream = new FileOutputStream(localFile);
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        outputStream.close();
        inputStream.close();
        
        // ok: java-incorrect-file-permissions
        localFile.setReadable(false, false);
        localFile.setReadable(true, true);
        localFile.setWritable(false, false);
        localFile.setWritable(true, true);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        String fileName = request.getParameter("filename");
        
        // Using Google Cloud Storage to download and then save locally
        Storage storage = StorageOptions.getDefaultInstance().getService();
        BlobId blobId = BlobId.of("my-bucket", fileName);
        Blob blob = storage.get(blobId);
        
        if (blob != null) {
            File localFile = new File("/tmp/gcs-" + fileName);
            blob.downloadTo(Paths.get(localFile.toURI()));
            
            // ok: java-incorrect-file-permissions
            // Set secure permissions - owner only
            localFile.setReadable(false, false);
            localFile.setReadable(true, true);
            localFile.setWritable(false, false);
            localFile.setWritable(true, true);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}