import java.io.*;
import java.nio.file.*;
import java.net.URI;
import java.util.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.apache.commons.io.FileUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.google.cloud.storage.*;
import org.apache.commons.vfs2.*;
import org.apache.commons.vfs2.provider.local.LocalFile;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.Configuration;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest.Builder;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.http.GET;
import retrofit2.http.Path;
import org.apache.tomcat.util.http.fileupload.FileItem;
import org.apache.tomcat.util.http.fileupload.disk.DiskFileItemFactory;
import org.apache.tomcat.util.http.fileupload.servlet.ServletFileUpload;
import org.apache.tomcat.util.http.fileupload.servlet.ServletRequestContext;
import org.apache.commons.net.ftp.FTPClient;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang3.StringUtils;

// Security Issue: Path Traversal Vulnerabilities (CWE-22, CWE-23)
// These examples demonstrate how user-controlled input can lead to path traversal vulnerabilities
// when used to determine filenames for read or write operations.

// True Positive Examples (Vulnerable/Insecure Code)

@Controller
public class PathTraversalExamples {

    // Spring MVC example
// {fact rule=path-traversal@v1.0 defects=1}
    @RequestMapping("/download")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        File file = new File("/var/data/");
        
        // ruleid: java-path-traversal
        File requestedFile = new File(file, fileName);
        
        FileInputStream fis = new FileInputStream(requestedFile);
        IOUtils.copy(fis, response.getOutputStream());
        fis.close();
    }
    
    // Apache Commons IO example
    @RequestMapping("/read-file")
    public String bad_case_2(HttpServletRequest request) throws IOException {
        String fileName = request.getParameter("name");
        
        // ruleid: java-path-traversal
        String content = FileUtils.readFileToString(new File("/app/resources/" + fileName), "UTF-8");
        
        return content;
    }
    
    // Java NIO example
    @RequestMapping("/nio-read")
    public byte[] bad_case_3(HttpServletRequest request) throws IOException {
        String filePath = request.getParameter("path");
        
        // ruleid: java-path-traversal
        Path path = Paths.get("/data/files/", filePath);
        
        return Files.readAllBytes(path);
    }
    
    // Apache Commons VFS example
    @RequestMapping("/vfs-read")
    public String bad_case_4(HttpServletRequest request) throws FileSystemException, IOException {
        String userFile = request.getParameter("document");
        FileSystemManager fsManager = VFS.getManager();
        
        // ruleid: java-path-traversal
        FileObject file = fsManager.resolveFile("file:///var/www/documents/" + userFile);
        
        FileContent content = file.getContent();
        InputStream is = content.getInputStream();
        String fileContent = IOUtils.toString(is, "UTF-8");
        is.close();
        return fileContent;
    }
    
    // Jetty server handler example
    public class bad_case_5 extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, 
                          HttpServletResponse response) throws IOException {
            String requestedPath = request.getParameter("file");
            
            // ruleid: java-path-traversal
            File file = new File("/var/www/html/" + requestedPath);
            
            if (file.exists() && file.isFile()) {
                response.setContentType("application/octet-stream");
                FileInputStream fis = new FileInputStream(file);
                OutputStream out = response.getOutputStream();
                IOUtils.copy(fis, out);
                fis.close();
                out.close();
            }
            baseRequest.setHandled(true);
        }
    }
    
    // AWS S3 SDK example
    @RequestMapping("/s3-download")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userKey = request.getParameter("key");
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-path-traversal
        com.amazonaws.services.s3.model.S3Object s3Object = s3Client.getObject("my-bucket", "user-files/" + userKey);
        
        InputStream is = s3Object.getObjectContent();
        IOUtils.copy(is, response.getOutputStream());
        is.close();
    }
    
    // Google Cloud Storage example
    @RequestMapping("/gcs-read")
    public byte[] bad_case_7(HttpServletRequest request) {
        String fileName = request.getParameter("file");
        Storage storage = StorageOptions.getDefaultInstance().getService();
        
        // ruleid: java-path-traversal
        BlobId blobId = BlobId.of("my-bucket", "user-data/" + fileName);
        
        Blob blob = storage.get(blobId);
        return blob.getContent();
    }
    
    // Apache Commons Exec example
    @RequestMapping("/exec-file")
    public void bad_case_8(HttpServletRequest request) throws Exception {
        String scriptName = request.getParameter("script");
        
        // ruleid: java-path-traversal
        CommandLine cmdLine = CommandLine.parse("python /scripts/" + scriptName);
        
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(cmdLine);
    }
    
    // Hadoop FileSystem example
    @RequestMapping("/hadoop-read")
    public String bad_case_9(HttpServletRequest request) throws IOException {
        String hdfsFile = request.getParameter("hdfsFile");
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(URI.create("hdfs://namenode:8020"), conf);
        
        // ruleid: java-path-traversal
        Path path = new Path("/user/hadoop/data/" + hdfsFile);
        
        InputStream in = fs.open(path);
        String content = IOUtils.toString(in, "UTF-8");
        in.close();
        return content;
    }
    
    // AWS SDK v2 example
    @RequestMapping("/s3v2-download")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userKey = request.getParameter("key");
        S3Client s3 = S3Client.builder().build();
        
        // ruleid: java-path-traversal
        software.amazon.awssdk.services.s3.model.GetObjectRequest getObjectRequest = 
            software.amazon.awssdk.services.s3.model.GetObjectRequest.builder()
                .bucket("my-bucket")
                .key("user-files/" + userKey)
                .build();
        
        software.amazon.awssdk.core.ResponseInputStream<?> s3Object = s3.getObject(getObjectRequest);
        IOUtils.copy(s3Object, response.getOutputStream());
        s3Object.close();
    }
    
    // OkHttp client example
    @RequestMapping("/okhttp-proxy")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filePath = request.getParameter("path");
        OkHttpClient client = new OkHttpClient();
        
        // ruleid: java-path-traversal
        Request okRequest = new Request.Builder()
            .url("http://internal-file-server/files/" + filePath)
            .build();
        
        try (Response okResponse = client.newCall(okRequest).execute()) {
            IOUtils.copy(okResponse.body().byteStream(), response.getOutputStream());
        }
    }
    
    // Apache Tomcat file upload example
    @RequestMapping("/upload")
    public void bad_case_12(HttpServletRequest request) throws Exception {
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        List<FileItem> items = upload.parseRequest(new ServletRequestContext(request));
        
        String uploadPath = request.getParameter("directory");
        for (FileItem item : items) {
            if (!item.isFormField()) {
                // ruleid: java-path-traversal
                File uploadedFile = new File("/var/uploads/" + uploadPath + "/" + item.getName());
                
                item.write(uploadedFile);
            }
        }
    }
    
    // Apache Commons Net FTP example
    @RequestMapping("/ftp-download")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String remoteFile = request.getParameter("file");
        FTPClient ftpClient = new FTPClient();
        ftpClient.connect("ftp.example.com");
        ftpClient.login("user", "password");
        
        // ruleid: java-path-traversal
        InputStream inputStream = ftpClient.retrieveFileStream("/public/" + remoteFile);
        
        IOUtils.copy(inputStream, response.getOutputStream());
        inputStream.close();
        ftpClient.disconnect();
    }
    
    // JSch SFTP example
    @RequestMapping("/sftp-get")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fileName = request.getParameter("file");
        JSch jsch = new JSch();
        Session session = jsch.getSession("user", "sftp.example.com", 22);
        session.setPassword("password");
        session.connect();
        
        ChannelSftp channel = (ChannelSftp) session.openChannel("sftp");
        channel.connect();
        
        // ruleid: java-path-traversal
        InputStream is = channel.get("/home/user/files/" + fileName);
        
        IOUtils.copy(is, response.getOutputStream());
        is.close();
        channel.disconnect();
        session.disconnect();
    }
    
    // Apache Commons Compress example
    @RequestMapping("/create-zip")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] filesToZip = request.getParameterValues("files");
        response.setContentType("application/zip");
        response.setHeader("Content-Disposition", "attachment; filename=\"archive.zip\"");
        
        ZipArchiveOutputStream zipOut = new ZipArchiveOutputStream(response.getOutputStream());
        
        for (String fileName : filesToZip) {
            // ruleid: java-path-traversal
            File fileToZip = new File("/var/data/" + fileName);
            
            ZipArchiveEntry zipEntry = new ZipArchiveEntry(fileToZip, fileToZip.getName());
            zipOut.putArchiveEntry(zipEntry);
            
            FileInputStream fis = new FileInputStream(fileToZip);
            IOUtils.copy(fis, zipOut);
            fis.close();
            zipOut.closeArchiveEntry();
        }
        
        zipOut.close();
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Spring MVC with path normalization and validation
    @RequestMapping("/download-safe")
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        
        // Validate filename
        if (fileName == null || fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
            return;
        }
        
        File baseDir = new File("/var/data/");
        
        // ok: java-path-traversal
        File requestedFile = new File(baseDir, fileName);
        
        // Additional path validation
        String canonicalBasePath = baseDir.getCanonicalPath();
        String canonicalRequestedPath = requestedFile.getCanonicalPath();
        
        if (!canonicalRequestedPath.startsWith(canonicalBasePath)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        
        FileInputStream fis = new FileInputStream(requestedFile);
        IOUtils.copy(fis, response.getOutputStream());
        fis.close();
    }
    
    // Apache Commons IO with whitelist validation
    @RequestMapping("/read-file-safe")
    public String good_case_2(HttpServletRequest request) throws IOException {
        String fileName = request.getParameter("name");
        
        // Whitelist of allowed files
        Set<String> allowedFiles = new HashSet<>(Arrays.asList("report.txt", "public-data.csv", "info.html"));
        
        if (!allowedFiles.contains(fileName)) {
            return "File not allowed";
        }
        
        // ok: java-path-traversal
        String content = FileUtils.readFileToString(new File("/app/resources/" + fileName), "UTF-8");
        
        return content;
    }
    
    // Java NIO with path normalization and security check
    @RequestMapping("/nio-read-safe")
    public byte[] good_case_3(HttpServletRequest request) throws IOException {
        String fileName = request.getParameter("path");
        
        // Normalize and validate the path
        Path basePath = Paths.get("/data/files/").normalize().toAbsolutePath();
        
        // ok: java-path-traversal
        Path resolvedPath = basePath.resolve(fileName).normalize();
        
        // Security check
        if (!resolvedPath.startsWith(basePath)) {
            throw new SecurityException("Path traversal attempt detected");
        }
        
        return Files.readAllBytes(resolvedPath);
    }
    
    // Apache Commons VFS with path validation
    @RequestMapping("/vfs-read-safe")
    public String good_case_4(HttpServletRequest request) throws FileSystemException, IOException {
        String userFile = request.getParameter("document");
        
        // Validate filename
        if (userFile == null || userFile.contains("..") || userFile.contains("/") || userFile.contains("\\")) {
            return "Invalid filename";
        }
        
        FileSystemManager fsManager = VFS.getManager();
        FileObject baseFolder = fsManager.resolveFile("file:///var/www/documents/");
        
        // ok: java-path-traversal
        FileObject file = baseFolder.resolveFile(userFile);
        
        // Additional security check
        if (!file.getURL().getPath().startsWith(baseFolder.getURL().getPath())) {
            throw new SecurityException("Invalid file access attempt");
        }
        
        FileContent content = file.getContent();
        InputStream is = content.getInputStream();
        String fileContent = IOUtils.toString(is, "UTF-8");
        is.close();
        return fileContent;
    }
    
    // Jetty server handler with secure path handling
    public class good_case_5 extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, 
                          HttpServletResponse response) throws IOException {
            String requestedPath = request.getParameter("file");
            
            // Validate and sanitize the path
            if (requestedPath == null || requestedPath.contains("..") || 
                !requestedPath.matches("[a-zA-Z0-9_\\-\\.]+")) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
                baseRequest.setHandled(true);
                return;
            }
            
            // ok: java-path-traversal
            File file = new File(new File("/var/www/html/"), requestedPath);
            
            // Additional path validation
            if (!file.getCanonicalPath().startsWith(new File("/var/www/html/").getCanonicalPath())) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                baseRequest.setHandled(true);
                return;
            }
            
            if (file.exists() && file.isFile()) {
                response.setContentType("application/octet-stream");
                FileInputStream fis = new FileInputStream(file);
                OutputStream out = response.getOutputStream();
                IOUtils.copy(fis, out);
                fis.close();
                out.close();
            }
            baseRequest.setHandled(true);
        }
    }
    
    // AWS S3 SDK with key validation
    @RequestMapping("/s3-download-safe")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userKey = request.getParameter("key");
        
        // Validate the key format
        if (userKey == null || !userKey.matches("[a-zA-Z0-9_\\-\\.]+")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid key format");
            return;
        }
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ok: java-path-traversal
        com.amazonaws.services.s3.model.S3Object s3Object = s3Client.getObject("my-bucket", "user-files/" + userKey);
        
        InputStream is = s3Object.getObjectContent();
        IOUtils.copy(is, response.getOutputStream());
        is.close();
    }
    
    // Google Cloud Storage with filename validation
    @RequestMapping("/gcs-read-safe")
    public byte[] good_case_7(HttpServletRequest request) {
        String fileName = request.getParameter("file");
        
        // Validate filename
        if (fileName == null || fileName.contains("..") || !fileName.matches("[a-zA-Z0-9_\\-\\.]+")) {
            throw new IllegalArgumentException("Invalid filename");
        }
        
        Storage storage = StorageOptions.getDefaultInstance().getService();
        
        // ok: java-path-traversal
        BlobId blobId = BlobId.of("my-bucket", "user-data/" + fileName);
        
        Blob blob = storage.get(blobId);
        if (blob == null) {
            throw new RuntimeException("File not found");
        }
        return blob.getContent();
    }
    
    // Apache Commons Exec with whitelist validation
    @RequestMapping("/exec-file-safe")
    public void good_case_8(HttpServletRequest request) throws Exception {
        String scriptName = request.getParameter("script");
        
        // Whitelist of allowed scripts
        Map<String, String> allowedScripts = new HashMap<>();
        allowedScripts.put("report", "report.py");
        allowedScripts.put("analyze", "analyze.py");
        allowedScripts.put("export", "export.py");
        
        if (!allowedScripts.containsKey(scriptName)) {
            throw new IllegalArgumentException("Invalid script name");
        }
        
        // ok: java-path-traversal
        CommandLine cmdLine = CommandLine.parse("python /scripts/" + allowedScripts.get(scriptName));
        
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(cmdLine);
    }
    
    // Hadoop FileSystem with path validation
    @RequestMapping("/hadoop-read-safe")
    public String good_case_9(HttpServletRequest request) throws IOException {
        String hdfsFile = request.getParameter("hdfsFile");
        
        // Validate file path
        if (hdfsFile == null || hdfsFile.contains("..") || !hdfsFile.matches("[a-zA-Z0-9_\\-\\.]+")) {
            throw new IllegalArgumentException("Invalid file path");
        }
        
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(URI.create("hdfs://namenode:8020"), conf);
        
        // ok: java-path-traversal
        Path path = new Path("/user/hadoop/data/" + hdfsFile);
        
        // Additional path validation
        Path basePath = new Path("/user/hadoop/data/");
        if (!path.toString().startsWith(basePath.toString())) {
            throw new SecurityException("Path traversal attempt detected");
        }
        
        InputStream in = fs.open(path);
        String content = IOUtils.toString(in, "UTF-8");
        in.close();
        return content;
    }
    
    // AWS SDK v2 with key validation
    @RequestMapping("/s3v2-download-safe")
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userKey = request.getParameter("key");
        
        // Validate key format and restrict to specific directory
        if (userKey == null || !userKey.matches("[a-zA-Z0-9_\\-\\.]+")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid key format");
            return;
        }
        
        S3Client s3 = S3Client.builder().build();
        
        // ok: java-path-traversal
        software.amazon.awssdk.services.s3.model.GetObjectRequest getObjectRequest = 
            software.amazon.awssdk.services.s3.model.GetObjectRequest.builder()
                .bucket("my-bucket")
                .key("user-files/" + userKey)
                .build();
        
        software.amazon.awssdk.core.ResponseInputStream<?> s3Object = s3.getObject(getObjectRequest);
        IOUtils.copy(s3Object, response.getOutputStream());
        s3Object.close();
    }
    
    // OkHttp client with URL validation
    @RequestMapping("/okhttp-proxy-safe")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filePath = request.getParameter("path");
        
        // Validate file path
        if (filePath == null || filePath.contains("..") || !filePath.matches("[a-zA-Z0-9_\\-\\.]+")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file path");
            return;
        }
        
        OkHttpClient client = new OkHttpClient();
        
        // ok: java-path-traversal
        Request okRequest = new Request.Builder()
            .url("http://internal-file-server/files/" + filePath)
            .build();
        
        try (Response okResponse = client.newCall(okRequest).execute()) {
            IOUtils.copy(okResponse.body().byteStream(), response.getOutputStream());
        }
    }
    
    // Apache Tomcat file upload with path validation
    @RequestMapping("/upload-safe")
    public void good_case_12(HttpServletRequest request) throws Exception {
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        List<FileItem> items = upload.parseRequest(new ServletRequestContext(request));
        
        String uploadPath = request.getParameter("directory");
        
        // Validate directory path
        if (uploadPath == null || uploadPath.contains("..") || !uploadPath.matches("[a-zA-Z0-9_\\-]+")) {
            throw new IllegalArgumentException("Invalid directory path");
        }
        
        File baseDir = new File("/var/uploads/");
        
        // ok: java-path-traversal
        File uploadDir = new File(baseDir, uploadPath);
        
        // Additional path validation
        if (!uploadDir.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
            throw new SecurityException("Path traversal attempt detected");
        }
        
        if (!uploadDir.exists()) {
            uploadDir.mkdirs();
        }
        
        for (FileItem item : items) {
            if (!item.isFormField()) {
                String fileName = new File(item.getName()).getName(); // Get just the filename
                File uploadedFile = new File(uploadDir, fileName);
                item.write(uploadedFile);
            }
        }
    }
    
    // Apache Commons Net FTP with path validation
    @RequestMapping("/ftp-download-safe")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String remoteFile = request.getParameter("file");
        
        // Validate file path
        if (remoteFile == null || remoteFile.contains("..") || !remoteFile.matches("[a-zA-Z0-9_\\-\\.]+")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file path");
            return;
        }
        
        FTPClient ftpClient = new FTPClient();
        ftpClient.connect("ftp.example.com");
        ftpClient.login("user", "password");
        
        // ok: java-path-traversal
        InputStream inputStream = ftpClient.retrieveFileStream("/public/" + remoteFile);
        
        if (inputStream == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            ftpClient.disconnect();
            return;
        }
        
        IOUtils.copy(inputStream, response.getOutputStream());
        inputStream.close();
        ftpClient.disconnect();
    }
    
    // JSch SFTP with path validation
    @RequestMapping("/sftp-get-safe")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fileName = request.getParameter("file");
        
        // Validate filename
        if (fileName == null || fileName.contains("..") || !fileName.matches("[a-zA-Z0-9_\\-\\.]+")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
            return;
        }
        
        JSch jsch = new JSch();
        Session session = jsch.getSession("user", "sftp.example.com", 22);
        session.setPassword("password");
        session.connect();
        
        ChannelSftp channel = (ChannelSftp) session.openChannel("sftp");
        channel.connect();
        
        // ok: java-path-traversal
        InputStream is = channel.get("/home/user/files/" + fileName);
        
        IOUtils.copy(is, response.getOutputStream());
        is.close();
        channel.disconnect();
        session.disconnect();
    }
    
    // Apache Commons Compress with path validation
    @RequestMapping("/create-zip-safe")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] filesToZip = request.getParameterValues("files");
        response.setContentType("application/zip");
        response.setHeader("Content-Disposition", "attachment; filename=\"archive.zip\"");
        
        // Whitelist of allowed files
        Set<String> allowedFiles = new HashSet<>(Arrays.asList(
            "report.txt", "data.csv", "image.png", "document.pdf", "config.xml"
        ));
        
        ZipArchiveOutputStream zipOut = new ZipArchiveOutputStream(response.getOutputStream());
        File baseDir = new File("/var/data/");
        
        for (String fileName : filesToZip) {
            // Validate against whitelist
            if (!allowedFiles.contains(fileName)) {
                continue; // Skip unauthorized files
            }
            
            // ok: java-path-traversal
            File fileToZip = new File(baseDir, fileName);
            
            // Additional path validation
            if (!fileToZip.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
                continue; // Skip files outside base directory
            }
            
            if (fileToZip.exists() && fileToZip.isFile()) {
                ZipArchiveEntry zipEntry = new ZipArchiveEntry(fileToZip, fileToZip.getName());
                zipOut.putArchiveEntry(zipEntry);
                
                FileInputStream fis = new FileInputStream(fileToZip);
                IOUtils.copy(fis, zipOut);
                fis.close();
                zipOut.closeArchiveEntry();
            }
        }
        
        zipOut.close();
    }
}
// {/fact}