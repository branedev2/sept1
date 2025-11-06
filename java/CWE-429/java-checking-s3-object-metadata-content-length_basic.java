import java.io.*;
import java.util.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import org.apache.commons.io.IOUtils;
import javax.servlet.http.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class S3ContentLengthExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=s3-object-metadata-content-length-check@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        // Get file from HTTP request
        InputStream inputStream = request.getInputStream();
        
        // Creating object metadata without content length
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/octet-stream");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, key, inputStream, metadata);
    }
    
    public void bad_case_2() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
        String bucketName = "user-uploads";
        String key = "large-file.zip";
        
        File file = new File("/tmp/large-file.zip");
        InputStream fileStream = new FileInputStream(file);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/zip");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        PutObjectRequest request = new PutObjectRequest(bucketName, key, fileStream, metadata);
        s3Client.putObject(request);
    }
    
    public void bad_case_3(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = request.getParameter("bucket");
        String key = request.getParameter("key");
        
        Part filePart = request.getPart("file");
        InputStream fileContent = filePart.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType(filePart.getContentType());
        // Missing content length
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(new PutObjectRequest(bucketName, key, fileContent, metadata));
    }
    
    public void bad_case_4() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "data-bucket";
        String key = "generated-data.json";
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // Write some JSON data
        baos.write("{\"data\":\"example\"}".getBytes());
        InputStream inputStream = new ByteArrayInputStream(baos.toByteArray());
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/json");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, key, inputStream, metadata);
    }
    
    public void bad_case_5(HttpServletRequest request) throws Exception {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "user-content";
        String fileName = request.getParameter("fileName");
        
        InputStream is = request.getInputStream();
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType(request.getContentType());
        metadata.addUserMetadata("uploaded-by", request.getRemoteUser());
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, "uploads/" + fileName, is, metadata);
    }
    
    public void bad_case_6() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "config-bucket";
        
        // Create a temporary file with some content
        File tempFile = File.createTempFile("config", ".xml");
        FileWriter writer = new FileWriter(tempFile);
        writer.write("<config><setting>value</setting></config>");
        writer.close();
        
        InputStream fileStream = new FileInputStream(tempFile);
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/xml");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, "settings.xml", fileStream, metadata);
    }
    
    public void bad_case_7(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "image-bucket";
        
        // Get image from request
        InputStream imageStream = request.getInputStream();
        String imageName = request.getParameter("imageName");
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("image/jpeg");
        metadata.setCacheControl("max-age=31536000");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        PutObjectRequest putRequest = new PutObjectRequest(bucketName, "images/" + imageName, imageStream, metadata);
        s3Client.putObject(putRequest);
    }
    
    public void bad_case_8() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "log-bucket";
        String key = "app-logs/log-" + System.currentTimeMillis() + ".txt";
        
        // Create log content
        StringBuilder logBuilder = new StringBuilder();
        logBuilder.append("Timestamp: ").append(new Date()).append("\n");
        logBuilder.append("Log level: INFO\n");
        logBuilder.append("Message: Application started successfully\n");
        
        InputStream logStream = new ByteArrayInputStream(logBuilder.toString().getBytes());
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("text/plain");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, key, logStream, metadata);
    }
    
    public void bad_case_9(HttpServletRequest request) throws Exception {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "document-storage";
        
        Part documentPart = request.getPart("document");
        String documentName = Paths.get(documentPart.getSubmittedFileName()).getFileName().toString();
        InputStream documentContent = documentPart.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType(documentPart.getContentType());
        metadata.addUserMetadata("original-filename", documentName);
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, "documents/" + documentName, documentContent, metadata);
    }
    
    public void bad_case_10() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "backup-bucket";
        String key = "database-backup-" + System.currentTimeMillis() + ".sql";
        
        Process process = Runtime.getRuntime().exec("mysqldump -u root -p mydb");
        InputStream dumpStream = process.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/sql");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, key, dumpStream, metadata);
    }
    
    public void bad_case_11(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "user-profiles";
        String userId = request.getParameter("userId");
        
        // Get profile picture from request
        InputStream profilePicStream = request.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("image/png");
        metadata.setContentDisposition("inline; filename=profile.png");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, "users/" + userId + "/profile.png", profilePicStream, metadata);
    }
    
    public void bad_case_12() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "report-bucket";
        String reportKey = "monthly-report-" + System.currentTimeMillis() + ".pdf";
        
        // Generate PDF report
        ByteArrayOutputStream pdfOutput = new ByteArrayOutputStream();
        // ... code to generate PDF content in pdfOutput
        InputStream pdfStream = new ByteArrayInputStream(pdfOutput.toByteArray());
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/pdf");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, reportKey, pdfStream, metadata);
    }
    
    public void bad_case_13(HttpServletRequest request) throws Exception {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "video-storage";
        
        Part videoPart = request.getPart("video");
        String videoName = request.getParameter("videoName");
        InputStream videoStream = videoPart.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("video/mp4");
        metadata.addUserMetadata("uploaded-by", request.getRemoteUser());
        
        // ruleid: java-checking-s3-object-metadata-content-length
        PutObjectRequest putRequest = new PutObjectRequest(bucketName, "videos/" + videoName, videoStream, metadata);
        s3Client.putObject(putRequest);
    }
    
    public void bad_case_14() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "data-exports";
        String exportKey = "export-" + UUID.randomUUID().toString() + ".csv";
        
        // Generate CSV data
        StringBuilder csvBuilder = new StringBuilder();
        csvBuilder.append("id,name,email\n");
        csvBuilder.append("1,John Doe,john@example.com\n");
        csvBuilder.append("2,Jane Smith,jane@example.com\n");
        
        InputStream csvStream = new ByteArrayInputStream(csvBuilder.toString().getBytes());
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("text/csv");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, exportKey, csvStream, metadata);
    }
    
    public void bad_case_15(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "audio-storage";
        String audioKey = request.getParameter("audioName");
        
        InputStream audioStream = request.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("audio/mpeg");
        metadata.setCacheControl("public, max-age=86400");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(bucketName, "audio/" + audioKey, audioStream, metadata);
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        // Get file from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        // Creating object metadata with content length
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/octet-stream");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(bytes.length);
        
        InputStream dataStream = new ByteArrayInputStream(bytes);
        s3Client.putObject(bucketName, key, dataStream, metadata);
    }
    
    public void good_case_2() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
        String bucketName = "user-uploads";
        String key = "large-file.zip";
        
        File file = new File("/tmp/large-file.zip");
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/zip");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(file.length());
        
        InputStream fileStream = new FileInputStream(file);
        PutObjectRequest request = new PutObjectRequest(bucketName, key, fileStream, metadata);
        s3Client.putObject(request);
    }
    
    public void good_case_3(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = request.getParameter("bucket");
        String key = request.getParameter("key");
        
        Part filePart = request.getPart("file");
        InputStream fileContent = filePart.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType(filePart.getContentType());
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(filePart.getSize());
        
        s3Client.putObject(new PutObjectRequest(bucketName, key, fileContent, metadata));
    }
    
    public void good_case_4() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "data-bucket";
        String key = "generated-data.json";
        
        String jsonData = "{\"data\":\"example\"}";
        byte[] jsonBytes = jsonData.getBytes();
        InputStream inputStream = new ByteArrayInputStream(jsonBytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/json");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(jsonBytes.length);
        
        s3Client.putObject(bucketName, key, inputStream, metadata);
    }
    
    public void good_case_5(HttpServletRequest request) throws Exception {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "user-content";
        String fileName = request.getParameter("fileName");
        
        // Read all bytes from the input stream
        byte[] bytes = IOUtils.toByteArray(request.getInputStream());
        InputStream is = new ByteArrayInputStream(bytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType(request.getContentType());
        metadata.addUserMetadata("uploaded-by", request.getRemoteUser());
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(bytes.length);
        
        s3Client.putObject(bucketName, "uploads/" + fileName, is, metadata);
    }
    
    public void good_case_6() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "config-bucket";
        
        // Create a temporary file with some content
        File tempFile = File.createTempFile("config", ".xml");
        FileWriter writer = new FileWriter(tempFile);
        writer.write("<config><setting>value</setting></config>");
        writer.close();
        
        // ok: java-checking-s3-object-metadata-content-length
        PutObjectRequest request = new PutObjectRequest(bucketName, "settings.xml", tempFile);
        s3Client.putObject(request);
    }
    
    public void good_case_7(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "image-bucket";
        
        // Get image from request and read all bytes
        byte[] imageBytes = IOUtils.toByteArray(request.getInputStream());
        InputStream imageStream = new ByteArrayInputStream(imageBytes);
        String imageName = request.getParameter("imageName");
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("image/jpeg");
        metadata.setCacheControl("max-age=31536000");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(imageBytes.length);
        
        PutObjectRequest putRequest = new PutObjectRequest(bucketName, "images/" + imageName, imageStream, metadata);
        s3Client.putObject(putRequest);
    }
    
    public void good_case_8() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "log-bucket";
        String key = "app-logs/log-" + System.currentTimeMillis() + ".txt";
        
        // Create log content
        String logContent = "Timestamp: " + new Date() + "\n" +
                           "Log level: INFO\n" +
                           "Message: Application started successfully\n";
        byte[] logBytes = logContent.getBytes();
        InputStream logStream = new ByteArrayInputStream(logBytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("text/plain");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(logBytes.length);
        
        s3Client.putObject(bucketName, key, logStream, metadata);
    }
    
    public void good_case_9(HttpServletRequest request) throws Exception {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "document-storage";
        
        Part documentPart = request.getPart("document");
        String documentName = Paths.get(documentPart.getSubmittedFileName()).getFileName().toString();
        
        // Read document content into byte array
        byte[] documentBytes = IOUtils.toByteArray(documentPart.getInputStream());
        InputStream documentContent = new ByteArrayInputStream(documentBytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType(documentPart.getContentType());
        metadata.addUserMetadata("original-filename", documentName);
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(documentBytes.length);
        
        s3Client.putObject(bucketName, "documents/" + documentName, documentContent, metadata);
    }
    
    public void good_case_10() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "backup-bucket";
        String key = "database-backup-" + System.currentTimeMillis() + ".sql";
        
        Process process = Runtime.getRuntime().exec("mysqldump -u root -p mydb");
        byte[] dumpBytes = IOUtils.toByteArray(process.getInputStream());
        InputStream dumpStream = new ByteArrayInputStream(dumpBytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/sql");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(dumpBytes.length);
        
        s3Client.putObject(bucketName, key, dumpStream, metadata);
    }
    
    public void good_case_11(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "user-profiles";
        String userId = request.getParameter("userId");
        
        // Get profile picture from request and determine its size
        byte[] profileBytes = IOUtils.toByteArray(request.getInputStream());
        InputStream profilePicStream = new ByteArrayInputStream(profileBytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("image/png");
        metadata.setContentDisposition("inline; filename=profile.png");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(profileBytes.length);
        
        s3Client.putObject(bucketName, "users/" + userId + "/profile.png", profilePicStream, metadata);
    }
    
    public void good_case_12() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "report-bucket";
        String reportKey = "monthly-report-" + System.currentTimeMillis() + ".pdf";
        
        // Generate PDF report
        ByteArrayOutputStream pdfOutput = new ByteArrayOutputStream();
        // ... code to generate PDF content in pdfOutput
        byte[] pdfBytes = pdfOutput.toByteArray();
        InputStream pdfStream = new ByteArrayInputStream(pdfBytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/pdf");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(pdfBytes.length);
        
        s3Client.putObject(bucketName, reportKey, pdfStream, metadata);
    }
    
    public void good_case_13(HttpServletRequest request) throws Exception {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "video-storage";
        
        Part videoPart = request.getPart("video");
        String videoName = request.getParameter("videoName");
        
        // Use the part size directly
        InputStream videoStream = videoPart.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("video/mp4");
        metadata.addUserMetadata("uploaded-by", request.getRemoteUser());
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(videoPart.getSize());
        
        PutObjectRequest putRequest = new PutObjectRequest(bucketName, "videos/" + videoName, videoStream, metadata);
        s3Client.putObject(putRequest);
    }
    
    public void good_case_14() throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "data-exports";
        String exportKey = "export-" + UUID.randomUUID().toString() + ".csv";
        
        // Generate CSV data
        String csvData = "id,name,email\n" +
                        "1,John Doe,john@example.com\n" +
                        "2,Jane Smith,jane@example.com\n";
        byte[] csvBytes = csvData.getBytes();
        InputStream csvStream = new ByteArrayInputStream(csvBytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("text/csv");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(csvBytes.length);
        
        s3Client.putObject(bucketName, exportKey, csvStream, metadata);
    }
    
    public void good_case_15(HttpServletRequest request) throws IOException {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "audio-storage";
        String audioKey = request.getParameter("audioName");
        
        // Use a file directly instead of a stream
        File audioFile = new File("/tmp/audio-upload.mp3");
        
        // ok: java-checking-s3-object-metadata-content-length
        PutObjectRequest putRequest = new PutObjectRequest(bucketName, "audio/" + audioKey, audioFile);
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("audio/mpeg");
        metadata.setCacheControl("public, max-age=86400");
        putRequest.setMetadata(metadata);
        
        s3Client.putObject(putRequest);
    }
}
// {/fact}