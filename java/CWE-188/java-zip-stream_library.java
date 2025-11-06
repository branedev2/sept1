import java.io.*;
import java.util.zip.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.compress.archivers.zip.*;
import org.apache.commons.io.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.web.multipart.MultipartFile;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import java.nio.file.*;
import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.entity.mime.*;
import org.apache.http.entity.mime.content.*;
import com.google.cloud.storage.*;
import software.amazon.awssdk.services.s3.*;
import software.amazon.awssdk.services.s3.model.*;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import org.apache.commons.vfs2.*;
import net.lingala.zip4j.*;
import net.lingala.zip4j.model.*;
import java.util.*;

// Security Issue: Reading ZIP files using streaming can lead to security vulnerabilities (CWE-188)
// as it reads local headers instead of the central directory, allowing attackers to manipulate file names,
// permissions, or content, potentially bypassing security controls.

// True Positive Examples (Vulnerable/Insecure Code)

public class ZipStreamVulnerabilityExamples {

    // Using standard Java ZIP API with streaming
// {fact rule=unsafe-data-layout-reliance@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Get ZIP file from HTTP request
        Part filePart = request.getPart("zipFile");
        InputStream fileInputStream = filePart.getInputStream();
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(fileInputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            System.out.println("Processing file: " + fileName);
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using Apache Commons Compress with streaming
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Get ZIP file from HTTP request
        Part filePart = request.getPart("zipFile");
        InputStream fileInputStream = filePart.getInputStream();
        
        // ruleid: java-zip-stream
        org.apache.commons.compress.archivers.zip.ZipArchiveInputStream zipIn = 
            new org.apache.commons.compress.archivers.zip.ZipArchiveInputStream(fileInputStream);
        
        org.apache.commons.compress.archivers.zip.ZipArchiveEntry entry;
        while ((entry = zipIn.getNextZipEntry()) != null) {
            String fileName = entry.getName();
            System.out.println("Processing file: " + fileName);
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using Spring MVC for file upload with streaming
    @PostMapping("/upload")
    public void bad_case_3(@RequestParam("zipFile") MultipartFile file) throws Exception {
        InputStream fileInputStream = file.getInputStream();
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(fileInputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = zipIn.read(buffer)) > 0) {
                outputStream.write(buffer, 0, len);
            }
            // Use the extracted content
            System.out.println("Extracted: " + fileName);
        }
        zipIn.close();
    }
    
    // Using AWS S3 client with streaming
    public void bad_case_4() throws Exception {
        // Initialize S3 client
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // Get object from S3
        S3Object s3Object = s3Client.getObject("mybucket", "archive.zip");
        InputStream s3InputStream = s3Object.getObjectContent();
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(s3InputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
        s3InputStream.close();
    }
    
    // Using OkHttp client with streaming
    public void bad_case_5() throws Exception {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/files/archive.zip")
            .build();
            
        Response response = client.newCall(request).execute();
        if (response.isSuccessful() && response.body() != null) {
            InputStream inputStream = response.body().byteStream();
            
            // ruleid: java-zip-stream
            ZipInputStream zipIn = new ZipInputStream(inputStream);
            
            ZipEntry entry;
            while ((entry = zipIn.getNextEntry()) != null) {
                String fileName = entry.getName();
                // Process the file content
            }
            zipIn.close();
        }
    }
    
    // Using Retrofit client with streaming
    public void bad_case_6() throws Exception {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
            
        FileDownloadService service = retrofit.create(FileDownloadService.class);
        Call<ResponseBody> call = service.downloadFile("archive.zip");
        Response<ResponseBody> response = call.execute();
        
        if (response.isSuccessful() && response.body() != null) {
            InputStream inputStream = response.body().byteStream();
            
            // ruleid: java-zip-stream
            ZipInputStream zipIn = new ZipInputStream(inputStream);
            
            ZipEntry entry;
            while ((entry = zipIn.getNextEntry()) != null) {
                String fileName = entry.getName();
                // Process the file content
            }
            zipIn.close();
        }
    }
    
    // Using Apache HttpClient with streaming
    public void bad_case_7() throws Exception {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/files/archive.zip");
        
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                InputStream inputStream = entity.getContent();
                
                // ruleid: java-zip-stream
                ZipInputStream zipIn = new ZipInputStream(inputStream);
                
                ZipEntry entry;
                while ((entry = zipIn.getNextEntry()) != null) {
                    String fileName = entry.getName();
                    // Process the file content
                }
                zipIn.close();
            }
        }
    }
    
    // Using Google Cloud Storage with streaming
    public void bad_case_8() throws Exception {
        Storage storage = StorageOptions.getDefaultInstance().getService();
        Blob blob = storage.get("bucket-name", "archive.zip");
        
        InputStream inputStream = new ByteArrayInputStream(blob.getContent());
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(inputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using AWS SDK v2 with streaming
    public void bad_case_9() throws Exception {
        S3Client s3 = S3Client.builder().build();
        
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
            .bucket("mybucket")
            .key("archive.zip")
            .build();
            
        ResponseInputStream<GetObjectResponse> s3Object = s3.getObject(getObjectRequest);
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(s3Object);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using Azure Blob Storage with streaming
    public void bad_case_10() throws Exception {
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
            
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container-name");
        BlobClient blobClient = containerClient.getBlobClient("archive.zip");
        
        InputStream inputStream = blobClient.openInputStream();
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(inputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using Apache Commons VFS with streaming
    public void bad_case_11() throws Exception {
        FileSystemManager fsManager = VFS.getManager();
        FileObject zipFile = fsManager.resolveFile("https://example.com/files/archive.zip");
        
        InputStream inputStream = zipFile.getContent().getInputStream();
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(inputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using URL connection with streaming
    public void bad_case_12() throws Exception {
        URL url = new URL("https://example.com/files/archive.zip");
        URLConnection connection = url.openConnection();
        InputStream inputStream = connection.getInputStream();
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(inputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using Servlet input stream with buffering but still streaming
    public void bad_case_13(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("zipFile");
        InputStream fileInputStream = filePart.getInputStream();
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(bufferedInputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using Apache Commons IO with streaming
    public void bad_case_14() throws Exception {
        URL url = new URL("https://example.com/files/archive.zip");
        InputStream inputStream = url.openStream();
        
        // Using Apache Commons IO for buffering but still streaming
        InputStream bufferedIn = org.apache.commons.io.IOUtils.toBufferedInputStream(inputStream);
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(bufferedIn);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
    }
    
    // Using Java NIO with streaming
    public void bad_case_15() throws Exception {
        URL url = new URL("https://example.com/files/archive.zip");
        ReadableByteChannel readableByteChannel = Channels.newChannel(url.openStream());
        
        // Using a channel but still streaming
        InputStream inputStream = Channels.newInputStream(readableByteChannel);
        
        // ruleid: java-zip-stream
        ZipInputStream zipIn = new ZipInputStream(inputStream);
        
        ZipEntry entry;
        while ((entry = zipIn.getNextEntry()) != null) {
            String fileName = entry.getName();
            // Process the file content
        }
        zipIn.close();
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Using standard Java ZIP API with ZipFile (non-streaming)
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Get ZIP file from HTTP request and save to temp file
        Part filePart = request.getPart("zipFile");
        File tempFile = File.createTempFile("upload", ".zip");
        try (InputStream input = filePart.getInputStream();
             OutputStream output = new FileOutputStream(tempFile)) {
            IOUtils.copy(input, output);
        }
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            System.out.println("Processing file: " + fileName);
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using Apache Commons Compress with ZipFile (non-streaming)
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Get ZIP file from HTTP request and save to temp file
        Part filePart = request.getPart("zipFile");
        File tempFile = File.createTempFile("upload", ".zip");
        try (InputStream input = filePart.getInputStream();
             OutputStream output = new FileOutputStream(tempFile)) {
            IOUtils.copy(input, output);
        }
        
        // ok: java-zip-stream
        org.apache.commons.compress.archivers.zip.ZipFile zipFile = 
            new org.apache.commons.compress.archivers.zip.ZipFile(tempFile);
        
        Enumeration<org.apache.commons.compress.archivers.zip.ZipArchiveEntry> entries = zipFile.getEntries();
        while (entries.hasMoreElements()) {
            org.apache.commons.compress.archivers.zip.ZipArchiveEntry entry = entries.nextElement();
            String fileName = entry.getName();
            System.out.println("Processing file: " + fileName);
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using Spring MVC for file upload with ZipFile (non-streaming)
    @PostMapping("/upload-safe")
    public void good_case_3(@RequestParam("zipFile") MultipartFile file) throws Exception {
        // Save uploaded file to temp location
        File tempFile = File.createTempFile("upload", ".zip");
        file.transferTo(tempFile);
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content safely
            InputStream entryStream = zipFile.getInputStream(entry);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = entryStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, len);
            }
            entryStream.close();
            // Use the extracted content
            System.out.println("Extracted: " + fileName);
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using AWS S3 client with ZipFile (non-streaming)
    public void good_case_4() throws Exception {
        // Initialize S3 client
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // Download object from S3 to temp file
        File tempFile = File.createTempFile("s3download", ".zip");
        s3Client.getObject(new GetObjectRequest("mybucket", "archive.zip"), tempFile);
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using OkHttp client with ZipFile (non-streaming)
    public void good_case_5() throws Exception {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/files/archive.zip")
            .build();
            
        Response response = client.newCall(request).execute();
        if (response.isSuccessful() && response.body() != null) {
            // Save to temp file
            File tempFile = File.createTempFile("download", ".zip");
            try (InputStream inputStream = response.body().byteStream();
                 FileOutputStream outputStream = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
            
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(tempFile);
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String fileName = entry.getName();
                // Process the file content
            }
            zipFile.close();
            tempFile.delete();
        }
    }
    
    // Using Retrofit client with ZipFile (non-streaming)
    public void good_case_6() throws Exception {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
            
        FileDownloadService service = retrofit.create(FileDownloadService.class);
        Call<ResponseBody> call = service.downloadFile("archive.zip");
        Response<ResponseBody> response = call.execute();
        
        if (response.isSuccessful() && response.body() != null) {
            // Save to temp file
            File tempFile = File.createTempFile("download", ".zip");
            try (InputStream inputStream = response.body().byteStream();
                 FileOutputStream outputStream = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
            
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(tempFile);
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String fileName = entry.getName();
                // Process the file content
            }
            zipFile.close();
            tempFile.delete();
        }
    }
    
    // Using Apache HttpClient with ZipFile (non-streaming)
    public void good_case_7() throws Exception {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/files/archive.zip");
        
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                // Save to temp file
                File tempFile = File.createTempFile("download", ".zip");
                try (InputStream inputStream = entity.getContent();
                     FileOutputStream outputStream = new FileOutputStream(tempFile)) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }
                
                // ok: java-zip-stream
                ZipFile zipFile = new ZipFile(tempFile);
                
                Enumeration<? extends ZipEntry> entries = zipFile.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String fileName = entry.getName();
                    // Process the file content
                }
                zipFile.close();
                tempFile.delete();
            }
        }
    }
    
    // Using Google Cloud Storage with ZipFile (non-streaming)
    public void good_case_8() throws Exception {
        Storage storage = StorageOptions.getDefaultInstance().getService();
        Blob blob = storage.get("bucket-name", "archive.zip");
        
        // Save to temp file
        File tempFile = File.createTempFile("gcs-download", ".zip");
        try (OutputStream outputStream = new FileOutputStream(tempFile)) {
            outputStream.write(blob.getContent());
        }
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using AWS SDK v2 with ZipFile (non-streaming)
    public void good_case_9() throws Exception {
        S3Client s3 = S3Client.builder().build();
        
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
            .bucket("mybucket")
            .key("archive.zip")
            .build();
            
        // Save to temp file
        File tempFile = File.createTempFile("s3v2-download", ".zip");
        s3.getObject(getObjectRequest, ResponseTransformer.toFile(tempFile));
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using Azure Blob Storage with ZipFile (non-streaming)
    public void good_case_10() throws Exception {
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
            
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container-name");
        BlobClient blobClient = containerClient.getBlobClient("archive.zip");
        
        // Save to temp file
        File tempFile = File.createTempFile("azure-download", ".zip");
        blobClient.downloadToFile(tempFile.getAbsolutePath(), true);
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using Apache Commons VFS with ZipFile (non-streaming)
    public void good_case_11() throws Exception {
        FileSystemManager fsManager = VFS.getManager();
        FileObject zipFile = fsManager.resolveFile("https://example.com/files/archive.zip");
        
        // Save to temp file
        File tempFile = File.createTempFile("vfs-download", ".zip");
        try (InputStream inputStream = zipFile.getContent().getInputStream();
             OutputStream outputStream = new FileOutputStream(tempFile)) {
            IOUtils.copy(inputStream, outputStream);
        }
        
        // ok: java-zip-stream
        ZipFile secureZipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = secureZipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content
        }
        secureZipFile.close();
        tempFile.delete();
    }
    
    // Using URL connection with ZipFile (non-streaming)
    public void good_case_12() throws Exception {
        URL url = new URL("https://example.com/files/archive.zip");
        URLConnection connection = url.openConnection();
        
        // Save to temp file
        File tempFile = File.createTempFile("url-download", ".zip");
        try (InputStream inputStream = connection.getInputStream();
             OutputStream outputStream = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using Zip4j library (non-streaming)
    public void good_case_13(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("zipFile");
        File tempFile = File.createTempFile("upload", ".zip");
        try (InputStream input = filePart.getInputStream();
             OutputStream output = new FileOutputStream(tempFile)) {
            IOUtils.copy(input, output);
        }
        
        // ok: java-zip-stream
        net.lingala.zip4j.ZipFile zipFile = new net.lingala.zip4j.ZipFile(tempFile);
        
        List<FileHeader> fileHeaders = zipFile.getFileHeaders();
        for (FileHeader fileHeader : fileHeaders) {
            String fileName = fileHeader.getFileName();
            // Process the file content
            InputStream inputStream = zipFile.getInputStream(fileHeader);
            // Use the input stream
            inputStream.close();
        }
        tempFile.delete();
    }
    
    // Using Java NIO with ZipFile (non-streaming)
    public void good_case_14() throws Exception {
        URL url = new URL("https://example.com/files/archive.zip");
        ReadableByteChannel readableByteChannel = Channels.newChannel(url.openStream());
        
        // Save to temp file using NIO
        File tempFile = File.createTempFile("nio-download", ".zip");
        try (FileOutputStream fileOutputStream = new FileOutputStream(tempFile)) {
            fileOutputStream.getChannel().transferFrom(readableByteChannel, 0, Long.MAX_VALUE);
        }
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Using Servlet input stream with ZipFile (non-streaming)
    public void good_case_15(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("zipFile");
        
        // Save to temp file
        File tempFile = File.createTempFile("servlet-upload", ".zip");
        try (InputStream inputStream = filePart.getInputStream();
             FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
        
        // ok: java-zip-stream
        ZipFile zipFile = new ZipFile(tempFile);
        
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String fileName = entry.getName();
            // Process the file content
        }
        zipFile.close();
        tempFile.delete();
    }
    
    // Interface for Retrofit example
    interface FileDownloadService {
        @GET("files/{filename}")
        Call<ResponseBody> downloadFile(@Path("filename") String filename);
    }
}
// {/fact}