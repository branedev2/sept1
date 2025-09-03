import java.io.*;
import java.net.*;
import java.util.*;
import java.nio.file.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.io.*;
import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.core.io.*;
import org.springframework.http.*;
import org.springframework.web.client.*;
import java.util.zip.*;
import com.fasterxml.jackson.databind.*;
import org.jsoup.*;
import org.jsoup.nodes.*;
import org.jsoup.select.*;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import com.google.cloud.storage.*;
import software.amazon.awssdk.services.s3.*;
import software.amazon.awssdk.services.s3.model.*;
import org.apache.commons.net.ftp.*;

// Security Issue: Not checking the result of InputStream.skip() can lead to incomplete data skipping,
// potentially causing data corruption, incorrect processing, or security vulnerabilities.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Standard Java IO with servlet input
    InputStream inputStream = request.getInputStream();
    byte[] buffer = new byte[1024];
    
    // ruleid: java-inputstreamcheckresultofskip
    inputStream.skip(2); // Not checking result of skip
    
    int bytesRead = inputStream.read(buffer);
    response.getOutputStream().write(buffer, 0, bytesRead);
    inputStream.close();
}

public void bad_case_2() throws IOException {
    // Apache HttpClient example
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet httpGet = new HttpGet("https://example.com/data.bin");
    
    try (CloseableHttpResponse httpResponse = httpClient.execute(httpGet)) {
        InputStream inputStream = httpResponse.getEntity().getContent();
        
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(10); // Header bytes to skip
        
        byte[] buffer = new byte[4096];
        int bytesRead;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        System.out.println("Data received: " + outputStream.size() + " bytes");
    }
}

public void bad_case_3() throws IOException {
    // OkHttp client example
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url("https://example.com/large-file.zip")
            .build();
    
    try (Response response = client.newCall(request).execute()) {
        if (response.isSuccessful() && response.body() != null) {
            InputStream inputStream = response.body().byteStream();
            
            // ruleid: java-inputstreamcheckresultofskip
            inputStream.skip(42); // Skip file header
            
            // Process ZIP file content
            ZipInputStream zipInputStream = new ZipInputStream(inputStream);
            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                System.out.println("Found entry: " + entry.getName());
            }
        }
    }
}

public void bad_case_4() throws IOException {
    // AWS S3 SDK example
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    S3Object s3Object = s3Client.getObject("mybucket", "large-document.pdf");
    
    try (InputStream inputStream = s3Object.getObjectContent()) {
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(5); // Skip PDF header
        
        // Process PDF content
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            // Process PDF data
            System.out.println("Processing " + bytesRead + " bytes of PDF data");
        }
    }
}

public void bad_case_5() throws IOException {
    // Spring RestTemplate example
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<Resource> response = restTemplate.getForEntity(
            "https://example.com/audio.mp3", Resource.class);
    
    if (response.getStatusCode() == HttpStatus.OK) {
        try (InputStream inputStream = response.getBody().getInputStream()) {
            // ruleid: java-inputstreamcheckresultofskip
            inputStream.skip(128); // Skip ID3 tag
            
            // Process MP3 audio data
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                // Process audio data
                System.out.println("Processing " + bytesRead + " bytes of audio data");
            }
        }
    }
}

public void bad_case_6() throws IOException {
    // Google HTTP Client Library
    HttpTransport httpTransport = new NetHttpTransport();
    HttpRequestFactory requestFactory = httpTransport.createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://example.com/image.jpg"));
    
    try (InputStream inputStream = request.execute().getContent()) {
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(20); // Skip JPEG header
        
        // Process image data
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            // Process image data
            System.out.println("Processing " + bytesRead + " bytes of image data");
        }
    }
}

public void bad_case_7() throws IOException {
    // Apache Commons IO with URL connection
    URL url = new URL("https://example.com/data.csv");
    URLConnection connection = url.openConnection();
    
    try (InputStream inputStream = connection.getInputStream()) {
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(1); // Skip BOM marker
        
        // Read CSV data
        List<String> lines = IOUtils.readLines(inputStream, "UTF-8");
        for (String line : lines) {
            System.out.println("CSV row: " + line);
        }
    }
}

public void bad_case_8() throws IOException {
    // JSoup HTML parsing with HTTP
    Connection connection = Jsoup.connect("https://example.com/page.html");
    Document document = connection.get();
    
    // Extract embedded binary data from a custom data attribute
    String base64Data = document.select("div.data").attr("data-binary");
    byte[] binaryData = Base64.getDecoder().decode(base64Data);
    
    try (InputStream inputStream = new ByteArrayInputStream(binaryData)) {
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(4); // Skip custom header
        
        // Process the binary data
        byte[] buffer = new byte[1024];
        int bytesRead = inputStream.read(buffer);
        System.out.println("Read " + bytesRead + " bytes of embedded binary data");
    }
}

public void bad_case_9() throws IOException {
    // Azure Blob Storage SDK
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container");
    BlobClient blobClient = containerClient.getBlobClient("data.bin");
    
    try (InputStream inputStream = blobClient.openInputStream()) {
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(16); // Skip custom header
        
        // Process the blob data
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            System.out.println("Processing " + bytesRead + " bytes from Azure Blob");
        }
    }
}

public void bad_case_10() throws IOException {
    // Google Cloud Storage
    Storage storage = StorageOptions.getDefaultInstance().getService();
    Blob blob = storage.get("bucket-name", "object-name");
    
    try (InputStream inputStream = new ByteArrayInputStream(blob.getContent())) {
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(8); // Skip file signature
        
        // Process the GCS data
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            System.out.println("Processing " + bytesRead + " bytes from GCS");
        }
    }
}

public void bad_case_11() throws IOException {
    // Retrofit HTTP client
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
    
    // Assume we have a service interface and got a response with binary data
    ResponseBody responseBody = ResponseBody.create(MediaType.get("application/octet-stream"), 
            "binary-data-here".getBytes());
    
    try (InputStream inputStream = responseBody.byteStream()) {
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(2); // Skip version bytes
        
        // Process the API response data
        byte[] buffer = new byte[1024];
        int bytesRead = inputStream.read(buffer);
        System.out.println("Read " + bytesRead + " bytes from API");
    }
}

public void bad_case_12() throws IOException {
    // Apache FTP client
    FTPClient ftpClient = new FTPClient();
    ftpClient.connect("ftp.example.com");
    ftpClient.login("username", "password");
    ftpClient.setFileType(FTP.BINARY_FILE_TYPE);
    
    InputStream inputStream = ftpClient.retrieveFileStream("/path/to/file.dat");
    if (inputStream != null) {
        try {
            // ruleid: java-inputstreamcheckresultofskip
            inputStream.skip(24); // Skip file header
            
            // Process the FTP file data
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                System.out.println("Processing " + bytesRead + " bytes from FTP");
            }
        } finally {
            inputStream.close();
            ftpClient.completePendingCommand();
            ftpClient.disconnect();
        }
    }
}

public void bad_case_13() throws IOException {
    // Jackson ObjectMapper with HTTP input
    URL url = new URL("https://api.example.com/data.json");
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("GET");
    
    try (InputStream inputStream = connection.getInputStream()) {
        // Assume we need to skip a custom byte order mark or prefix
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(3); // Skip custom prefix
        
        // Parse JSON
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> data = mapper.readValue(inputStream, Map.class);
        System.out.println("Parsed JSON with " + data.size() + " entries");
    }
}

public void bad_case_14() throws IOException {
    // AWS SDK v2
    S3Client s3 = S3Client.builder().build();
    GetObjectRequest getObjectRequest = GetObjectRequest.builder()
            .bucket("my-bucket")
            .key("my-object")
            .build();
    
    try (InputStream inputStream = s3.getObject(getObjectRequest)) {
        // ruleid: java-inputstreamcheckresultofskip
        inputStream.skip(100); // Skip metadata section
        
        // Process the S3 object data
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            System.out.println("Processing " + bytesRead + " bytes from S3");
        }
    }
}

public void bad_case_15() throws IOException {
    // NIO Files with HTTP downloaded content
    URL url = new URL("https://example.com/download.dat");
    Path tempFile = Files.createTempFile("download", ".tmp");
    
    try (InputStream webStream = url.openStream()) {
        Files.copy(webStream, tempFile, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
    }
    
    try (InputStream fileStream = Files.newInputStream(tempFile)) {
        // ruleid: java-inputstreamcheckresultofskip
        fileStream.skip(12); // Skip file header
        
        // Process the downloaded file
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = fileStream.read(buffer)) != -1) {
            System.out.println("Processing " + bytesRead + " bytes from downloaded file");
        }
    }
    
    Files.delete(tempFile);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Standard Java IO with servlet input - properly checking skip result
    InputStream inputStream = request.getInputStream();
    byte[] buffer = new byte[1024];
    
    // ok: java-inputstreamcheckresultofskip
    long bytesToSkip = 2;
    long bytesSkipped = 0;
    while (bytesSkipped < bytesToSkip) {
        long result = inputStream.skip(bytesToSkip - bytesSkipped);
        if (result <= 0) break; // No more bytes can be skipped
        bytesSkipped += result;
    }
    
    int bytesRead = inputStream.read(buffer);
    response.getOutputStream().write(buffer, 0, bytesRead);
    inputStream.close();
}

public void good_case_2() throws IOException {
    // Apache HttpClient example with proper skip checking
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet httpGet = new HttpGet("https://example.com/data.bin");
    
    try (CloseableHttpResponse httpResponse = httpClient.execute(httpGet)) {
        InputStream inputStream = httpResponse.getEntity().getContent();
        
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 10;
        long bytesSkipped = 0;
        while (bytesSkipped < bytesToSkip) {
            long result = inputStream.skip(bytesToSkip - bytesSkipped);
            if (result <= 0) break;
            bytesSkipped += result;
        }
        
        byte[] buffer = new byte[4096];
        int bytesRead;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        System.out.println("Data received: " + outputStream.size() + " bytes");
    }
}

public void good_case_3() throws IOException {
    // OkHttp client example with proper skip checking
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url("https://example.com/large-file.zip")
            .build();
    
    try (Response response = client.newCall(request).execute()) {
        if (response.isSuccessful() && response.body() != null) {
            InputStream inputStream = response.body().byteStream();
            
            // ok: java-inputstreamcheckresultofskip
            long bytesToSkip = 42;
            long bytesSkipped = 0;
            while (bytesSkipped < bytesToSkip) {
                long result = inputStream.skip(bytesToSkip - bytesSkipped);
                if (result <= 0) {
                    System.out.println("Warning: Could not skip all requested bytes");
                    break;
                }
                bytesSkipped += result;
            }
            
            // Process ZIP file content
            ZipInputStream zipInputStream = new ZipInputStream(inputStream);
            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                System.out.println("Found entry: " + entry.getName());
            }
        }
    }
}

public void good_case_4() throws IOException {
    // AWS S3 SDK example with proper skip checking
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    S3Object s3Object = s3Client.getObject("mybucket", "large-document.pdf");
    
    try (InputStream inputStream = s3Object.getObjectContent()) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 5;
        long totalSkipped = 0;
        while (totalSkipped < bytesToSkip) {
            long skipped = inputStream.skip(bytesToSkip - totalSkipped);
            if (skipped <= 0) {
                System.err.println("Failed to skip required bytes in PDF header");
                break;
            }
            totalSkipped += skipped;
        }
        
        // Process PDF content
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            // Process PDF data
            System.out.println("Processing " + bytesRead + " bytes of PDF data");
        }
    }
}

public void good_case_5() throws IOException {
    // Spring RestTemplate example with proper skip checking
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<Resource> response = restTemplate.getForEntity(
            "https://example.com/audio.mp3", Resource.class);
    
    if (response.getStatusCode() == HttpStatus.OK) {
        try (InputStream inputStream = response.getBody().getInputStream()) {
            // ok: java-inputstreamcheckresultofskip
            long bytesToSkip = 128;
            long skippedSoFar = 0;
            while (skippedSoFar < bytesToSkip) {
                long skipped = inputStream.skip(bytesToSkip - skippedSoFar);
                if (skipped <= 0) {
                    System.err.println("Could not skip ID3 tag completely");
                    break;
                }
                skippedSoFar += skipped;
            }
            
            // Process MP3 audio data
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                // Process audio data
                System.out.println("Processing " + bytesRead + " bytes of audio data");
            }
        }
    }
}

public void good_case_6() throws IOException {
    // Google HTTP Client Library with proper skip checking
    HttpTransport httpTransport = new NetHttpTransport();
    HttpRequestFactory requestFactory = httpTransport.createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://example.com/image.jpg"));
    
    try (InputStream inputStream = request.execute().getContent()) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 20;
        long skippedTotal = 0;
        while (skippedTotal < bytesToSkip) {
            long skippedNow = inputStream.skip(bytesToSkip - skippedTotal);
            if (skippedNow <= 0) {
                System.err.println("Failed to skip JPEG header completely");
                break;
            }
            skippedTotal += skippedNow;
        }
        
        // Process image data
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            // Process image data
            System.out.println("Processing " + bytesRead + " bytes of image data");
        }
    }
}

public void good_case_7() throws IOException {
    // Apache Commons IO with URL connection and proper skip checking
    URL url = new URL("https://example.com/data.csv");
    URLConnection connection = url.openConnection();
    
    try (InputStream inputStream = connection.getInputStream()) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 1;
        long skippedBytes = 0;
        while (skippedBytes < bytesToSkip) {
            long skipped = inputStream.skip(bytesToSkip - skippedBytes);
            if (skipped <= 0) {
                System.err.println("Could not skip BOM marker");
                break;
            }
            skippedBytes += skipped;
        }
        
        // Read CSV data
        List<String> lines = IOUtils.readLines(inputStream, "UTF-8");
        for (String line : lines) {
            System.out.println("CSV row: " + line);
        }
    }
}

public void good_case_8() throws IOException {
    // JSoup HTML parsing with HTTP and proper skip checking
    Connection connection = Jsoup.connect("https://example.com/page.html");
    Document document = connection.get();
    
    // Extract embedded binary data from a custom data attribute
    String base64Data = document.select("div.data").attr("data-binary");
    byte[] binaryData = Base64.getDecoder().decode(base64Data);
    
    try (InputStream inputStream = new ByteArrayInputStream(binaryData)) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 4;
        long totalSkipped = 0;
        while (totalSkipped < bytesToSkip) {
            long skipped = inputStream.skip(bytesToSkip - totalSkipped);
            if (skipped <= 0) {
                System.err.println("Could not skip custom header completely");
                break;
            }
            totalSkipped += skipped;
        }
        
        // Process the binary data
        byte[] buffer = new byte[1024];
        int bytesRead = inputStream.read(buffer);
        System.out.println("Read " + bytesRead + " bytes of embedded binary data");
    }
}

public void good_case_9() throws IOException {
    // Azure Blob Storage SDK with proper skip checking
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container");
    BlobClient blobClient = containerClient.getBlobClient("data.bin");
    
    try (InputStream inputStream = blobClient.openInputStream()) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 16;
        long skippedTotal = 0;
        while (skippedTotal < bytesToSkip) {
            long skippedNow = inputStream.skip(bytesToSkip - skippedTotal);
            if (skippedNow <= 0) {
                System.err.println("Failed to skip custom header completely");
                break;
            }
            skippedTotal += skippedNow;
        }
        
        // Process the blob data
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            System.out.println("Processing " + bytesRead + " bytes from Azure Blob");
        }
    }
}

public void good_case_10() throws IOException {
    // Google Cloud Storage with proper skip checking
    Storage storage = StorageOptions.getDefaultInstance().getService();
    Blob blob = storage.get("bucket-name", "object-name");
    
    try (InputStream inputStream = new ByteArrayInputStream(blob.getContent())) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 8;
        long skippedSoFar = 0;
        while (skippedSoFar < bytesToSkip) {
            long skipped = inputStream.skip(bytesToSkip - skippedSoFar);
            if (skipped <= 0) {
                System.err.println("Could not skip file signature completely");
                break;
            }
            skippedSoFar += skipped;
        }
        
        // Process the GCS data
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            System.out.println("Processing " + bytesRead + " bytes from GCS");
        }
    }
}

public void good_case_11() throws IOException {
    // Retrofit HTTP client with proper skip checking
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
    
    // Assume we have a service interface and got a response with binary data
    ResponseBody responseBody = ResponseBody.create(MediaType.get("application/octet-stream"), 
            "binary-data-here".getBytes());
    
    try (InputStream inputStream = responseBody.byteStream()) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 2;
        long bytesSkipped = 0;
        while (bytesSkipped < bytesToSkip) {
            long result = inputStream.skip(bytesToSkip - bytesSkipped);
            if (result <= 0) {
                System.err.println("Failed to skip version bytes");
                break;
            }
            bytesSkipped += result;
        }
        
        // Process the API response data
        byte[] buffer = new byte[1024];
        int bytesRead = inputStream.read(buffer);
        System.out.println("Read " + bytesRead + " bytes from API");
    }
}

public void good_case_12() throws IOException {
    // Apache FTP client with proper skip checking
    FTPClient ftpClient = new FTPClient();
    ftpClient.connect("ftp.example.com");
    ftpClient.login("username", "password");
    ftpClient.setFileType(FTP.BINARY_FILE_TYPE);
    
    InputStream inputStream = ftpClient.retrieveFileStream("/path/to/file.dat");
    if (inputStream != null) {
        try {
            // ok: java-inputstreamcheckresultofskip
            long bytesToSkip = 24;
            long skippedTotal = 0;
            while (skippedTotal < bytesToSkip) {
                long skipped = inputStream.skip(bytesToSkip - skippedTotal);
                if (skipped <= 0) {
                    System.err.println("Failed to skip file header completely");
                    break;
                }
                skippedTotal += skipped;
            }
            
            // Process the FTP file data
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                System.out.println("Processing " + bytesRead + " bytes from FTP");
            }
        } finally {
            inputStream.close();
            ftpClient.completePendingCommand();
            ftpClient.disconnect();
        }
    }
}

public void good_case_13() throws IOException {
    // Jackson ObjectMapper with HTTP input and proper skip checking
    URL url = new URL("https://api.example.com/data.json");
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("GET");
    
    try (InputStream inputStream = connection.getInputStream()) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 3;
        long skippedSoFar = 0;
        while (skippedSoFar < bytesToSkip) {
            long skipped = inputStream.skip(bytesToSkip - skippedSoFar);
            if (skipped <= 0) {
                System.err.println("Could not skip custom prefix completely");
                break;
            }
            skippedSoFar += skipped;
        }
        
        // Parse JSON
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> data = mapper.readValue(inputStream, Map.class);
        System.out.println("Parsed JSON with " + data.size() + " entries");
    }
}

public void good_case_14() throws IOException {
    // AWS SDK v2 with proper skip checking
    S3Client s3 = S3Client.builder().build();
    GetObjectRequest getObjectRequest = GetObjectRequest.builder()
            .bucket("my-bucket")
            .key("my-object")
            .build();
    
    try (InputStream inputStream = s3.getObject(getObjectRequest)) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 100;
        long skippedBytes = 0;
        while (skippedBytes < bytesToSkip) {
            long result = inputStream.skip(bytesToSkip - skippedBytes);
            if (result <= 0) {
                System.err.println("Failed to skip metadata section completely");
                break;
            }
            skippedBytes += result;
        }
        
        // Process the S3 object data
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            System.out.println("Processing " + bytesRead + " bytes from S3");
        }
    }
}

public void good_case_15() throws IOException {
    // NIO Files with HTTP downloaded content and proper skip checking
    URL url = new URL("https://example.com/download.dat");
    Path tempFile = Files.createTempFile("download", ".tmp");
    
    try (InputStream webStream = url.openStream()) {
        Files.copy(webStream, tempFile, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
    }
    
    try (InputStream fileStream = Files.newInputStream(tempFile)) {
        // ok: java-inputstreamcheckresultofskip
        long bytesToSkip = 12;
        long skippedTotal = 0;
        while (skippedTotal < bytesToSkip) {
            long skipped = fileStream.skip(bytesToSkip - skippedTotal);
            if (skipped <= 0) {
                System.err.println("Failed to skip file header completely");
                break;
            }
            skippedTotal += skipped;
        }
        
        // Process the downloaded file
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = fileStream.read(buffer)) != -1) {
            System.out.println("Processing " + bytesRead + " bytes from downloaded file");
        }
    }
    
    Files.delete(tempFile);
}