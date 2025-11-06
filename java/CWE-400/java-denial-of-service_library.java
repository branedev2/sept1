import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.io.*;
import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import java.nio.file.*;
import com.fasterxml.jackson.databind.*;
import org.jsoup.*;
import org.jsoup.nodes.*;
import java.util.concurrent.*;
import java.util.zip.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.*;
import com.google.cloud.storage.*;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import org.apache.commons.csv.*;

// Security Issue: Denial of Service via Unbounded readLine() Operations

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using Java Servlet API to read HTTP request content without limiting lines
    String url = request.getParameter("url");
    URL resourceUrl = new URL(url);
    BufferedReader reader = new BufferedReader(new InputStreamReader(resourceUrl.openStream()));
    StringBuilder content = new StringBuilder();
    String line;
    
    // ruleid: java-denial-of-service
    while ((line = reader.readLine()) != null) {
        content.append(line).append("\n");
    }
    
    response.getWriter().write("Content: " + content.toString());
    reader.close();
}

public void bad_case_2() throws IOException {
    // Using Apache HttpClient to read response without limiting lines
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet request = new HttpGet("http://example.com/large-file.txt");
    
    try (CloseableHttpResponse response = httpClient.execute(request)) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
        StringBuilder result = new StringBuilder();
        String line;
        
        // ruleid: java-denial-of-service
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }
        
        System.out.println("Response content: " + result.toString());
    }
}

@RestController
public class bad_case_3 {
    // Using Spring MVC framework to process uploaded file without line limits
    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()));
            List<String> lines = new ArrayList<>();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            
            return ResponseEntity.ok("Processed " + lines.size() + " lines");
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing file");
        }
    }
}

public void bad_case_4() throws IOException {
    // Using OkHttp library to read response without limiting lines
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url("https://example.com/large-data.txt")
            .build();
    
    try (Response response = client.newCall(request).execute()) {
        if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);
        
        BufferedReader reader = new BufferedReader(response.body().charStream());
        StringBuilder content = new StringBuilder();
        String line;
        
        // ruleid: java-denial-of-service
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        
        System.out.println("Content size: " + content.length());
    }
}

public void bad_case_5() throws IOException {
    // Using AWS S3 SDK to read object content without limiting lines
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    S3Object s3Object = s3Client.getObject("mybucket", "large-log-file.txt");
    
    BufferedReader reader = new BufferedReader(new InputStreamReader(s3Object.getObjectContent()));
    List<String> logEntries = new ArrayList<>();
    String line;
    
    // ruleid: java-denial-of-service
    while ((line = reader.readLine()) != null) {
        logEntries.add(line);
    }
    
    System.out.println("Processed " + logEntries.size() + " log entries");
    reader.close();
}

public void bad_case_6() throws IOException {
    // Using JSoup to parse HTML from URL without limiting lines
    String url = "http://example.com/large-page.html";
    Document doc = Jsoup.connect(url).get();
    String htmlContent = doc.html();
    
    BufferedReader reader = new BufferedReader(new StringReader(htmlContent));
    List<String> htmlLines = new ArrayList<>();
    String line;
    
    // ruleid: java-denial-of-service
    while ((line = reader.readLine()) != null) {
        htmlLines.add(line);
    }
    
    System.out.println("HTML has " + htmlLines.size() + " lines");
}

public void bad_case_7(HttpServletRequest request) throws IOException {
    // Using Jackson to parse JSON from HTTP request without limiting lines
    String jsonUrl = request.getParameter("jsonUrl");
    URL url = new URL(jsonUrl);
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    StringBuilder jsonContent = new StringBuilder();
    String line;
    
    // ruleid: java-denial-of-service
    while ((line = reader.readLine()) != null) {
        jsonContent.append(line);
    }
    
    ObjectMapper mapper = new ObjectMapper();
    JsonNode rootNode = mapper.readTree(jsonContent.toString());
    System.out.println("Parsed JSON with " + rootNode.size() + " root elements");
}

public void bad_case_8() throws IOException {
    // Using Retrofit HTTP client without limiting response lines
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
    
    ExampleService service = retrofit.create(ExampleService.class);
    Call<ResponseBody> call = service.getLargeData();
    Response<ResponseBody> response = call.execute();
    
    if (response.isSuccessful() && response.body() != null) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(response.body().byteStream()));
        StringBuilder result = new StringBuilder();
        String line;
        
        // ruleid: java-denial-of-service
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }
        
        System.out.println("API response size: " + result.length());
    }
}

interface ExampleService {
    @GET("large-data")
    Call<ResponseBody> getLargeData();
}

public void bad_case_9() throws IOException, InterruptedException {
    // Using Java ProcessBuilder to read command output without limiting lines
    ProcessBuilder processBuilder = new ProcessBuilder("curl", "http://example.com/large-file.txt");
    Process process = processBuilder.start();
    
    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    StringBuilder output = new StringBuilder();
    String line;
    
    // ruleid: java-denial-of-service
    while ((line = reader.readLine()) != null) {
        output.append(line).append("\n");
    }
    
    int exitCode = process.waitFor();
    System.out.println("Command output: " + output.toString());
}

public void bad_case_10() throws IOException {
    // Using Google Cloud Storage client to read file without limiting lines
    Storage storage = StorageOptions.getDefaultInstance().getService();
    Blob blob = storage.get("my-bucket", "large-file.txt");
    
    BufferedReader reader = new BufferedReader(new InputStreamReader(
            new ByteArrayInputStream(blob.getContent())));
    List<String> fileLines = new ArrayList<>();
    String line;
    
    // ruleid: java-denial-of-service
    while ((line = reader.readLine()) != null) {
        fileLines.add(line);
    }
    
    System.out.println("Cloud storage file has " + fileLines.size() + " lines");
}

public void bad_case_11() throws IOException {
    // Using Azure Blob Storage client to read file without limiting lines
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
    
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container");
    BlobClient blobClient = containerClient.getBlobClient("large-file.txt");
    
    try (InputStream inputStream = blobClient.openInputStream();
         BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
        
        StringBuilder content = new StringBuilder();
        String line;
        
        // ruleid: java-denial-of-service
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        
        System.out.println("Azure blob content length: " + content.length());
    }
}

public void bad_case_12() throws IOException {
    // Using ZipInputStream to read entries without limiting lines
    URL url = new URL("http://example.com/archive.zip");
    ZipInputStream zipIn = new ZipInputStream(url.openStream());
    ZipEntry entry;
    
    while ((entry = zipIn.getNextEntry()) != null) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(zipIn));
        StringBuilder entryContent = new StringBuilder();
        String line;
        
        // ruleid: java-denial-of-service
        while ((line = reader.readLine()) != null) {
            entryContent.append(line).append("\n");
        }
        
        System.out.println("Entry " + entry.getName() + " content: " + entryContent.toString());
    }
    zipIn.close();
}

public void bad_case_13() throws Exception {
    // Using XML parser to read XML without limiting lines
    URL url = new URL("http://example.com/large.xml");
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    StringBuilder xmlContent = new StringBuilder();
    String line;
    
    // ruleid: java-denial-of-service
    while ((line = reader.readLine()) != null) {
        xmlContent.append(line);
    }
    
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document document = builder.parse(new InputSource(new StringReader(xmlContent.toString())));
    System.out.println("XML root element: " + document.getDocumentElement().getNodeName());
}

public void bad_case_14() throws IOException {
    // Using Apache Commons CSV to read CSV without limiting lines
    URL url = new URL("http://example.com/large-data.csv");
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    StringBuilder csvContent = new StringBuilder();
    String line;
    
    // ruleid: java-denial-of-service
    while ((line = reader.readLine()) != null) {
        csvContent.append(line).append("\n");
    }
    
    CSVParser csvParser = CSVFormat.DEFAULT.parse(new StringReader(csvContent.toString()));
    for (CSVRecord record : csvParser) {
        System.out.println("Record: " + record.toString());
    }
}

public void bad_case_15() throws IOException {
    // Using Java NIO to read file from URL without limiting lines
    URL url = new URL("http://example.com/large-file.txt");
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    Path tempFile = Files.createTempFile("downloaded", ".txt");
    
    try (BufferedWriter writer = Files.newBufferedWriter(tempFile)) {
        String line;
        
        // ruleid: java-denial-of-service
        while ((line = reader.readLine()) != null) {
            writer.write(line);
            writer.newLine();
        }
    }
    
    System.out.println("File downloaded to: " + tempFile.toString());
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using Java Servlet API with line limit
    String url = request.getParameter("url");
    URL resourceUrl = new URL(url);
    BufferedReader reader = new BufferedReader(new InputStreamReader(resourceUrl.openStream()));
    StringBuilder content = new StringBuilder();
    String line;
    int lineCount = 0;
    final int MAX_LINES = 10000;
    
    // ok: java-denial-of-service
    while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
        content.append(line).append("\n");
        lineCount++;
    }
    
    if (lineCount >= MAX_LINES) {
        content.append("... (truncated after " + MAX_LINES + " lines)");
    }
    
    response.getWriter().write("Content: " + content.toString());
    reader.close();
}

public void good_case_2() throws IOException {
    // Using Apache HttpClient with line limit
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet request = new HttpGet("http://example.com/large-file.txt");
    
    try (CloseableHttpResponse response = httpClient.execute(request)) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
        StringBuilder result = new StringBuilder();
        String line;
        int lineCount = 0;
        final int MAX_LINES = 5000;
        
        // ok: java-denial-of-service
        while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
            result.append(line);
            lineCount++;
        }
        
        System.out.println("Response content (limited to " + MAX_LINES + " lines): " + result.toString());
    }
}

@RestController
public class good_case_3 {
    // Using Spring MVC framework with line limit for uploaded file
    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()));
            List<String> lines = new ArrayList<>();
            String line;
            int lineCount = 0;
            final int MAX_LINES = 1000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                lines.add(line);
                lineCount++;
            }
            
            String message = "Processed " + lines.size() + " lines";
            if (lineCount >= MAX_LINES) {
                message += " (file truncated at " + MAX_LINES + " lines)";
            }
            
            return ResponseEntity.ok(message);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing file");
        }
    }
}

public void good_case_4() throws IOException {
    // Using OkHttp library with line limit
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url("https://example.com/large-data.txt")
            .build();
    
    try (Response response = client.newCall(request).execute()) {
        if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);
        
        BufferedReader reader = new BufferedReader(response.body().charStream());
        StringBuilder content = new StringBuilder();
        String line;
        int lineCount = 0;
        final int MAX_LINES = 2000;
        
        // ok: java-denial-of-service
        while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
            content.append(line).append("\n");
            lineCount++;
        }
        
        System.out.println("Content size (limited to " + MAX_LINES + " lines): " + content.length());
    }
}

public void good_case_5() throws IOException {
    // Using AWS S3 SDK with line limit
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    S3Object s3Object = s3Client.getObject("mybucket", "large-log-file.txt");
    
    BufferedReader reader = new BufferedReader(new InputStreamReader(s3Object.getObjectContent()));
    List<String> logEntries = new ArrayList<>();
    String line;
    int lineCount = 0;
    final int MAX_LINES = 5000;
    
    // ok: java-denial-of-service
    while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
        logEntries.add(line);
        lineCount++;
    }
    
    String message = "Processed " + logEntries.size() + " log entries";
    if (lineCount >= MAX_LINES) {
        message += " (truncated at " + MAX_LINES + " lines)";
    }
    
    System.out.println(message);
    reader.close();
}

public void good_case_6() throws IOException {
    // Using JSoup with line limit
    String url = "http://example.com/large-page.html";
    Document doc = Jsoup.connect(url).get();
    String htmlContent = doc.html();
    
    BufferedReader reader = new BufferedReader(new StringReader(htmlContent));
    List<String> htmlLines = new ArrayList<>();
    String line;
    int lineCount = 0;
    final int MAX_LINES = 10000;
    
    // ok: java-denial-of-service
    while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
        htmlLines.add(line);
        lineCount++;
    }
    
    String message = "HTML has " + htmlLines.size() + " lines";
    if (lineCount >= MAX_LINES) {
        message += " (truncated at " + MAX_LINES + " lines)";
    }
    
    System.out.println(message);
}

public void good_case_7(HttpServletRequest request) throws IOException {
    // Using Jackson with line limit
    String jsonUrl = request.getParameter("jsonUrl");
    URL url = new URL(jsonUrl);
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    StringBuilder jsonContent = new StringBuilder();
    String line;
    int lineCount = 0;
    final int MAX_LINES = 1000;
    
    // ok: java-denial-of-service
    while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
        jsonContent.append(line);
        lineCount++;
    }
    
    if (lineCount >= MAX_LINES) {
        System.out.println("Warning: JSON content truncated at " + MAX_LINES + " lines");
    }
    
    ObjectMapper mapper = new ObjectMapper();
    JsonNode rootNode = mapper.readTree(jsonContent.toString());
    System.out.println("Parsed JSON with " + rootNode.size() + " root elements");
}

public void good_case_8() throws IOException {
    // Using Retrofit HTTP client with line limit
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
    
    ExampleService service = retrofit.create(ExampleService.class);
    Call<ResponseBody> call = service.getLargeData();
    Response<ResponseBody> response = call.execute();
    
    if (response.isSuccessful() && response.body() != null) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(response.body().byteStream()));
        StringBuilder result = new StringBuilder();
        String line;
        int lineCount = 0;
        final int MAX_LINES = 2000;
        
        // ok: java-denial-of-service
        while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
            result.append(line);
            lineCount++;
        }
        
        System.out.println("API response size (limited to " + MAX_LINES + " lines): " + result.length());
    }
}

public void good_case_9() throws IOException, InterruptedException {
    // Using Java ProcessBuilder with line limit
    ProcessBuilder processBuilder = new ProcessBuilder("curl", "http://example.com/large-file.txt");
    Process process = processBuilder.start();
    
    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    StringBuilder output = new StringBuilder();
    String line;
    int lineCount = 0;
    final int MAX_LINES = 500;
    
    // ok: java-denial-of-service
    while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
        output.append(line).append("\n");
        lineCount++;
    }
    
    if (lineCount >= MAX_LINES) {
        output.append("... (output truncated after " + MAX_LINES + " lines)");
    }
    
    int exitCode = process.waitFor();
    System.out.println("Command output: " + output.toString());
}

public void good_case_10() throws IOException {
    // Using Google Cloud Storage client with line limit
    Storage storage = StorageOptions.getDefaultInstance().getService();
    Blob blob = storage.get("my-bucket", "large-file.txt");
    
    BufferedReader reader = new BufferedReader(new InputStreamReader(
            new ByteArrayInputStream(blob.getContent())));
    List<String> fileLines = new ArrayList<>();
    String line;
    int lineCount = 0;
    final int MAX_LINES = 5000;
    
    // ok: java-denial-of-service
    while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
        fileLines.add(line);
        lineCount++;
    }
    
    String message = "Cloud storage file has " + fileLines.size() + " lines";
    if (lineCount >= MAX_LINES) {
        message += " (truncated at " + MAX_LINES + " lines)";
    }
    
    System.out.println(message);
}

public void good_case_11() throws IOException {
    // Using Azure Blob Storage client with line limit
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
    
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container");
    BlobClient blobClient = containerClient.getBlobClient("large-file.txt");
    
    try (InputStream inputStream = blobClient.openInputStream();
         BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
        
        StringBuilder content = new StringBuilder();
        String line;
        int lineCount = 0;
        final int MAX_LINES = 3000;
        
        // ok: java-denial-of-service
        while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
            content.append(line).append("\n");
            lineCount++;
        }
        
        if (lineCount >= MAX_LINES) {
            content.append("... (content truncated after " + MAX_LINES + " lines)");
        }
        
        System.out.println("Azure blob content length: " + content.length());
    }
}

public void good_case_12() throws IOException {
    // Using ZipInputStream with line limit
    URL url = new URL("http://example.com/archive.zip");
    ZipInputStream zipIn = new ZipInputStream(url.openStream());
    ZipEntry entry;
    
    while ((entry = zipIn.getNextEntry()) != null) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(zipIn));
        StringBuilder entryContent = new StringBuilder();
        String line;
        int lineCount = 0;
        final int MAX_LINES = 1000;
        
        // ok: java-denial-of-service
        while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
            entryContent.append(line).append("\n");
            lineCount++;
        }
        
        if (lineCount >= MAX_LINES) {
            entryContent.append("... (entry content truncated after " + MAX_LINES + " lines)");
        }
        
        System.out.println("Entry " + entry.getName() + " content: " + entryContent.toString());
    }
    zipIn.close();
}

public void good_case_13() throws Exception {
    // Using XML parser with line limit
    URL url = new URL("http://example.com/large.xml");
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    StringBuilder xmlContent = new StringBuilder();
    String line;
    int lineCount = 0;
    final int MAX_LINES = 5000;
    
    // ok: java-denial-of-service
    while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
        xmlContent.append(line);
        lineCount++;
    }
    
    if (lineCount >= MAX_LINES) {
        System.out.println("Warning: XML content truncated at " + MAX_LINES + " lines");
    }
    
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document document = builder.parse(new InputSource(new StringReader(xmlContent.toString())));
    System.out.println("XML root element: " + document.getDocumentElement().getNodeName());
}

public void good_case_14() throws IOException {
    // Using Apache Commons CSV with line limit
    URL url = new URL("http://example.com/large-data.csv");
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    StringBuilder csvContent = new StringBuilder();
    String line;
    int lineCount = 0;
    final int MAX_LINES = 10000;
    
    // ok: java-denial-of-service
    while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
        csvContent.append(line).append("\n");
        lineCount++;
    }
    
    if (lineCount >= MAX_LINES) {
        System.out.println("Warning: CSV content truncated at " + MAX_LINES + " lines");
    }
    
    CSVParser csvParser = CSVFormat.DEFAULT.parse(new StringReader(csvContent.toString()));
    for (CSVRecord record : csvParser) {
        System.out.println("Record: " + record.toString());
    }
}

public void good_case_15() throws IOException {
    // Using Java NIO with line limit
    URL url = new URL("http://example.com/large-file.txt");
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    Path tempFile = Files.createTempFile("downloaded", ".txt");
    
    try (BufferedWriter writer = Files.newBufferedWriter(tempFile)) {
        String line;
        int lineCount = 0;
        final int MAX_LINES = 5000;
        
        // ok: java-denial-of-service
        while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
            writer.write(line);
            writer.newLine();
            lineCount++;
        }
        
        if (lineCount >= MAX_LINES) {
            writer.write("... (file truncated at " + MAX_LINES + " lines)");
        }
    }
    
    System.out.println("File downloaded to: " + tempFile.toString());
}