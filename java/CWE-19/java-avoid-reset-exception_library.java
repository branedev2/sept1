import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import com.amazonaws.services.s3.transfer.TransferManager;
import com.amazonaws.services.s3.transfer.TransferManagerBuilder;
import com.amazonaws.services.s3.transfer.Upload;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import org.apache.commons.io.IOUtils;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.bind.annotation.*;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.Response;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.core.http.HttpMethod;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.util.InputStreamContentProvider;
import org.eclipse.jetty.http.HttpMethod;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import software.amazon.awssdk.transfer.s3.S3TransferManager;
import software.amazon.awssdk.transfer.s3.model.UploadRequest;
import software.amazon.awssdk.transfer.s3.progress.LoggingTransferListener;

// Security Issue: Uploading objects to Amazon S3 using non-repeatable streams can lead to ResetException

// True Positive Examples (Vulnerable/Insecure Code)
public class S3ResetExceptionExamples {

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            InputStream inputStream = request.getInputStream();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", inputStream, new ObjectMetadata()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(@RequestParam("file") MultipartFile file) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            InputStream inputStream = file.getInputStream();
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(file.getSize());
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject("mybucket", "mykey", inputStream, metadata);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            URL url = new URL("https://example.com/large-file");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            InputStream inputStream = connection.getInputStream();
            
            TransferManager transferManager = TransferManagerBuilder.standard().build();
            ObjectMetadata metadata = new ObjectMetadata();
            
            // ruleid: java-avoid-reset-exception
            Upload upload = transferManager.upload("mybucket", "mykey", inputStream, metadata);
            upload.waitForCompletion();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("https://example.com/large-file");
            CloseableHttpResponse response = httpClient.execute(httpGet);
            HttpEntity entity = response.getEntity();
            InputStream inputStream = entity.getContent();
            
            S3Client s3Client = S3Client.builder().build();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(PutObjectRequest.builder()
                    .bucket("mybucket")
                    .key("mykey")
                    .build(), 
                    RequestBody.fromInputStream(inputStream, entity.getContentLength()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://example.com/large-file")
                    .build();
            
            Response response = client.newCall(request).execute();
            InputStream inputStream = response.body().byteStream();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            ObjectMetadata metadata = new ObjectMetadata();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", inputStream, metadata));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        try {
            ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
            FileItem fileItem = (FileItem) upload.parseRequest(request).get(0);
            InputStream inputStream = fileItem.getInputStream();
            
            AmazonS3 s3Client = new AmazonS3Client();
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(fileItem.getSize());
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject("mybucket", "mykey", inputStream, metadata);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            AsyncHttpClient asyncHttpClient = Dsl.asyncHttpClient();
            CompletableFuture<Response> future = asyncHttpClient.prepareGet("https://example.com/large-file")
                    .execute()
                    .toCompletableFuture();
            
            Response response = future.get();
            InputStream inputStream = new ByteArrayInputStream(response.getResponseBodyAsBytes());
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", inputStream, new ObjectMetadata()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            Vertx vertx = Vertx.vertx();
            WebClient client = WebClient.create(vertx);
            
            client.get(80, "example.com", "/large-file")
                .send(ar -> {
                    if (ar.succeeded()) {
                        HttpResponse<Buffer> response = ar.result();
                        InputStream inputStream = new ByteArrayInputStream(response.bodyAsBuffer().getBytes());
                        
                        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
                        ObjectMetadata metadata = new ObjectMetadata();
                        
                        // ruleid: java-avoid-reset-exception
                        s3Client.putObject("mybucket", "mykey", inputStream, metadata);
                    }
                });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            HttpClient httpClient = new HttpClient();
            httpClient.start();
            
            ContentResponse response = httpClient.newRequest("https://example.com/large-file")
                    .method(HttpMethod.GET)
                    .send();
            
            InputStream inputStream = new ByteArrayInputStream(response.getContent());
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // ruleid: java-avoid-reset-exception
            PutObjectResult result = s3Client.putObject("mybucket", "mykey", inputStream, new ObjectMetadata());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            URL url = new URL("https://example.com/large-file");
            InputStream inputStream = url.openStream();
            
            S3Client s3Client = S3Client.builder().build();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(PutObjectRequest.builder()
                    .bucket("mybucket")
                    .key("mykey")
                    .build(), 
                    RequestBody.fromInputStream(inputStream, -1));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            HttpClient httpClient = new HttpClient();
            httpClient.start();
            
            org.eclipse.jetty.client.api.Request request = httpClient.newRequest("https://example.com/large-file")
                    .method(HttpMethod.GET);
            
            InputStreamContentProvider provider = new InputStreamContentProvider(
                    request.send().getContentAsInputStream());
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", 
                    provider.getInputStream(), new ObjectMetadata()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        try {
            InputStream inputStream = request.getPart("file").getInputStream();
            
            TransferManager transferManager = TransferManagerBuilder.standard().build();
            ObjectMetadata metadata = new ObjectMetadata();
            
            // ruleid: java-avoid-reset-exception
            Upload upload = transferManager.upload(new PutObjectRequest("mybucket", "mykey", inputStream, metadata));
            upload.waitForCompletion();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            URL url = new URL("https://example.com/large-file");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            InputStream inputStream = connection.getInputStream();
            
            software.amazon.awssdk.transfer.s3.S3TransferManager transferManager = 
                    software.amazon.awssdk.transfer.s3.S3TransferManager.builder().build();
            
            // ruleid: java-avoid-reset-exception
            transferManager.upload(UploadRequest.builder()
                    .putObjectRequest(b -> b.bucket("mybucket").key("mykey"))
                    .requestBody(software.amazon.awssdk.core.sync.RequestBody.fromInputStream(
                            inputStream, connection.getContentLength()))
                    .build());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("https://example.com/large-file");
            CloseableHttpResponse response = httpClient.execute(httpGet);
            HttpEntity entity = response.getEntity();
            InputStream inputStream = entity.getContent();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            ObjectMetadata metadata = new ObjectMetadata();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", inputStream, metadata)
                    .withMetadata(metadata));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://example.com/large-file")
                    .build();
            
            Response response = client.newCall(request).execute();
            InputStream inputStream = response.body().byteStream();
            
            S3Client s3Client = S3Client.builder().build();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(r -> r.bucket("mybucket").key("mykey"), 
                    RequestBody.fromInputStream(inputStream, response.body().contentLength()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // Read the entire input stream into a byte array first
            byte[] bytes = IOUtils.toByteArray(request.getInputStream());
            InputStream repeatable = new ByteArrayInputStream(bytes);
            
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(bytes.length);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", repeatable, metadata));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(@RequestParam("file") MultipartFile file) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // Convert to byte array first to make it repeatable
            byte[] bytes = file.getBytes();
            InputStream repeatable = new ByteArrayInputStream(bytes);
            
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(bytes.length);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject("mybucket", "mykey", repeatable, metadata);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            URL url = new URL("https://example.com/large-file");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            // Save to a temporary file first
            Path tempFile = Files.createTempFile("s3upload", ".tmp");
            Files.copy(connection.getInputStream(), tempFile, java.nio.file.StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            
            TransferManager transferManager = TransferManagerBuilder.standard().build();
            
            // ok: java-avoid-reset-exception
            Upload upload = transferManager.upload("mybucket", "mykey", tempFile.toFile());
            upload.waitForCompletion();
            
            // Clean up
            Files.deleteIfExists(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("https://example.com/large-file");
            CloseableHttpResponse response = httpClient.execute(httpGet);
            HttpEntity entity = response.getEntity();
            
            // Save to byte array first
            byte[] bytes = IOUtils.toByteArray(entity.getContent());
            
            S3Client s3Client = S3Client.builder().build();
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(PutObjectRequest.builder()
                    .bucket("mybucket")
                    .key("mykey")
                    .build(), 
                    RequestBody.fromBytes(bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://example.com/large-file")
                    .build();
            
            Response response = client.newCall(request).execute();
            byte[] bytes = response.body().bytes(); // Get all bytes at once
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(bytes.length);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", 
                    new ByteArrayInputStream(bytes), metadata));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        try {
            ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
            FileItem fileItem = (FileItem) upload.parseRequest(request).get(0);
            
            // Write to a temporary file first
            File tempFile = File.createTempFile("s3upload", ".tmp");
            fileItem.write(tempFile);
            
            AmazonS3 s3Client = new AmazonS3Client();
            
            // ok: java-avoid-reset-exception
            s3Client.putObject("mybucket", "mykey", tempFile);
            
            // Clean up
            tempFile.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            AsyncHttpClient asyncHttpClient = Dsl.asyncHttpClient();
            CompletableFuture<Response> future = asyncHttpClient.prepareGet("https://example.com/large-file")
                    .execute()
                    .toCompletableFuture();
            
            Response response = future.get();
            byte[] bytes = response.getResponseBodyAsBytes();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(bytes.length);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", 
                    new ByteArrayInputStream(bytes), metadata));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            Vertx vertx = Vertx.vertx();
            WebClient client = WebClient.create(vertx);
            
            client.get(80, "example.com", "/large-file")
                .send(ar -> {
                    if (ar.succeeded()) {
                        HttpResponse<Buffer> response = ar.result();
                        byte[] bytes = response.bodyAsBuffer().getBytes();
                        
                        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
                        ObjectMetadata metadata = new ObjectMetadata();
                        metadata.setContentLength(bytes.length);
                        
                        // ok: java-avoid-reset-exception
                        s3Client.putObject("mybucket", "mykey", new ByteArrayInputStream(bytes), metadata);
                    }
                });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            HttpClient httpClient = new HttpClient();
            httpClient.start();
            
            ContentResponse response = httpClient.newRequest("https://example.com/large-file")
                    .method(HttpMethod.GET)
                    .send();
            
            byte[] content = response.getContent();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(content.length);
            
            // ok: java-avoid-reset-exception
            PutObjectResult result = s3Client.putObject("mybucket", "mykey", 
                    new ByteArrayInputStream(content), metadata);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            URL url = new URL("https://example.com/large-file");
            
            // Save to a temporary file first
            Path tempFile = Files.createTempFile("s3upload", ".tmp");
            Files.copy(url.openStream(), tempFile, java.nio.file.StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            
            S3Client s3Client = S3Client.builder().build();
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(PutObjectRequest.builder()
                    .bucket("mybucket")
                    .key("mykey")
                    .build(), 
                    RequestBody.fromFile(tempFile));
            
            // Clean up
            Files.deleteIfExists(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            HttpClient httpClient = new HttpClient();
            httpClient.start();
            
            ContentResponse response = httpClient.newRequest("https://example.com/large-file")
                    .method(HttpMethod.GET)
                    .send();
            
            byte[] content = response.getContent();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // Use TransferManager with a file
            File tempFile = File.createTempFile("s3upload", ".tmp");
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                fos.write(content);
            }
            
            TransferManager transferManager = TransferManagerBuilder.standard().withS3Client(s3Client).build();
            
            // ok: java-avoid-reset-exception
            Upload upload = transferManager.upload("mybucket", "mykey", tempFile);
            upload.waitForCompletion();
            
            // Clean up
            tempFile.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(HttpServletRequest request) {
        try {
            // Save part to a temporary file
            Path tempFile = Files.createTempFile("s3upload", ".tmp");
            try (InputStream in = request.getPart("file").getInputStream();
                 OutputStream out = Files.newOutputStream(tempFile)) {
                IOUtils.copy(in, out);
            }
            
            TransferManager transferManager = TransferManagerBuilder.standard().build();
            
            // ok: java-avoid-reset-exception
            Upload upload = transferManager.upload("mybucket", "mykey", tempFile.toFile());
            upload.waitForCompletion();
            
            // Clean up
            Files.deleteIfExists(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            URL url = new URL("https://example.com/large-file");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            // Save to a temporary file first
            Path tempFile = Files.createTempFile("s3upload", ".tmp");
            Files.copy(connection.getInputStream(), tempFile, java.nio.file.StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            
            software.amazon.awssdk.transfer.s3.S3TransferManager transferManager = 
                    software.amazon.awssdk.transfer.s3.S3TransferManager.builder().build();
            
            // ok: java-avoid-reset-exception
            transferManager.upload(UploadRequest.builder()
                    .putObjectRequest(b -> b.bucket("mybucket").key("mykey"))
                    .requestBody(software.amazon.awssdk.core.sync.RequestBody.fromFile(tempFile))
                    .addTransferListener(LoggingTransferListener.create())
                    .build());
            
            // Clean up
            Files.deleteIfExists(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("https://example.com/large-file");
            CloseableHttpResponse response = httpClient.execute(httpGet);
            HttpEntity entity = response.getEntity();
            
            // Save to a temporary file
            File tempFile = File.createTempFile("s3upload", ".tmp");
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                entity.writeTo(fos);
            }
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest("mybucket", "mykey", tempFile));
            
            // Clean up
            tempFile.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://example.com/large-file")
                    .build();
            
            Response response = client.newCall(request).execute();
            
            // Use a buffered approach with a temporary file
            Path tempFile = Files.createTempFile("s3upload", ".tmp");
            try (InputStream in = response.body().byteStream();
                 OutputStream out = Files.newOutputStream(tempFile)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            
            S3Client s3Client = S3Client.builder().build();
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(r -> r.bucket("mybucket").key("mykey"), 
                    RequestBody.fromFile(tempFile));
            
            // Clean up
            Files.deleteIfExists(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}