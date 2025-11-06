import java.io.*;
import java.net.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.amazonaws.AmazonClientException;
import org.apache.commons.io.IOUtils;
import java.nio.file.*;
import javax.servlet.http.*;
import java.util.Properties;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;

@Controller
public class S3StreamUploadExamples {

    // True Positives (Vulnerable Code)

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Getting input stream from HTTP request
            InputStream inputStream = request.getInputStream();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_2() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using FileInputStream directly
            InputStream inputStream = new FileInputStream("large-file.txt");
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @RequestMapping("/upload")
    public void bad_case_3(@RequestParam("file") MultipartFile file) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = file.getOriginalFilename();
            
            // Getting input stream from MultipartFile
            InputStream inputStream = file.getInputStream();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_4() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            URL url = new URL("http://example.com/large-file.zip");
            InputStream inputStream = url.openStream();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5(HttpServletRequest request) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Getting part of the input stream
            InputStream inputStream = request.getPart("file").getInputStream();
            
            // ruleid: java-avoid-reset-exception
            PutObjectRequest putRequest = new PutObjectRequest(bucketName, key, inputStream, new ObjectMetadata());
            s3Client.putObject(putRequest);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_6() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using socket input stream
            Socket socket = new Socket("example.com", 80);
            InputStream inputStream = socket.getInputStream();
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(new PutObjectRequest(bucketName, key, inputStream, new ObjectMetadata()));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using process input stream
            Process process = Runtime.getRuntime().exec("cat large-file.txt");
            InputStream inputStream = process.getInputStream();
            
            // ruleid: java-avoid-reset-exception
            ObjectMetadata metadata = new ObjectMetadata();
            s3Client.putObject(bucketName, key, inputStream, metadata);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using input stream from a JAR file
            URL url = getClass().getResource("/large-resource.bin");
            InputStream inputStream = url.openStream();
            
            // ruleid: java-avoid-reset-exception
            PutObjectRequest request = new PutObjectRequest(bucketName, key, inputStream, new ObjectMetadata());
            s3Client.putObject(request);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9(HttpServletRequest request) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = request.getParameter("bucket");
            String key = request.getParameter("key");
            
            // Using BufferedInputStream which doesn't solve the reset issue
            BufferedInputStream inputStream = new BufferedInputStream(request.getInputStream());
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_10() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using DataInputStream which doesn't solve the reset issue
            DataInputStream inputStream = new DataInputStream(new FileInputStream("large-file.dat"));
            
            // ruleid: java-avoid-reset-exception
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentType("application/octet-stream");
            s3Client.putObject(bucketName, key, inputStream, metadata);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using SequenceInputStream which doesn't solve the reset issue
            InputStream is1 = new FileInputStream("file1.txt");
            InputStream is2 = new FileInputStream("file2.txt");
            SequenceInputStream inputStream = new SequenceInputStream(is1, is2);
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            TransferManager transferManager = TransferManagerBuilder.standard().withS3Client(s3Client).build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using PipedInputStream which doesn't solve the reset issue
            PipedInputStream inputStream = new PipedInputStream();
            PipedOutputStream outputStream = new PipedOutputStream(inputStream);
            
            new Thread(() -> {
                try {
                    outputStream.write("Test data".getBytes());
                    outputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
            
            // ruleid: java-avoid-reset-exception
            Upload upload = transferManager.upload(bucketName, key, inputStream, new ObjectMetadata());
            upload.waitForCompletion();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_13() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using FilterInputStream which doesn't solve the reset issue
            InputStream baseStream = new FileInputStream("large-file.txt");
            FilterInputStream inputStream = new FilterInputStream(baseStream) {};
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using AudioInputStream which doesn't solve the reset issue
            File audioFile = new File("audio.wav");
            AudioInputStream inputStream = AudioSystem.getAudioInputStream(audioFile);
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_15() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using ObjectInputStream which doesn't solve the reset issue
            FileInputStream fileIn = new FileInputStream("object.ser");
            ObjectInputStream inputStream = new ObjectInputStream(fileIn);
            
            // ruleid: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negatives (Safe Code)
    
    public void good_case_1(HttpServletRequest request) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // First read all bytes from the input stream
            InputStream inputStream = request.getInputStream();
            byte[] bytes = IOUtils.toByteArray(inputStream);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, new ByteArrayInputStream(bytes), new ObjectMetadata());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_2() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using File object directly instead of stream
            File file = new File("large-file.txt");
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, file);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @RequestMapping("/upload")
    public void good_case_3(@RequestParam("file") MultipartFile file) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = file.getOriginalFilename();
            
            // Convert to byte array first
            byte[] bytes = file.getBytes();
            ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
            
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(bytes.length);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, metadata);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_4() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            URL url = new URL("http://example.com/large-file.zip");
            InputStream inputStream = url.openStream();
            
            // Save to temporary file first
            File tempFile = File.createTempFile("download", ".tmp");
            Files.copy(inputStream, tempFile.toPath(), StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, tempFile);
            tempFile.delete();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5(HttpServletRequest request) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Getting part of the input stream and converting to byte array
            InputStream inputStream = request.getPart("file").getInputStream();
            byte[] bytes = IOUtils.toByteArray(inputStream);
            
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(bytes.length);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, new ByteArrayInputStream(bytes), metadata);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using TransferManager with File
            TransferManager transferManager = TransferManagerBuilder.standard().withS3Client(s3Client).build();
            File file = new File("large-file.txt");
            
            // ok: java-avoid-reset-exception
            Upload upload = transferManager.upload(bucketName, key, file);
            upload.waitForCompletion();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using byte array directly
            byte[] data = "Hello, S3!".getBytes();
            ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
            
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(data.length);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, metadata);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using S3 multipart upload API
            File file = new File("large-file.txt");
            
            // ok: java-avoid-reset-exception
            InitiateMultipartUploadRequest initRequest = new InitiateMultipartUploadRequest(bucketName, key);
            InitiateMultipartUploadResult initResponse = s3Client.initiateMultipartUpload(initRequest);
            
            // Further implementation would include uploading parts and completing the upload
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_9(HttpServletRequest request) {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = request.getParameter("bucket");
            String key = request.getParameter("key");
            
            // Save to temporary file first
            InputStream inputStream = request.getInputStream();
            Path tempPath = Files.createTempFile("upload", ".tmp");
            Files.copy(inputStream, tempPath, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, tempPath.toFile());
            Files.delete(tempPath);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_10() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using S3 presigned URL for upload
            // ok: java-avoid-reset-exception
            GeneratePresignedUrlRequest generatePresignedUrlRequest = 
                new GeneratePresignedUrlRequest(bucketName, key)
                    .withMethod(HttpMethod.PUT)
                    .withExpiration(new Date(System.currentTimeMillis() + 3600000));
            
            URL url = s3Client.generatePresignedUrl(generatePresignedUrlRequest);
            // Client can upload directly to this URL
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using StringInputStream which is a ByteArrayInputStream under the hood
            String content = "This is the content to upload";
            InputStream inputStream = new ByteArrayInputStream(content.getBytes());
            
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(content.length());
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(bucketName, key, inputStream, metadata);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using FileChannel for efficient file transfer
            RandomAccessFile file = new RandomAccessFile("large-file.txt", "r");
            FileChannel channel = file.getChannel();
            
            // Read file into byte buffer
            ByteBuffer buffer = ByteBuffer.allocate((int)channel.size());
            channel.read(buffer);
            buffer.flip();
            
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            
            // ok: java-avoid-reset-exception
            ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(bytes.length);
            s3Client.putObject(bucketName, key, inputStream, metadata);
            
            channel.close();
            file.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using TransferManager with byte array
            TransferManager transferManager = TransferManagerBuilder.standard().withS3Client(s3Client).build();
            
            byte[] data = "Hello, S3!".getBytes();
            ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
            
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(data.length);
            
            // ok: java-avoid-reset-exception
            Upload upload = transferManager.upload(bucketName, key, inputStream, metadata);
            upload.waitForCompletion();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using PutObjectRequest with File
            File file = new File("large-file.txt");
            
            // ok: java-avoid-reset-exception
            PutObjectRequest request = new PutObjectRequest(bucketName, key, file);
            s3Client.putObject(request);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15() {
        try {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            // Using S3 client builder pattern with direct file upload
            File file = new File("large-file.txt");
            
            // ok: java-avoid-reset-exception
            s3Client.putObject(PutObjectRequest.builder()
                .bucket(bucketName)
                .key(key)
                .file(file)
                .build());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}