import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.util.encoders.Hex;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.Files;
import org.springframework.util.DigestUtils;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import org.apache.commons.io.IOUtils;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.MD5Hash;
import org.apache.commons.net.util.Base64;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.net.URL;
import java.net.HttpURLConnection;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import java.util.Arrays;
import java.util.Base64;
import java.security.SecureRandom;
import java.util.UUID;

// Security Issue: Using insecure hashing algorithms like MD5 or SHA-1 for file checksums

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using standard Java MessageDigest with MD5 for file checksum
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    FileInputStream fis = new FileInputStream(file);
    // ruleid: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("MD5");
    
    byte[] dataBytes = new byte[1024];
    int nread = 0;
    while ((nread = fis.read(dataBytes)) != -1) {
        md.update(dataBytes, 0, nread);
    }
    byte[] mdbytes = md.digest();
    
    StringBuilder sb = new StringBuilder();
    for (byte mdbyte : mdbytes) {
        sb.append(Integer.toString((mdbyte & 0xff) + 0x100, 16).substring(1));
    }
    
    String fileChecksum = sb.toString();
    System.out.println("File checksum: " + fileChecksum);
    fis.close();
}

public void bad_case_2(HttpServletRequest request) throws IOException {
    // Using Apache Commons Codec DigestUtils with SHA-1
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ruleid: java-insecure-hashing-for-checksum
    String checksum = DigestUtils.sha1Hex(new FileInputStream(file));
    
    System.out.println("File checksum: " + checksum);
}

public void bad_case_3(HttpServletRequest request) throws IOException {
    // Using Google Guava with MD5
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ruleid: java-insecure-hashing-for-checksum
    HashFunction hashFunction = Hashing.md5();
    HashCode hashCode = Files.asByteSource(file).hash(hashFunction);
    String checksum = hashCode.toString();
    
    System.out.println("File checksum: " + checksum);
}

public void bad_case_4(HttpServletRequest request) throws IOException {
    // Using Spring Framework DigestUtils with MD5
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    FileInputStream fis = new FileInputStream(file);
    
    // ruleid: java-insecure-hashing-for-checksum
    String checksum = org.springframework.util.DigestUtils.md5DigestAsHex(fis);
    
    System.out.println("File checksum: " + checksum);
    fis.close();
}

public void bad_case_5(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using DigestInputStream with SHA-1
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ruleid: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    try (DigestInputStream dis = new DigestInputStream(new FileInputStream(file), md)) {
        byte[] buffer = new byte[8192];
        while (dis.read(buffer) != -1) {
            // Read the entire file
        }
    }
    
    byte[] digest = md.digest();
    String checksum = javax.xml.bind.DatatypeConverter.printHexBinary(digest).toLowerCase();
    System.out.println("File checksum: " + checksum);
}

public void bad_case_6(HttpServletRequest request) throws IOException {
    // Using BouncyCastle with MD5
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    byte[] fileData = Files.readAllBytes(file.toPath());
    
    // ruleid: java-insecure-hashing-for-checksum
    MD5Digest digest = new MD5Digest();
    digest.update(fileData, 0, fileData.length);
    byte[] md5Bytes = new byte[digest.getDigestSize()];
    digest.doFinal(md5Bytes, 0);
    
    String checksum = new String(Hex.encode(md5Bytes));
    System.out.println("File checksum: " + checksum);
}

public void bad_case_7(HttpServletRequest request) throws IOException {
    // Using Apache Hadoop MD5Hash
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    byte[] fileData = Files.readAllBytes(file.toPath());
    
    // ruleid: java-insecure-hashing-for-checksum
    MD5Hash md5Hash = MD5Hash.digest(fileData);
    String checksum = md5Hash.toString();
    
    System.out.println("File checksum: " + checksum);
}

public void bad_case_8(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using AWS S3 with MD5 checksum
    String filePath = request.getParameter("filePath");
    String bucketName = request.getParameter("bucket");
    String key = request.getParameter("key");
    
    File file = new File(filePath);
    AmazonS3 s3Client = null; // Normally initialized with credentials
    
    // ruleid: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] fileBytes = Files.readAllBytes(file.toPath());
    byte[] md5Bytes = md.digest(fileBytes);
    String md5Base64 = Base64.getEncoder().encodeToString(md5Bytes);
    
    ObjectMetadata metadata = new ObjectMetadata();
    metadata.setContentLength(file.length());
    metadata.setContentMD5(md5Base64);
    
    PutObjectRequest request = new PutObjectRequest(bucketName, key, file).withMetadata(metadata);
    // s3Client.putObject(request);
    
    System.out.println("File uploaded with MD5 checksum: " + md5Base64);
}

public void bad_case_9(HttpServletRequest request) throws IOException {
    // Using OkHttp to download file and compute SHA-1 checksum
    String url = request.getParameter("url");
    String filePath = request.getParameter("filePath");
    
    OkHttpClient client = new OkHttpClient();
    Request httpRequest = new Request.Builder().url(url).build();
    
    try (Response response = client.newCall(httpRequest).execute()) {
        if (response.isSuccessful() && response.body() != null) {
            byte[] fileData = response.body().bytes();
            Files.write(Paths.get(filePath), fileData);
            
            // ruleid: java-insecure-hashing-for-checksum
            String checksum = DigestUtils.sha1Hex(fileData);
            
            System.out.println("Downloaded file checksum: " + checksum);
        }
    }
}

public void bad_case_10(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using Apache HttpClient with MD5
    String url = request.getParameter("url");
    String filePath = request.getParameter("filePath");
    
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet httpGet = new HttpGet(url);
    
    byte[] fileData = EntityUtils.toByteArray(httpClient.execute(httpGet).getEntity());
    Files.write(Paths.get(filePath), fileData);
    
    // ruleid: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] digest = md.digest(fileData);
    String checksum = org.apache.commons.codec.binary.Hex.encodeHexString(digest);
    
    System.out.println("Downloaded file checksum: " + checksum);
    httpClient.close();
}

public void bad_case_11(HttpServletRequest request) throws IOException {
    // Using Java HttpURLConnection with SHA-1
    String url = request.getParameter("url");
    String filePath = request.getParameter("filePath");
    
    URL fileUrl = new URL(url);
    HttpURLConnection connection = (HttpURLConnection) fileUrl.openConnection();
    
    try (InputStream in = connection.getInputStream()) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        IOUtils.copy(in, out);
        byte[] fileData = out.toByteArray();
        Files.write(Paths.get(filePath), fileData);
        
        // ruleid: java-insecure-hashing-for-checksum
        String checksum = DigestUtils.sha1Hex(fileData);
        
        System.out.println("Downloaded file checksum: " + checksum);
    }
}

public void bad_case_12(HttpServletRequest request) throws IOException {
    // Using Jackson ObjectMapper to serialize object and compute MD5
    String filePath = request.getParameter("filePath");
    String name = request.getParameter("name");
    int age = Integer.parseInt(request.getParameter("age"));
    
    ObjectMapper mapper = new ObjectMapper();
    User user = new User(name, age);
    mapper.writeValue(new File(filePath), user);
    
    // ruleid: java-insecure-hashing-for-checksum
    String checksum = DigestUtils.md5Hex(new FileInputStream(filePath));
    
    System.out.println("File checksum: " + checksum);
}

public void bad_case_13(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using Java NIO with SHA-1
    String filePath = request.getParameter("filePath");
    Path path = Paths.get(filePath);
    byte[] fileData = Files.readAllBytes(path);
    
    // ruleid: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA1");
    byte[] digest = md.digest(fileData);
    
    StringBuilder sb = new StringBuilder();
    for (byte b : digest) {
        sb.append(String.format("%02x", b));
    }
    String checksum = sb.toString();
    
    System.out.println("File checksum: " + checksum);
}

public void bad_case_14(HttpServletRequest request) throws IOException {
    // Using Apache Commons IO with SHA-1
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ruleid: java-insecure-hashing-for-checksum
    String checksum = org.apache.commons.codec.digest.DigestUtils.sha1Hex(FileUtils.readFileToByteArray(file));
    
    System.out.println("File checksum: " + checksum);
}

public void bad_case_15(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using Java MessageDigest with incremental updates for SHA-1
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ruleid: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    
    try (InputStream is = new FileInputStream(file)) {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) > 0) {
            md.update(buffer, 0, read);
        }
    }
    
    byte[] digest = md.digest();
    StringBuilder sb = new StringBuilder();
    for (byte b : digest) {
        sb.append(String.format("%02x", b));
    }
    String checksum = sb.toString();
    
    System.out.println("File checksum: " + checksum);
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using standard Java MessageDigest with SHA-256 for file checksum
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    FileInputStream fis = new FileInputStream(file);
    // ok: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    
    byte[] dataBytes = new byte[1024];
    int nread = 0;
    while ((nread = fis.read(dataBytes)) != -1) {
        md.update(dataBytes, 0, nread);
    }
    byte[] mdbytes = md.digest();
    
    StringBuilder sb = new StringBuilder();
    for (byte mdbyte : mdbytes) {
        sb.append(Integer.toString((mdbyte & 0xff) + 0x100, 16).substring(1));
    }
    
    String fileChecksum = sb.toString();
    System.out.println("File checksum: " + fileChecksum);
    fis.close();
}

public void good_case_2(HttpServletRequest request) throws IOException {
    // Using Apache Commons Codec DigestUtils with SHA-256
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ok: java-insecure-hashing-for-checksum
    String checksum = DigestUtils.sha256Hex(new FileInputStream(file));
    
    System.out.println("File checksum: " + checksum);
}

public void good_case_3(HttpServletRequest request) throws IOException {
    // Using Google Guava with SHA-256
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ok: java-insecure-hashing-for-checksum
    HashFunction hashFunction = Hashing.sha256();
    HashCode hashCode = Files.asByteSource(file).hash(hashFunction);
    String checksum = hashCode.toString();
    
    System.out.println("File checksum: " + checksum);
}

public void good_case_4(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using DigestInputStream with SHA-512
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ok: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-512");
    try (DigestInputStream dis = new DigestInputStream(new FileInputStream(file), md)) {
        byte[] buffer = new byte[8192];
        while (dis.read(buffer) != -1) {
            // Read the entire file
        }
    }
    
    byte[] digest = md.digest();
    String checksum = javax.xml.bind.DatatypeConverter.printHexBinary(digest).toLowerCase();
    System.out.println("File checksum: " + checksum);
}

public void good_case_5(HttpServletRequest request) throws IOException {
    // Using BouncyCastle with SHA-256
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    byte[] fileData = Files.readAllBytes(file.toPath());
    
    // ok: java-insecure-hashing-for-checksum
    SHA256Digest digest = new SHA256Digest();
    digest.update(fileData, 0, fileData.length);
    byte[] sha256Bytes = new byte[digest.getDigestSize()];
    digest.doFinal(sha256Bytes, 0);
    
    String checksum = new String(Hex.encode(sha256Bytes));
    System.out.println("File checksum: " + checksum);
}

public void good_case_6(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using AWS S3 with SHA-256 checksum
    String filePath = request.getParameter("filePath");
    String bucketName = request.getParameter("bucket");
    String key = request.getParameter("key");
    
    File file = new File(filePath);
    AmazonS3 s3Client = null; // Normally initialized with credentials
    
    // ok: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] fileBytes = Files.readAllBytes(file.toPath());
    byte[] sha256Bytes = md.digest(fileBytes);
    String sha256Base64 = Base64.getEncoder().encodeToString(sha256Bytes);
    
    ObjectMetadata metadata = new ObjectMetadata();
    metadata.setContentLength(file.length());
    metadata.addUserMetadata("x-amz-checksum-sha256", sha256Base64);
    
    PutObjectRequest putRequest = new PutObjectRequest(bucketName, key, file).withMetadata(metadata);
    // s3Client.putObject(putRequest);
    
    System.out.println("File uploaded with SHA-256 checksum: " + sha256Base64);
}

public void good_case_7(HttpServletRequest request) throws IOException {
    // Using OkHttp to download file and compute SHA-384 checksum
    String url = request.getParameter("url");
    String filePath = request.getParameter("filePath");
    
    OkHttpClient client = new OkHttpClient();
    Request httpRequest = new Request.Builder().url(url).build();
    
    try (Response response = client.newCall(httpRequest).execute()) {
        if (response.isSuccessful() && response.body() != null) {
            byte[] fileData = response.body().bytes();
            Files.write(Paths.get(filePath), fileData);
            
            // ok: java-insecure-hashing-for-checksum
            String checksum = DigestUtils.sha384Hex(fileData);
            
            System.out.println("Downloaded file checksum: " + checksum);
        }
    }
}

public void good_case_8(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using Apache HttpClient with SHA-512
    String url = request.getParameter("url");
    String filePath = request.getParameter("filePath");
    
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet httpGet = new HttpGet(url);
    
    byte[] fileData = EntityUtils.toByteArray(httpClient.execute(httpGet).getEntity());
    Files.write(Paths.get(filePath), fileData);
    
    // ok: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-512");
    byte[] digest = md.digest(fileData);
    String checksum = org.apache.commons.codec.binary.Hex.encodeHexString(digest);
    
    System.out.println("Downloaded file checksum: " + checksum);
    httpClient.close();
}

public void good_case_9(HttpServletRequest request) throws IOException {
    // Using Java HttpURLConnection with SHA-256
    String url = request.getParameter("url");
    String filePath = request.getParameter("filePath");
    
    URL fileUrl = new URL(url);
    HttpURLConnection connection = (HttpURLConnection) fileUrl.openConnection();
    
    try (InputStream in = connection.getInputStream()) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        IOUtils.copy(in, out);
        byte[] fileData = out.toByteArray();
        Files.write(Paths.get(filePath), fileData);
        
        // ok: java-insecure-hashing-for-checksum
        String checksum = DigestUtils.sha256Hex(fileData);
        
        System.out.println("Downloaded file checksum: " + checksum);
    }
}

public void good_case_10(HttpServletRequest request) throws IOException {
    // Using Jackson ObjectMapper to serialize object and compute SHA-256
    String filePath = request.getParameter("filePath");
    String name = request.getParameter("name");
    int age = Integer.parseInt(request.getParameter("age"));
    
    ObjectMapper mapper = new ObjectMapper();
    User user = new User(name, age);
    mapper.writeValue(new File(filePath), user);
    
    // ok: java-insecure-hashing-for-checksum
    String checksum = DigestUtils.sha256Hex(new FileInputStream(filePath));
    
    System.out.println("File checksum: " + checksum);
}

public void good_case_11(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using Java NIO with SHA-384
    String filePath = request.getParameter("filePath");
    Path path = Paths.get(filePath);
    byte[] fileData = Files.readAllBytes(path);
    
    // ok: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-384");
    byte[] digest = md.digest(fileData);
    
    StringBuilder sb = new StringBuilder();
    for (byte b : digest) {
        sb.append(String.format("%02x", b));
    }
    String checksum = sb.toString();
    
    System.out.println("File checksum: " + checksum);
}

public void good_case_12(HttpServletRequest request) throws IOException {
    // Using Apache Commons IO with SHA-512
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ok: java-insecure-hashing-for-checksum
    String checksum = org.apache.commons.codec.digest.DigestUtils.sha512Hex(FileUtils.readFileToByteArray(file));
    
    System.out.println("File checksum: " + checksum);
}

public void good_case_13(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using Java MessageDigest with incremental updates for SHA-256
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ok: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    
    try (InputStream is = new FileInputStream(file)) {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) > 0) {
            md.update(buffer, 0, read);
        }
    }
    
    byte[] digest = md.digest();
    StringBuilder sb = new StringBuilder();
    for (byte b : digest) {
        sb.append(String.format("%02x", b));
    }
    String checksum = sb.toString();
    
    System.out.println("File checksum: " + checksum);
}

public void good_case_14(HttpServletRequest request) throws IOException {
    // Using CRC32 for non-security related checksum (acceptable for error detection)
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    byte[] fileData = Files.readAllBytes(file.toPath());
    
    // ok: java-insecure-hashing-for-checksum
    Checksum crc32 = new CRC32();
    crc32.update(fileData, 0, fileData.length);
    long checksumValue = crc32.getValue();
    
    System.out.println("CRC32 checksum: " + checksumValue);
}

public void good_case_15(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
    // Using SHA-224 for file checksum
    String filePath = request.getParameter("filePath");
    File file = new File(filePath);
    
    // ok: java-insecure-hashing-for-checksum
    MessageDigest md = MessageDigest.getInstance("SHA-224");
    byte[] fileData = Files.readAllBytes(file.toPath());
    byte[] digest = md.digest(fileData);
    
    String checksum = javax.xml.bind.DatatypeConverter.printHexBinary(digest);
    System.out.println("File checksum: " + checksum);
}

// Helper class for examples
class User {
    private String name;
    private int age;
    
    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public String getName() {
        return name;
    }
    
    public int getAge() {
        return age;
    }
}