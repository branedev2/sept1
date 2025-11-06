import java.io.*;
import java.util.zip.*;
import java.net.*;
import java.nio.file.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.compress.archivers.zip.*;
import org.apache.commons.io.FilenameUtils;
import org.zeroturnaround.zip.*;
import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import org.rauschig.jarchivelib.Archiver;
import org.rauschig.jarchivelib.ArchiverFactory;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.commons.compress.utils.IOUtils;
import okhttp3.*;
import java.util.regex.Pattern;

// Security Issue: ZIP Entry Overwrite Vulnerability (Path Traversal in ZIP archives)

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using java.util.zip (standard library) without validation
    String zipFilePath = request.getParameter("zipFile");
    File zipFile = new File(zipFilePath);
    String extractPath = "/tmp/extracted/";
    
    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            File outputFile = new File(extractPath, entry.getName());
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void bad_case_2(HttpServletRequest request) throws IOException {
    // Using Apache Commons Compress without validation
    String zipFilePath = request.getParameter("zipFile");
    File zipFile = new File(zipFilePath);
    String extractPath = "/tmp/extracted/";
    
    try (ZipArchiveInputStream zis = new ZipArchiveInputStream(new FileInputStream(zipFile))) {
        ZipArchiveEntry entry;
        while ((entry = zis.getNextZipEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            File outputFile = new File(extractPath, entry.getName());
            
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

@PostMapping("/upload")
public void bad_case_3(@RequestParam("file") MultipartFile file) throws IOException {
    // Using Spring MVC with ZeroTurnaround ZipUtil without validation
    File tempFile = File.createTempFile("upload", ".zip");
    file.transferTo(tempFile);
    String extractPath = "/tmp/extracted/";
    
    // ruleid: java-zip-entry-overwrite
    ZipUtil.unpack(tempFile, new File(extractPath));
}

public void bad_case_4(HttpServletRequest request) throws ZipException {
    // Using Zip4j library without validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    
    // ruleid: java-zip-entry-overwrite
    ZipFile zipFile = new ZipFile(zipFilePath);
    zipFile.extractAll(extractPath);
}

public void bad_case_5(HttpServletRequest request) throws IOException {
    // Using JArchiveLib without validation
    String zipFilePath = request.getParameter("zipFile");
    File zipFile = new File(zipFilePath);
    File extractDir = new File("/tmp/extracted/");
    
    Archiver archiver = ArchiverFactory.createArchiver("zip");
    // ruleid: java-zip-entry-overwrite
    archiver.extract(zipFile, extractDir);
}

public void bad_case_6(HttpServletRequest request) throws IOException {
    // Using AWS S3 to download and extract zip without validation
    String bucketName = request.getParameter("bucket");
    String key = request.getParameter("key");
    String extractPath = "/tmp/extracted/";
    
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    S3Object s3Object = s3Client.getObject(bucketName, key);
    
    try (ZipInputStream zis = new ZipInputStream(s3Object.getObjectContent())) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            File outputFile = new File(extractPath, entry.getName());
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void bad_case_7(HttpServletRequest request) throws IOException {
    // Using Apache HttpClient to download and extract zip without validation
    String zipUrl = request.getParameter("zipUrl");
    String extractPath = "/tmp/extracted/";
    
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        HttpGet httpGet = new HttpGet(zipUrl);
        
        try (InputStream inputStream = httpClient.execute(httpGet).getEntity().getContent();
             ZipInputStream zis = new ZipInputStream(inputStream)) {
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // ruleid: java-zip-entry-overwrite
                File outputFile = new File(extractPath, entry.getName());
                
                try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                    IOUtils.copy(zis, fos);
                }
            }
        }
    }
}

public void bad_case_8(HttpServletRequest request) throws IOException {
    // Using OkHttp to download and extract zip without validation
    String zipUrl = request.getParameter("zipUrl");
    String extractPath = "/tmp/extracted/";
    
    OkHttpClient client = new OkHttpClient();
    Request okRequest = new Request.Builder().url(zipUrl).build();
    
    try (Response response = client.newCall(okRequest).execute();
         InputStream inputStream = response.body().byteStream();
         ZipInputStream zis = new ZipInputStream(inputStream)) {
        
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            File outputFile = new File(extractPath, entry.getName());
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void bad_case_9(HttpServletRequest request) throws IOException {
    // Using java.nio.file for ZIP extraction without validation
    String zipFilePath = request.getParameter("zipFile");
    Path zipPath = Paths.get(zipFilePath);
    Path extractPath = Paths.get("/tmp/extracted/");
    
    try (FileSystem zipFs = FileSystems.newFileSystem(zipPath, null)) {
        for (Path root : zipFs.getRootDirectories()) {
            Files.walk(root).forEach(source -> {
                try {
                    if (!Files.isDirectory(source)) {
                        Path target = extractPath.resolve(source.toString().substring(1));
                        // ruleid: java-zip-entry-overwrite
                        Files.createDirectories(target.getParent());
                        Files.copy(source, target, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

public void bad_case_10(HttpServletRequest request) throws IOException {
    // Using custom ZIP extraction with java.io without validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    
    byte[] buffer = new byte[1024];
    
    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath))) {
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            String fileName = zipEntry.getName();
            // ruleid: java-zip-entry-overwrite
            File newFile = new File(extractPath + File.separator + fileName);
            
            new File(newFile.getParent()).mkdirs();
            
            try (FileOutputStream fos = new FileOutputStream(newFile)) {
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
        zis.closeEntry();
    }
}

public void bad_case_11(HttpServletRequest request) throws IOException, ServletException {
    // Using servlet file upload and ZIP extraction without validation
    Part filePart = request.getPart("zipFile");
    String extractPath = "/tmp/extracted/";
    
    try (InputStream inputStream = filePart.getInputStream();
         ZipInputStream zis = new ZipInputStream(inputStream)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            File newFile = new File(extractPath + File.separator + zipEntry.getName());
            
            if (!newFile.getParentFile().exists()) {
                newFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(newFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void bad_case_12(HttpServletRequest request) throws IOException {
    // Using URL connection to download and extract ZIP without validation
    String zipUrl = request.getParameter("zipUrl");
    String extractPath = "/tmp/extracted/";
    
    URL url = new URL(zipUrl);
    URLConnection connection = url.openConnection();
    
    try (InputStream inputStream = connection.getInputStream();
         ZipInputStream zis = new ZipInputStream(inputStream)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            File newFile = new File(extractPath, zipEntry.getName());
            
            try (FileOutputStream fos = new FileOutputStream(newFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void bad_case_13(HttpServletRequest request) throws IOException {
    // Using BufferedInputStream with ZipInputStream without validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    
    try (FileInputStream fis = new FileInputStream(zipFilePath);
         BufferedInputStream bis = new BufferedInputStream(fis);
         ZipInputStream zis = new ZipInputStream(bis)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            String filePath = extractPath + File.separator + zipEntry.getName();
            
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath))) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    bos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void bad_case_14(HttpServletRequest request) throws IOException {
    // Using DataInputStream with ZipInputStream without validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    
    try (FileInputStream fis = new FileInputStream(zipFilePath);
         DataInputStream dis = new DataInputStream(fis);
         ZipInputStream zis = new ZipInputStream(dis)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            File newFile = new File(extractPath, zipEntry.getName());
            
            try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(newFile))) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    dos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void bad_case_15(HttpServletRequest request) throws IOException {
    // Using ByteArrayOutputStream to process ZIP data without validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    
    byte[] zipData = Files.readAllBytes(Paths.get(zipFilePath));
    
    try (ByteArrayInputStream bais = new ByteArrayInputStream(zipData);
         ZipInputStream zis = new ZipInputStream(bais)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            // ruleid: java-zip-entry-overwrite
            File newFile = new File(extractPath, zipEntry.getName());
            
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    baos.write(buffer, 0, len);
                }
                
                try (FileOutputStream fos = new FileOutputStream(newFile)) {
                    baos.writeTo(fos);
                }
            }
        }
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using java.util.zip with validation
    String zipFilePath = request.getParameter("zipFile");
    File zipFile = new File(zipFilePath);
    String extractPath = "/tmp/extracted/";
    
    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String entryName = entry.getName();
            
            // Validate zip entry name
            if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File outputFile = new File(extractPath, entryName);
            
            // Ensure the output file is within the target directory
            String canonicalDestinationPath = outputFile.getCanonicalPath();
            String canonicalExtractionPath = new File(extractPath).getCanonicalPath();
            
            if (!canonicalDestinationPath.startsWith(canonicalExtractionPath + File.separator)) {
                continue; // Path traversal attempt detected
            }
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_2(HttpServletRequest request) throws IOException {
    // Using Apache Commons Compress with validation
    String zipFilePath = request.getParameter("zipFile");
    File zipFile = new File(zipFilePath);
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath);
    
    try (ZipArchiveInputStream zis = new ZipArchiveInputStream(new FileInputStream(zipFile))) {
        ZipArchiveEntry entry;
        while ((entry = zis.getNextZipEntry()) != null) {
            String entryName = entry.getName();
            
            // Normalize the path and check for path traversal
            String normalizedPath = FilenameUtils.normalize(entryName);
            if (normalizedPath == null || normalizedPath.startsWith("..") || normalizedPath.startsWith("/")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File outputFile = new File(extractDir, normalizedPath);
            
            // Additional check to ensure we're still in the target directory
            if (!outputFile.getCanonicalPath().startsWith(extractDir.getCanonicalPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

@PostMapping("/upload")
public void good_case_3(@RequestParam("file") MultipartFile file) throws IOException {
    // Using Spring MVC with custom extraction and validation
    File tempFile = File.createTempFile("upload", ".zip");
    file.transferTo(tempFile);
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath);
    
    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(tempFile))) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String entryName = entry.getName();
            
            // Validate zip entry name
            if (entryName.contains("..") || entryName.startsWith("/")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File outputFile = new File(extractDir, entryName);
            
            // Ensure the output file is within the target directory
            if (!outputFile.getCanonicalPath().startsWith(extractDir.getCanonicalPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_4(HttpServletRequest request) throws ZipException, IOException {
    // Using Zip4j library with validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath);
    
    ZipFile zipFile = new ZipFile(zipFilePath);
    
    // Custom extraction with validation instead of using extractAll
    java.util.List<?> fileHeaders = zipFile.getFileHeaders();
    for (Object header : fileHeaders) {
        net.lingala.zip4j.model.FileHeader fileHeader = (net.lingala.zip4j.model.FileHeader) header;
        String entryName = fileHeader.getFileName();
        
        // Validate zip entry name
        if (entryName.contains("..") || entryName.startsWith("/")) {
            continue; // Skip this entry
        }
        
        // ok: java-zip-entry-overwrite
        File outputFile = new File(extractDir, entryName);
        
        // Ensure the output file is within the target directory
        if (!outputFile.getCanonicalPath().startsWith(extractDir.getCanonicalPath())) {
            continue; // Path traversal attempt detected
        }
        
        // Extract the specific file
        zipFile.extractFile(fileHeader, extractPath);
    }
}

public void good_case_5(HttpServletRequest request) throws IOException {
    // Using JArchiveLib with custom extraction and validation
    String zipFilePath = request.getParameter("zipFile");
    File zipFile = new File(zipFilePath);
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath);
    
    // Instead of using the archiver directly, we'll use ZipInputStream for validation
    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String entryName = entry.getName();
            
            // Validate zip entry name
            if (entryName.contains("..") || entryName.startsWith("/")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File outputFile = new File(extractDir, entryName);
            
            // Ensure the output file is within the target directory
            if (!outputFile.getCanonicalPath().startsWith(extractDir.getCanonicalPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_6(HttpServletRequest request) throws IOException {
    // Using AWS S3 to download and extract zip with validation
    String bucketName = request.getParameter("bucket");
    String key = request.getParameter("key");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath);
    
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    S3Object s3Object = s3Client.getObject(bucketName, key);
    
    try (ZipInputStream zis = new ZipInputStream(s3Object.getObjectContent())) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String entryName = entry.getName();
            
            // Validate zip entry name
            if (entryName.contains("..") || entryName.startsWith("/")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File outputFile = new File(extractDir, entryName);
            
            // Ensure the output file is within the target directory
            if (!outputFile.getCanonicalPath().startsWith(extractDir.getCanonicalPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_7(HttpServletRequest request) throws IOException {
    // Using Apache HttpClient to download and extract zip with validation
    String zipUrl = request.getParameter("zipUrl");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath);
    
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        HttpGet httpGet = new HttpGet(zipUrl);
        
        try (InputStream inputStream = httpClient.execute(httpGet).getEntity().getContent();
             ZipInputStream zis = new ZipInputStream(inputStream)) {
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String entryName = entry.getName();
                
                // Validate zip entry name
                if (entryName.contains("..") || entryName.startsWith("/")) {
                    continue; // Skip this entry
                }
                
                // ok: java-zip-entry-overwrite
                File outputFile = new File(extractDir, entryName);
                
                // Ensure the output file is within the target directory
                if (!outputFile.getCanonicalPath().startsWith(extractDir.getCanonicalPath())) {
                    continue; // Path traversal attempt detected
                }
                
                if (!outputFile.getParentFile().exists()) {
                    outputFile.getParentFile().mkdirs();
                }
                
                try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                    IOUtils.copy(zis, fos);
                }
            }
        }
    }
}

public void good_case_8(HttpServletRequest request) throws IOException {
    // Using OkHttp to download and extract zip with validation
    String zipUrl = request.getParameter("zipUrl");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath);
    
    OkHttpClient client = new OkHttpClient();
    Request okRequest = new Request.Builder().url(zipUrl).build();
    
    try (Response response = client.newCall(okRequest).execute();
         InputStream inputStream = response.body().byteStream();
         ZipInputStream zis = new ZipInputStream(inputStream)) {
        
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String entryName = entry.getName();
            
            // Validate zip entry name
            if (entryName.contains("..") || entryName.startsWith("/")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File outputFile = new File(extractDir, entryName);
            
            // Ensure the output file is within the target directory
            if (!outputFile.getCanonicalPath().startsWith(extractDir.getCanonicalPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_9(HttpServletRequest request) throws IOException {
    // Using java.nio.file for ZIP extraction with validation
    String zipFilePath = request.getParameter("zipFile");
    Path zipPath = Paths.get(zipFilePath);
    Path extractPath = Paths.get("/tmp/extracted/");
    String extractPathStr = extractPath.toFile().getCanonicalPath();
    
    try (FileSystem zipFs = FileSystems.newFileSystem(zipPath, null)) {
        for (Path root : zipFs.getRootDirectories()) {
            Files.walk(root).forEach(source -> {
                try {
                    if (!Files.isDirectory(source)) {
                        String entryName = source.toString().substring(1); // Remove leading slash
                        
                        // Validate zip entry name
                        if (entryName.contains("..") || entryName.startsWith("/")) {
                            return; // Skip this entry
                        }
                        
                        // ok: java-zip-entry-overwrite
                        Path target = extractPath.resolve(entryName);
                        
                        // Ensure the output file is within the target directory
                        if (!target.toFile().getCanonicalPath().startsWith(extractPathStr)) {
                            return; // Path traversal attempt detected
                        }
                        
                        Files.createDirectories(target.getParent());
                        Files.copy(source, target, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

public void good_case_10(HttpServletRequest request) throws IOException {
    // Using custom ZIP extraction with java.io with validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath).getCanonicalFile();
    
    byte[] buffer = new byte[1024];
    
    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath))) {
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            String fileName = zipEntry.getName();
            
            // Validate zip entry name
            if (fileName.contains("..") || fileName.startsWith("/") || fileName.startsWith("\\")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File newFile = new File(extractDir, fileName);
            
            // Ensure the output file is within the target directory
            if (!newFile.getCanonicalPath().startsWith(extractDir.getPath())) {
                continue; // Path traversal attempt detected
            }
            
            new File(newFile.getParent()).mkdirs();
            
            try (FileOutputStream fos = new FileOutputStream(newFile)) {
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
        zis.closeEntry();
    }
}

public void good_case_11(HttpServletRequest request) throws IOException, ServletException {
    // Using servlet file upload and ZIP extraction with validation
    Part filePart = request.getPart("zipFile");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath).getCanonicalFile();
    
    try (InputStream inputStream = filePart.getInputStream();
         ZipInputStream zis = new ZipInputStream(inputStream)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            String entryName = zipEntry.getName();
            
            // Validate zip entry name
            if (entryName.contains("..") || entryName.startsWith("/")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File newFile = new File(extractDir, entryName);
            
            // Ensure the output file is within the target directory
            if (!newFile.getCanonicalPath().startsWith(extractDir.getPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!newFile.getParentFile().exists()) {
                newFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(newFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_12(HttpServletRequest request) throws IOException {
    // Using URL connection to download and extract ZIP with validation
    String zipUrl = request.getParameter("zipUrl");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath).getCanonicalFile();
    
    URL url = new URL(zipUrl);
    URLConnection connection = url.openConnection();
    
    try (InputStream inputStream = connection.getInputStream();
         ZipInputStream zis = new ZipInputStream(inputStream)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            String entryName = zipEntry.getName();
            
            // Validate zip entry name using regex pattern
            Pattern pattern = Pattern.compile("^[^/\\\\].*?[^/\\\\.]$");
            if (!pattern.matcher(entryName).matches() || entryName.contains("..")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File newFile = new File(extractDir, entryName);
            
            // Ensure the output file is within the target directory
            if (!newFile.getCanonicalPath().startsWith(extractDir.getPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!newFile.getParentFile().exists()) {
                newFile.getParentFile().mkdirs();
            }
            
            try (FileOutputStream fos = new FileOutputStream(newFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_13(HttpServletRequest request) throws IOException {
    // Using BufferedInputStream with ZipInputStream with validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath).getCanonicalFile();
    
    try (FileInputStream fis = new FileInputStream(zipFilePath);
         BufferedInputStream bis = new BufferedInputStream(fis);
         ZipInputStream zis = new ZipInputStream(bis)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            String entryName = zipEntry.getName();
            
            // Validate zip entry name
            if (entryName.contains("..") || entryName.startsWith("/")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File newFile = new File(extractDir, entryName);
            
            // Ensure the output file is within the target directory
            if (!newFile.getCanonicalPath().startsWith(extractDir.getPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!newFile.getParentFile().exists()) {
                newFile.getParentFile().mkdirs();
            }
            
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(newFile))) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    bos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_14(HttpServletRequest request) throws IOException {
    // Using DataInputStream with ZipInputStream with validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath).getCanonicalFile();
    
    try (FileInputStream fis = new FileInputStream(zipFilePath);
         DataInputStream dis = new DataInputStream(fis);
         ZipInputStream zis = new ZipInputStream(dis)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            String entryName = zipEntry.getName();
            
            // Normalize the path
            String normalizedPath = FilenameUtils.normalize(entryName);
            if (normalizedPath == null) {
                continue; // Skip invalid paths
            }
            
            // Validate zip entry name
            if (normalizedPath.contains("..") || normalizedPath.startsWith("/")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File newFile = new File(extractDir, normalizedPath);
            
            // Ensure the output file is within the target directory
            if (!newFile.getCanonicalPath().startsWith(extractDir.getPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!newFile.getParentFile().exists()) {
                newFile.getParentFile().mkdirs();
            }
            
            try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(newFile))) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    dos.write(buffer, 0, len);
                }
            }
        }
    }
}

public void good_case_15(HttpServletRequest request) throws IOException {
    // Using ByteArrayOutputStream to process ZIP data with validation
    String zipFilePath = request.getParameter("zipFile");
    String extractPath = "/tmp/extracted/";
    File extractDir = new File(extractPath).getCanonicalFile();
    
    byte[] zipData = Files.readAllBytes(Paths.get(zipFilePath));
    
    try (ByteArrayInputStream bais = new ByteArrayInputStream(zipData);
         ZipInputStream zis = new ZipInputStream(bais)) {
        
        ZipEntry zipEntry;
        while ((zipEntry = zis.getNextEntry()) != null) {
            String entryName = zipEntry.getName();
            
            // Validate zip entry name
            if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                continue; // Skip this entry
            }
            
            // ok: java-zip-entry-overwrite
            File newFile = new File(extractDir, entryName);
            
            // Ensure the output file is within the target directory
            if (!newFile.getCanonicalPath().startsWith(extractDir.getPath())) {
                continue; // Path traversal attempt detected
            }
            
            if (!newFile.getParentFile().exists()) {
                newFile.getParentFile().mkdirs();
            }
            
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    baos.write(buffer, 0, len);
                }
                
                try (FileOutputStream fos = new FileOutputStream(newFile)) {
                    baos.writeTo(fos);
                }
            }
        }
    }
}