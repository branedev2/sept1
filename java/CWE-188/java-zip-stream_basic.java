import java.io.*;
import java.util.zip.*;
import java.nio.file.*;
import java.util.*;
import java.security.*;
import javax.servlet.http.*;
import java.nio.channels.*;

public class ZipStreamVulnerabilityExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=unsafe-data-layout-reliance@v1.0 defects=1}
    public void bad_case_1() {
        try {
            File zipFile = new File("archive.zip");
            FileInputStream fis = new FileInputStream(zipFile);
            BufferedInputStream bis = new BufferedInputStream(fis);
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(bis);
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                System.out.println("Processing: " + entry.getName());
                // Process entry content
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
        try {
            String zipPath = request.getParameter("zipFile");
            FileInputStream fis = new FileInputStream(zipPath);
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(fis);
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Extract and process files
                byte[] buffer = new byte[1024];
                int len;
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                while ((len = zis.read(buffer)) > 0) {
                    baos.write(buffer, 0, len);
                }
                System.out.println("Extracted: " + entry.getName());
            }
            zis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(
                new FileInputStream("data.zip")
            );
            
            ZipEntry zipEntry;
            while ((zipEntry = zis.getNextEntry()) != null) {
                if (zipEntry.getName().endsWith(".txt")) {
                    // Process text files
                    BufferedReader br = new BufferedReader(new InputStreamReader(zis));
                    String line;
                    while ((line = br.readLine()) != null) {
                        System.out.println(line);
                    }
                }
                zis.closeEntry();
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            URL url = new URL("http://example.com/files.zip");
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(url.openStream());
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    // Process file entries
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int count;
                    while ((count = zis.read(buffer)) != -1) {
                        baos.write(buffer, 0, count);
                    }
                }
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            Path zipPath = Paths.get("resources", "archive.zip");
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(Files.newInputStream(zipPath));
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Validate file extensions
                String name = entry.getName();
                if (name.endsWith(".xml") || name.endsWith(".json")) {
                    // Process valid files
                    System.out.println("Processing: " + name);
                }
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(InputStream inputStream) {
        try {
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(inputStream);
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Check file size
                if (entry.getSize() < 10_000_000) { // 10MB limit
                    // Process small files
                    byte[] content = zis.readAllBytes();
                    System.out.println("Read " + content.length + " bytes from " + entry.getName());
                }
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            File tempZip = File.createTempFile("temp", ".zip");
            // Some code to write to the temp zip file
            
            FileInputStream fis = new FileInputStream(tempZip);
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(fis);
            
            // Extract with custom buffer size
            byte[] buffer = new byte[8192];
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File outputFile = new File("output/" + entry.getName());
                // Ensure directory exists
                outputFile.getParentFile().mkdirs();
                
                FileOutputStream fos = new FileOutputStream(outputFile);
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
            }
            zis.close();
            tempZip.delete();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        try {
            Part filePart = request.getPart("zipFile");
            InputStream fileContent = filePart.getInputStream();
            
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(fileContent);
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Security check - reject entries with path traversal attempts
                if (entry.getName().contains("..")) {
                    System.out.println("Rejected suspicious entry: " + entry.getName());
                    continue;
                }
                
                // Process valid entries
                System.out.println("Processing: " + entry.getName());
            }
            zis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // Create a password protected zip stream
            String password = "secret123";
            FileInputStream fis = new FileInputStream("protected.zip");
            
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(fis) {
                @Override
                public ZipEntry getNextEntry() throws IOException {
                    ZipEntry entry = super.getNextEntry();
                    if (entry != null) {
                        // Custom decryption logic would go here
                        System.out.println("Decrypting: " + entry.getName() + " with password: " + password);
                    }
                    return entry;
                }
            };
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Process decrypted entries
                System.out.println("Processing: " + entry.getName());
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // Create a chain of input streams
            FileInputStream fis = new FileInputStream("large_archive.zip");
            BufferedInputStream bis = new BufferedInputStream(fis, 65536); // Large buffer
            
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(bis);
            
            // Process with multi-threading
            ExecutorService executor = Executors.newFixedThreadPool(4);
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                final ZipEntry currentEntry = entry;
                final byte[] content = zis.readAllBytes();
                
                executor.submit(() -> {
                    try {
                        System.out.println("Processing " + currentEntry.getName() + " in thread: " + Thread.currentThread().getName());
                        // Process content
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return null;
                });
            }
            
            executor.shutdown();
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // Read zip from byte array
            byte[] zipData = Files.readAllBytes(Paths.get("data.zip"));
            ByteArrayInputStream bais = new ByteArrayInputStream(zipData);
            
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(bais);
            
            // Calculate hash of each entry
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = zis.read(buffer)) != -1) {
                    md.update(buffer, 0, bytesRead);
                }
                byte[] digest = md.digest();
                System.out.println(entry.getName() + " hash: " + bytesToHex(digest));
            }
            zis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public void bad_case_12() {
        try {
            // Use NIO channels
            FileChannel channel = FileChannel.open(Paths.get("archive.zip"), StandardOpenOption.READ);
            InputStream is = Channels.newInputStream(channel);
            
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(is);
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Skip directories
                if (entry.isDirectory()) {
                    continue;
                }
                
                // Process only specific file types
                if (entry.getName().endsWith(".class")) {
                    // Process class files
                    System.out.println("Found class file: " + entry.getName());
                }
            }
            zis.close();
            channel.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // Create a custom filtered stream
            FileInputStream fis = new FileInputStream("data.zip");
            FilterInputStream filterStream = new FilterInputStream(fis) {
                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    int result = super.read(b, off, len);
                    // Log bytes read
                    if (result > 0) {
                        System.out.println("Read " + result + " bytes");
                    }
                    return result;
                }
            };
            
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(filterStream);
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                System.out.println("Found entry: " + entry.getName() + ", size: " + entry.getSize());
                // Skip entry content
                zis.closeEntry();
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // Process a zip file with a specific charset
            FileInputStream fis = new FileInputStream("international.zip");
            
            // ruleid: java-zip-stream
            ZipInputStream zis = new ZipInputStream(fis, java.nio.charset.StandardCharsets.UTF_8);
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Handle international filenames
                String name = entry.getName();
                System.out.println("Processing entry with UTF-8 name: " + name);
                
                // Read content as text with the same charset
                if (name.endsWith(".txt")) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(zis, java.nio.charset.StandardCharsets.UTF_8));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println(line);
                    }
                }
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // Process nested zip files
            FileInputStream fis = new FileInputStream("outer.zip");
            
            // ruleid: java-zip-stream
            ZipInputStream outerZis = new ZipInputStream(fis);
            
            ZipEntry outerEntry;
            while ((outerEntry = outerZis.getNextEntry()) != null) {
                if (outerEntry.getName().endsWith(".zip")) {
                    // Found a nested zip file
                    System.out.println("Processing nested zip: " + outerEntry.getName());
                    
                    // Create a new ZipInputStream for the nested zip
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = outerZis.read(buffer)) > 0) {
                        baos.write(buffer, 0, len);
                    }
                    
                    // Process the nested zip
                    ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
                    // ruleid: java-zip-stream
                    ZipInputStream nestedZis = new ZipInputStream(bais);
                    
                    ZipEntry nestedEntry;
                    while ((nestedEntry = nestedZis.getNextEntry()) != null) {
                        System.out.println("  Nested entry: " + nestedEntry.getName());
                    }
                    nestedZis.close();
                }
            }
            outerZis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            File zipFile = new File("archive.zip");
            // ok: java-zip-stream
            ZipFile zip = new ZipFile(zipFile);
            
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                System.out.println("Processing: " + entry.getName());
                // Process entry content using zip.getInputStream(entry)
            }
            zip.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
        try {
            String zipPath = request.getParameter("zipFile");
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(zipPath);
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // Extract and process files
                InputStream is = zipFile.getInputStream(entry);
                byte[] buffer = new byte[1024];
                int len;
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                while ((len = is.read(buffer)) > 0) {
                    baos.write(buffer, 0, len);
                }
                System.out.println("Extracted: " + entry.getName());
                is.close();
            }
            zipFile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile("data.zip");
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".txt")) {
                    // Process text files
                    InputStream is = zipFile.getInputStream(entry);
                    BufferedReader br = new BufferedReader(new InputStreamReader(is));
                    String line;
                    while ((line = br.readLine()) != null) {
                        System.out.println(line);
                    }
                    is.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            // Download zip to a temporary file first
            URL url = new URL("http://example.com/files.zip");
            Path tempFile = Files.createTempFile("download", ".zip");
            Files.copy(url.openStream(), tempFile, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(tempFile.toFile());
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.isDirectory()) {
                    // Process file entries
                    InputStream is = zipFile.getInputStream(entry);
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int count;
                    while ((count = is.read(buffer)) != -1) {
                        baos.write(buffer, 0, count);
                    }
                    is.close();
                }
            }
            zipFile.close();
            Files.delete(tempFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            Path zipPath = Paths.get("resources", "archive.zip");
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(zipPath.toFile());
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // Validate file extensions
                String name = entry.getName();
                if (name.endsWith(".xml") || name.endsWith(".json")) {
                    // Process valid files
                    System.out.println("Processing: " + name);
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(InputStream inputStream) {
        try {
            // Save the input stream to a temporary file
            Path tempFile = Files.createTempFile("temp", ".zip");
            Files.copy(inputStream, tempFile, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(tempFile.toFile());
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // Check file size
                if (entry.getSize() < 10_000_000) { // 10MB limit
                    // Process small files
                    InputStream is = zipFile.getInputStream(entry);
                    byte[] content = is.readAllBytes();
                    System.out.println("Read " + content.length + " bytes from " + entry.getName());
                    is.close();
                }
            }
            zipFile.close();
            Files.delete(tempFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            File tempZip = File.createTempFile("temp", ".zip");
            // Some code to write to the temp zip file
            
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(tempZip);
            
            // Extract with custom buffer size
            byte[] buffer = new byte[8192];
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                File outputFile = new File("output/" + entry.getName());
                // Ensure directory exists
                outputFile.getParentFile().mkdirs();
                
                InputStream is = zipFile.getInputStream(entry);
                FileOutputStream fos = new FileOutputStream(outputFile);
                int len;
                while ((len = is.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
                is.close();
            }
            zipFile.close();
            tempZip.delete();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8(HttpServletRequest request) {
        try {
            Part filePart = request.getPart("zipFile");
            // Save uploaded file to temporary location
            Path tempFile = Files.createTempFile("upload", ".zip");
            filePart.write(tempFile.toString());
            
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(tempFile.toFile());
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // Security check - reject entries with path traversal attempts
                if (entry.getName().contains("..")) {
                    System.out.println("Rejected suspicious entry: " + entry.getName());
                    continue;
                }
                
                // Process valid entries
                System.out.println("Processing: " + entry.getName());
            }
            zipFile.close();
            Files.delete(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // Create a password protected zip file
            String password = "secret123";
            File zipFile = new File("protected.zip");
            
            // ok: java-zip-stream
            // For password-protected ZIPs, use a specialized library that handles the central directory correctly
            net.lingala.zip4j.ZipFile secureZip = new net.lingala.zip4j.ZipFile(zipFile);
            if (secureZip.isEncrypted()) {
                secureZip.setPassword(password.toCharArray());
            }
            
            List<net.lingala.zip4j.model.FileHeader> fileHeaders = secureZip.getFileHeaders();
            for (net.lingala.zip4j.model.FileHeader header : fileHeaders) {
                // Process entries
                System.out.println("Processing: " + header.getFileName());
                // Extract if needed
                secureZip.extractFile(header, "output/");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile("large_archive.zip");
            
            // Process with multi-threading
            ExecutorService executor = Executors.newFixedThreadPool(4);
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                final ZipEntry entry = entries.nextElement();
                
                executor.submit(() -> {
                    try {
                        System.out.println("Processing " + entry.getName() + " in thread: " + Thread.currentThread().getName());
                        // Process content
                        InputStream is = zipFile.getInputStream(entry);
                        byte[] content = is.readAllBytes();
                        is.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return null;
                });
            }
            
            executor.shutdown();
            executor.awaitTermination(1, TimeUnit.HOURS);
            zipFile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // Save byte array to temporary file first
            byte[] zipData = Files.readAllBytes(Paths.get("data.zip"));
            Path tempFile = Files.createTempFile("data", ".zip");
            Files.write(tempFile, zipData);
            
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile(tempFile.toFile());
            
            // Calculate hash of each entry
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                InputStream is = zipFile.getInputStream(entry);
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    md.update(buffer, 0, bytesRead);
                }
                byte[] digest = md.digest();
                System.out.println(entry.getName() + " hash: " + bytesToHex(digest));
                is.close();
            }
            zipFile.close();
            Files.delete(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile("archive.zip");
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // Skip directories
                if (entry.isDirectory()) {
                    continue;
                }
                
                // Process only specific file types
                if (entry.getName().endsWith(".class")) {
                    // Process class files
                    System.out.println("Found class file: " + entry.getName());
                    InputStream is = zipFile.getInputStream(entry);
                    // Process class file content
                    is.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile("data.zip");
            
            // Create a custom wrapper for logging
            class LoggingInputStream extends InputStream {
                private final InputStream wrapped;
                
                public LoggingInputStream(InputStream wrapped) {
                    this.wrapped = wrapped;
                }
                
                @Override
                public int read() throws IOException {
                    int result = wrapped.read();
                    if (result != -1) {
                        System.out.println("Read 1 byte");
                    }
                    return result;
                }
                
                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    int result = wrapped.read(b, off, len);
                    if (result > 0) {
                        System.out.println("Read " + result + " bytes");
                    }
                    return result;
                }
                
                @Override
                public void close() throws IOException {
                    wrapped.close();
                }
            }
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                System.out.println("Found entry: " + entry.getName() + ", size: " + entry.getSize());
                
                // Use the logging wrapper around the entry input stream
                InputStream entryStream = zipFile.getInputStream(entry);
                LoggingInputStream loggingStream = new LoggingInputStream(entryStream);
                
                // Read and discard content
                byte[] buffer = new byte[8192];
                while (loggingStream.read(buffer) > 0) {
                    // Just discard the data
                }
                loggingStream.close();
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // ok: java-zip-stream
            ZipFile zipFile = new ZipFile("international.zip", java.nio.charset.StandardCharsets.UTF_8);
            
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // Handle international filenames
                String name = entry.getName();
                System.out.println("Processing entry with UTF-8 name: " + name);
                
                // Read content as text with the same charset
                if (name.endsWith(".txt")) {
                    InputStream is = zipFile.getInputStream(entry);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is, java.nio.charset.StandardCharsets.UTF_8));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println(line);
                    }
                    is.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // ok: java-zip-stream
            ZipFile outerZipFile = new ZipFile("outer.zip");
            
            Enumeration<? extends ZipEntry> outerEntries = outerZipFile.entries();
            while (outerEntries.hasMoreElements()) {
                ZipEntry outerEntry = outerEntries.nextElement();
                if (outerEntry.getName().endsWith(".zip")) {
                    // Found a nested zip file
                    System.out.println("Processing nested zip: " + outerEntry.getName());
                    
                    // Save the nested zip to a temporary file
                    InputStream is = outerZipFile.getInputStream(outerEntry);
                    Path tempFile = Files.createTempFile("nested", ".zip");
                    Files.copy(is, tempFile, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                    is.close();
                    
                    // Process the nested zip
                    // ok: java-zip-stream
                    ZipFile nestedZipFile = new ZipFile(tempFile.toFile());
                    
                    Enumeration<? extends ZipEntry> nestedEntries = nestedZipFile.entries();
                    while (nestedEntries.hasMoreElements()) {
                        ZipEntry nestedEntry = nestedEntries.nextElement();
                        System.out.println("  Nested entry: " + nestedEntry.getName());
                    }
                    nestedZipFile.close();
                    Files.delete(tempFile);
                }
            }
            outerZipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}