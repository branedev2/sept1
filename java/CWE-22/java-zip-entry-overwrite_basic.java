import java.io.*;
import java.util.zip.*;
import java.nio.file.*;
import javax.servlet.http.*;
import java.util.Enumeration;
import java.util.regex.Pattern;
import org.apache.commons.io.FilenameUtils;

public class ZipEntryOverwriteExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String zipFilePath = request.getParameter("zipFile");
            File destDir = new File("/tmp/extracted");
            
            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath));
            ZipEntry zipEntry;
            
            while ((zipEntry = zis.getNextEntry()) != null) {
                String fileName = zipEntry.getName();
                // ruleid: java-zip-entry-overwrite
                File newFile = new File(destDir, fileName);
                
                FileOutputStream fos = new FileOutputStream(newFile);
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
            }
            zis.closeEntry();
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        try {
            String zipFilePath = request.getParameter("zipFile");
            String outputDir = "/var/www/uploads/";
            
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // ruleid: java-zip-entry-overwrite
                File entryDestination = new File(outputDir, entry.getName());
                
                if (entry.isDirectory()) {
                    entryDestination.mkdirs();
                } else {
                    InputStream in = zipFile.getInputStream(entry);
                    OutputStream out = new FileOutputStream(entryDestination);
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = in.read(buffer)) > 0) {
                        out.write(buffer, 0, length);
                    }
                    in.close();
                    out.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            String zipFilePath = "user_upload.zip";
            String extractPath = "/opt/application/data/";
            
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                
                // ruleid: java-zip-entry-overwrite
                File outputFile = new File(extractPath + entryName);
                
                if (!entry.isDirectory()) {
                    BufferedInputStream bis = new BufferedInputStream(zipFile.getInputStream(entry));
                    File parent = outputFile.getParentFile();
                    if (parent != null) {
                        parent.mkdirs();
                    }
                    
                    FileOutputStream fos = new FileOutputStream(outputFile);
                    BufferedOutputStream bos = new BufferedOutputStream(fos);
                    
                    int bytesRead;
                    byte[] buffer = new byte[8192];
                    while ((bytesRead = bis.read(buffer)) != -1) {
                        bos.write(buffer, 0, bytesRead);
                    }
                    
                    bos.close();
                    bis.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
        try {
            String zipFileName = request.getParameter("filename");
            File zipFile = new File("/uploads/" + zipFileName);
            File destDir = new File("/var/www/html/uploads/");
            
            byte[] buffer = new byte[1024];
            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
            ZipEntry zipEntry;
            
            while ((zipEntry = zis.getNextEntry()) != null) {
                String entryName = zipEntry.getName();
                // ruleid: java-zip-entry-overwrite
                File newFile = new File(destDir + File.separator + entryName);
                
                // Create parent directories if they don't exist
                new File(newFile.getParent()).mkdirs();
                
                FileOutputStream fos = new FileOutputStream(newFile);
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
            }
            zis.closeEntry();
            zis.close();
            
            response.getWriter().println("Files extracted successfully");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            String zipFilePath = "backup.zip";
            String destDirectory = "/home/user/restore/";
            
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // ruleid: java-zip-entry-overwrite
                File entryFile = new File(destDirectory + entry.getName());
                
                if (entry.isDirectory()) {
                    entryFile.mkdirs();
                } else {
                    entryFile.getParentFile().mkdirs();
                    InputStream is = zipFile.getInputStream(entry);
                    FileOutputStream fos = new FileOutputStream(entryFile);
                    
                    byte[] bytes = new byte[1024];
                    int length;
                    while ((length = is.read(bytes)) >= 0) {
                        fos.write(bytes, 0, length);
                    }
                    
                    is.close();
                    fos.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        try {
            Part filePart = request.getPart("zipfile");
            String extractPath = "/usr/local/tomcat/webapps/data/";
            
            InputStream fileContent = filePart.getInputStream();
            ZipInputStream zipIn = new ZipInputStream(fileContent);
            ZipEntry entry;
            
            while ((entry = zipIn.getNextEntry()) != null) {
                // ruleid: java-zip-entry-overwrite
                String filePath = extractPath + entry.getName();
                
                if (!entry.isDirectory()) {
                    BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath));
                    byte[] bytesIn = new byte[4096];
                    int read = 0;
                    while ((read = zipIn.read(bytesIn)) != -1) {
                        bos.write(bytesIn, 0, read);
                    }
                    bos.close();
                } else {
                    File dir = new File(filePath);
                    dir.mkdir();
                }
                zipIn.closeEntry();
            }
            zipIn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            String zipFilePath = "archive.zip";
            String outputFolder = "/opt/app/files/";
            
            ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath));
            ZipEntry entry;
            
            while ((entry = zipInputStream.getNextEntry()) != null) {
                String entryName = entry.getName();
                // ruleid: java-zip-entry-overwrite
                File outputFile = new File(outputFolder, entryName);
                
                if (entry.isDirectory()) {
                    outputFile.mkdirs();
                } else {
                    // Create parent directories if needed
                    if (outputFile.getParentFile() != null) {
                        outputFile.getParentFile().mkdirs();
                    }
                    
                    FileOutputStream outputStream = new FileOutputStream(outputFile);
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = zipInputStream.read(buffer)) > 0) {
                        outputStream.write(buffer, 0, length);
                    }
                    outputStream.close();
                }
                zipInputStream.closeEntry();
            }
            zipInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        try {
            String zipFile = request.getParameter("file");
            String destDir = System.getProperty("user.home") + "/extracted/";
            
            File dir = new File(destDir);
            if (!dir.exists()) dir.mkdirs();
            
            FileInputStream fis = new FileInputStream(zipFile);
            ZipInputStream zipIn = new ZipInputStream(fis);
            ZipEntry entry;
            
            while ((entry = zipIn.getNextEntry()) != null) {
                // ruleid: java-zip-entry-overwrite
                String filePath = destDir + entry.getName();
                
                if (!entry.isDirectory()) {
                    extractFile(zipIn, filePath);
                } else {
                    File dirPath = new File(filePath);
                    dirPath.mkdir();
                }
                zipIn.closeEntry();
            }
            zipIn.close();
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private void extractFile(ZipInputStream zipIn, String filePath) throws IOException {
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath));
        byte[] bytesIn = new byte[4096];
        int read = 0;
        while ((read = zipIn.read(bytesIn)) != -1) {
            bos.write(bytesIn, 0, read);
        }
        bos.close();
    }

    public void bad_case_9() {
        try {
            File zipFile = new File("data.zip");
            File targetDir = new File("/var/data/");
            
            ZipFile zip = new ZipFile(zipFile);
            Enumeration<? extends ZipEntry> zipEntries = zip.entries();
            
            while (zipEntries.hasMoreElements()) {
                ZipEntry entry = zipEntries.nextElement();
                // ruleid: java-zip-entry-overwrite
                File targetFile = new File(targetDir, entry.getName());
                
                if (entry.isDirectory()) {
                    targetFile.mkdirs();
                    continue;
                }
                
                InputStream inputStream = zip.getInputStream(entry);
                FileOutputStream outputStream = new FileOutputStream(targetFile);
                
                byte[] buffer = new byte[1024];
                int length;
                while ((length = inputStream.read(buffer)) > 0) {
                    outputStream.write(buffer, 0, length);
                }
                
                outputStream.close();
                inputStream.close();
            }
            
            zip.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        try {
            String zipPath = request.getParameter("zipPath");
            String extractDir = "/app/public/images/";
            
            ZipFile zipFile = new ZipFile(zipPath);
            
            for (Enumeration<? extends ZipEntry> e = zipFile.entries(); e.hasMoreElements();) {
                ZipEntry entry = e.nextElement();
                // ruleid: java-zip-entry-overwrite
                File destinationPath = new File(extractDir, entry.getName());
                
                if (entry.isDirectory()) {
                    destinationPath.mkdirs();
                } else {
                    destinationPath.getParentFile().mkdirs();
                    
                    InputStream in = zipFile.getInputStream(entry);
                    FileOutputStream out = new FileOutputStream(destinationPath);
                    
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = in.read(buffer)) >= 0) {
                        out.write(buffer, 0, len);
                    }
                    
                    in.close();
                    out.close();
                }
            }
            
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            String zipFilePath = "package.zip";
            String outputDir = "/opt/webapps/ROOT/";
            
            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath));
            ZipEntry zipEntry;
            byte[] buffer = new byte[2048];
            
            while ((zipEntry = zis.getNextEntry()) != null) {
                String fileName = zipEntry.getName();
                // ruleid: java-zip-entry-overwrite
                File newFile = new File(outputDir + fileName);
                
                if (zipEntry.isDirectory()) {
                    newFile.mkdirs();
                } else {
                    new File(newFile.getParent()).mkdirs();
                    FileOutputStream fos = new FileOutputStream(newFile);
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        fos.write(buffer, 0, len);
                    }
                    fos.close();
                }
                zis.closeEntry();
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        try {
            String zipFileName = request.getParameter("zipFile");
            String outputPath = "/tmp/uploads/";
            
            try (ZipFile zipFile = new ZipFile(zipFileName)) {
                Enumeration<? extends ZipEntry> entries = zipFile.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    // ruleid: java-zip-entry-overwrite
                    File entryDestination = new File(outputPath, entry.getName());
                    
                    if (entry.isDirectory()) {
                        entryDestination.mkdirs();
                    } else {
                        entryDestination.getParentFile().mkdirs();
                        try (InputStream in = zipFile.getInputStream(entry);
                             OutputStream out = new FileOutputStream(entryDestination)) {
                            byte[] buffer = new byte[1024];
                            int length;
                            while ((length = in.read(buffer)) > 0) {
                                out.write(buffer, 0, length);
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            String zipFile = "content.zip";
            String extractFolder = "/var/www/html/";
            
            byte[] buffer = new byte[1024];
            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
            ZipEntry zipEntry = zis.getNextEntry();
            
            while (zipEntry != null) {
                String fileName = zipEntry.getName();
                // ruleid: java-zip-entry-overwrite
                File newFile = new File(extractFolder + fileName);
                
                // Create directories for sub directories in zip
                new File(newFile.getParent()).mkdirs();
                
                FileOutputStream fos = new FileOutputStream(newFile);
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
                
                zipEntry = zis.getNextEntry();
            }
            zis.closeEntry();
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        try {
            String zipPath = request.getParameter("path");
            String destPath = "/home/user/public_html/";
            
            File destDir = new File(destPath);
            if (!destDir.exists()) {
                destDir.mkdir();
            }
            
            ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipPath));
            ZipEntry entry = zipIn.getNextEntry();
            
            while (entry != null) {
                String filePath = destPath + File.separator + entry.getName();
                // ruleid: java-zip-entry-overwrite
                if (!entry.isDirectory()) {
                    // Extract file
                    BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath));
                    byte[] bytesIn = new byte[4096];
                    int read = 0;
                    while ((read = zipIn.read(bytesIn)) != -1) {
                        bos.write(bytesIn, 0, read);
                    }
                    bos.close();
                } else {
                    // Create directory
                    File dir = new File(filePath);
                    dir.mkdir();
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
            zipIn.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            String zipFilePath = "updates.zip";
            String destDirectory = "/usr/share/app/";
            
            File destDir = new File(destDirectory);
            if (!destDir.exists()) {
                destDir.mkdir();
            }
            
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // ruleid: java-zip-entry-overwrite
                File entryDestination = new File(destDir, entry.getName());
                
                if (entry.isDirectory()) {
                    entryDestination.mkdirs();
                } else {
                    entryDestination.getParentFile().mkdirs();
                    InputStream in = zipFile.getInputStream(entry);
                    OutputStream out = new FileOutputStream(entryDestination);
                    
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = in.read(buffer)) > 0) {
                        out.write(buffer, 0, length);
                    }
                    
                    in.close();
                    out.close();
                }
            }
            
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request) {
        try {
            String zipFilePath = request.getParameter("zipFile");
            File destDir = new File("/tmp/extracted");
            
            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath));
            ZipEntry zipEntry;
            
            while ((zipEntry = zis.getNextEntry()) != null) {
                String fileName = zipEntry.getName();
                
                // ok: java-zip-entry-overwrite
                // Validate file name to prevent path traversal
                if (fileName.contains("..") || fileName.startsWith("/") || fileName.startsWith("\\")) {
                    System.out.println("Potentially malicious entry detected: " + fileName);
                    continue;
                }
                
                File newFile = new File(destDir, fileName);
                
                // Ensure the file is within the target directory
                String canonicalDestDir = destDir.getCanonicalPath();
                String canonicalNewFile = newFile.getCanonicalPath();
                if (!canonicalNewFile.startsWith(canonicalDestDir)) {
                    System.out.println("Path traversal attempt detected: " + fileName);
                    continue;
                }
                
                FileOutputStream fos = new FileOutputStream(newFile);
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
            }
            zis.closeEntry();
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request) {
        try {
            String zipFilePath = request.getParameter("zipFile");
            String outputDir = "/var/www/uploads/";
            
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                
                // ok: java-zip-entry-overwrite
                // Normalize the path and check for traversal attempts
                String normalizedPath = FilenameUtils.normalize(entryName);
                if (normalizedPath == null || normalizedPath.startsWith("..") || normalizedPath.startsWith("/")) {
                    System.out.println("Skipping potentially malicious entry: " + entryName);
                    continue;
                }
                
                File entryDestination = new File(outputDir, normalizedPath);
                
                // Double-check that the final path is within the target directory
                if (!entryDestination.getCanonicalPath().startsWith(new File(outputDir).getCanonicalPath())) {
                    System.out.println("Path traversal attempt detected: " + entryName);
                    continue;
                }
                
                if (entry.isDirectory()) {
                    entryDestination.mkdirs();
                } else {
                    InputStream in = zipFile.getInputStream(entry);
                    OutputStream out = new FileOutputStream(entryDestination);
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = in.read(buffer)) > 0) {
                        out.write(buffer, 0, length);
                    }
                    in.close();
                    out.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            String zipFilePath = "user_upload.zip";
            String extractPath = "/opt/application/data/";
            
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            // Create a pattern to match safe filenames
            // ok: java-zip-entry-overwrite
            Pattern pattern = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9_\\-\\.]*(/[a-zA-Z0-9][a-zA-Z0-9_\\-\\.]*)*$");
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                
                // Validate the entry name against the safe pattern
                if (!pattern.matcher(entryName).matches()) {
                    System.out.println("Rejecting suspicious zip entry: " + entryName);
                    continue;
                }
                
                File outputFile = new File(extractPath + entryName);
                
                // Additional check to ensure we're not escaping the target directory
                if (!outputFile.getCanonicalPath().startsWith(new File(extractPath).getCanonicalPath())) {
                    System.out.println("Path traversal attempt detected: " + entryName);
                    continue;
                }
                
                if (!entry.isDirectory()) {
                    BufferedInputStream bis = new BufferedInputStream(zipFile.getInputStream(entry));
                    File parent = outputFile.getParentFile();
                    if (parent != null) {
                        parent.mkdirs();
                    }
                    
                    FileOutputStream fos = new FileOutputStream(outputFile);
                    BufferedOutputStream bos = new BufferedOutputStream(fos);
                    
                    int bytesRead;
                    byte[] buffer = new byte[8192];
                    while ((bytesRead = bis.read(buffer)) != -1) {
                        bos.write(buffer, 0, bytesRead);
                    }
                    
                    bos.close();
                    bis.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
        try {
            String zipFileName = request.getParameter("filename");
            File zipFile = new File("/uploads/" + zipFileName);
            File destDir = new File("/var/www/html/uploads/");
            
            byte[] buffer = new byte[1024];
            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
            ZipEntry zipEntry;
            
            while ((zipEntry = zis.getNextEntry()) != null) {
                String entryName = zipEntry.getName();
                
                // ok: java-zip-entry-overwrite
                // Sanitize the file path to prevent directory traversal
                String sanitizedName = entryName.replaceAll("[\\\\/:*?\"<>|]", "_");
                sanitizedName = sanitizedName.replaceAll("\\.\\.", "_");
                
                File newFile = new File(destDir + File.separator + sanitizedName);
                
                // Verify the file will be created inside the destination directory
                String canonicalDestDir = destDir.getCanonicalPath();
                String canonicalNewFile = newFile.getCanonicalPath();
                
                if (!canonicalNewFile.startsWith(canonicalDestDir + File.separator)) {
                    System.out.println("Directory traversal attempt detected: " + entryName);
                    continue;
                }
                
                // Create parent directories if they don't exist
                new File(newFile.getParent()).mkdirs();
                
                FileOutputStream fos = new FileOutputStream(newFile);
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
            }
            zis.closeEntry();
            zis.close();
            
            response.getWriter().println("Files extracted successfully");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            String zipFilePath = "backup.zip";
            String destDirectory = "/home/user/restore/";
            
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            File destDir = new File(destDirectory);
            String canonicalDestPath = destDir.getCanonicalPath() + File.separator;
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                
                // ok: java-zip-entry-overwrite
                // Validate zip entry name
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                    System.out.println("Skipping potentially malicious entry: " + entryName);
                    continue;
                }
                
                File entryFile = new File(destDirectory + entryName);
                String canonicalEntryPath = entryFile.getCanonicalPath();
                
                // Ensure the entry is within the destination directory
                if (!canonicalEntryPath.startsWith(canonicalDestPath)) {
                    System.out.println("Directory traversal attempt detected: " + entryName);
                    continue;
                }
                
                if (entry.isDirectory()) {
                    entryFile.mkdirs();
                } else {
                    entryFile.getParentFile().mkdirs();
                    InputStream is = zipFile.getInputStream(entry);
                    FileOutputStream fos = new FileOutputStream(entryFile);
                    
                    byte[] bytes = new byte[1024];
                    int length;
                    while ((length = is.read(bytes)) >= 0) {
                        fos.write(bytes, 0, length);
                    }
                    
                    is.close();
                    fos.close();
                }
            }
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        try {
            Part filePart = request.getPart("zipfile");
            String extractPath = "/usr/local/tomcat/webapps/data/";
            File extractDir = new File(extractPath);
            String canonicalExtractPath = extractDir.getCanonicalPath() + File.separator;
            
            InputStream fileContent = filePart.getInputStream();
            ZipInputStream zipIn = new ZipInputStream(fileContent);
            ZipEntry entry;
            
            while ((entry = zipIn.getNextEntry()) != null) {
                String entryName = entry.getName();
                
                // ok: java-zip-entry-overwrite
                // Remove any path traversal sequences
                String safeName = entryName.replaceAll("\\.\\./", "")
                                          .replaceAll("\\.\\.\\\\", "")
                                          .replaceAll("^/", "")
                                          .replaceAll("^\\\\", "");
                
                File outputFile = new File(extractDir, safeName);
                String canonicalOutputPath = outputFile.getCanonicalPath();
                
                // Verify the output file is within the extract directory
                if (!canonicalOutputPath.startsWith(canonicalExtractPath)) {
                    System.out.println("Blocked path traversal attempt: " + entryName);
                    continue;
                }
                
                if (!entry.isDirectory()) {
                    // Create parent directories if needed
                    File parent = outputFile.getParentFile();
                    if (parent != null) {
                        parent.mkdirs();
                    }
                    
                    BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile));
                    byte[] bytesIn = new byte[4096];
                    int read = 0;
                    while ((read = zipIn.read(bytesIn)) != -1) {
                        bos.write(bytesIn, 0, read);
                    }
                    bos.close();
                } else {
                    outputFile.mkdirs();
                }
                zipIn.closeEntry();
            }
            zipIn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            String zipFilePath = "archive.zip";
            String outputFolder = "/opt/app/files/";
            
            ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath));
            ZipEntry entry;
            
            // ok: java-zip-entry-overwrite
            // Create a safe directory resolver
            Path outputPath = Paths.get(outputFolder).normalize();
            String canonicalOutputPath = outputPath.toFile().getCanonicalPath() + File.separator;
            
            while ((entry = zipInputStream.getNextEntry()) != null) {
                String entryName = entry.getName();
                
                // Normalize the path and check for traversal
                Path resolvedPath = outputPath.resolve(entryName).normalize();
                String canonicalEntryPath = resolvedPath.toFile().getCanonicalPath();
                
                // Ensure the entry path is within the output directory
                if (!canonicalEntryPath.startsWith(canonicalOutputPath)) {
                    System.out.println("Path traversal attempt detected: " + entryName);
                    continue;
                }
                
                File outputFile = resolvedPath.toFile();
                
                if (entry.isDirectory()) {
                    outputFile.mkdirs();
                } else {
                    // Create parent directories if needed
                    if (outputFile.getParentFile() != null) {
                        outputFile.getParentFile().mkdirs();
                    }
                    
                    FileOutputStream outputStream = new FileOutputStream(outputFile);
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = zipInputStream.read(buffer)) > 0) {
                        outputStream.write(buffer, 0, length);
                    }
                    outputStream.close();
                }
                zipInputStream.closeEntry();
            }
            zipInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8(HttpServletRequest request) {
        try {
            String zipFile = request.getParameter("file");
            String destDir = System.getProperty("user.home") + "/extracted/";
            
            File dir = new File(destDir);
            if (!dir.exists()) dir.mkdirs();
            
            String canonicalDestDir = dir.getCanonicalPath() + File.separator;
            
            FileInputStream fis = new FileInputStream(zipFile);
            ZipInputStream zipIn = new ZipInputStream(fis);
            ZipEntry entry;
            
            while ((entry = zipIn.getNextEntry()) != null) {
                String entryName = entry.getName();
                
                // ok: java-zip-entry-overwrite
                // Validate the entry name
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                    System.out.println("Potentially malicious entry: " + entryName);
                    continue;
                }
                
                File outputFile = new File(destDir, entryName);
                String canonicalOutputPath = outputFile.getCanonicalPath();
                
                // Ensure the output file is within the destination directory
                if (!canonicalOutputPath.startsWith(canonicalDestDir)) {
                    System.out.println("Path traversal attempt: " + entryName);
                    continue;
                }
                
                if (!entry.isDirectory()) {
                    // Extract file
                    extractFile(zipIn, canonicalOutputPath);
                } else {
                    // Create directory
                    File dirPath = new File(canonicalOutputPath);
                    dirPath.mkdirs();
                }
                zipIn.closeEntry();
            }
            zipIn.close();
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            File zipFile = new File("data.zip");
            File targetDir = new File("/var/data/");
            String canonicalTargetPath = targetDir.getCanonicalPath() + File.separator;
            
            ZipFile zip = new ZipFile(zipFile);
            Enumeration<? extends ZipEntry> zipEntries = zip.entries();
            
            while (zipEntries.hasMoreElements()) {
                ZipEntry entry = zipEntries.nextElement();
                String entryName = entry.getName();
                
                // ok: java-zip-entry-overwrite
                // Check for path traversal attempts
                if (entryName.contains("..") || entryName.startsWith("/")) {
                    System.out.println("Skipping potentially malicious entry: " + entryName);
                    continue;
                }
                
                // Use Path to safely resolve and normalize the path
                Path targetPath = targetDir.toPath().resolve(entryName).normalize();
                File targetFile = targetPath.toFile();
                
                // Verify the target file is within the target directory
                if (!targetFile.getCanonicalPath().startsWith(canonicalTargetPath)) {
                    System.out.println("Path traversal attempt detected: " + entryName);
                    continue;
                }
                
                if (entry.isDirectory()) {
                    targetFile.mkdirs();
                    continue;
                }
                
                InputStream inputStream = zip.getInputStream(entry);
                FileOutputStream outputStream = new FileOutputStream(targetFile);
                
                byte[] buffer = new byte[1024];
                int length;
                while ((length = inputStream.read(buffer)) > 0) {
                    outputStream.write(buffer, 0, length);
                }
                
                outputStream.close();
                inputStream.close();
            }
            
            zip.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(HttpServletRequest request) {
        try {
            String zipPath = request.getParameter("zipPath");
            String extractDir = "/app/public/images/";
            
            ZipFile zipFile = new ZipFile(zipPath);
            File destinationDir = new File(extractDir);
            String canonicalDestDir = destinationDir.getCanonicalPath() + File.separator;
            
            for (Enumeration<? extends ZipEntry> e = zipFile.entries(); e.hasMoreElements();) {
                ZipEntry entry = e.nextElement();
                String entryName = entry.getName();
                
                // ok: java-zip-entry-overwrite
                // Validate the entry name
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                    System.out.println("Potentially malicious entry: " + entryName);
                    continue;
                }
                
                // Create a safe path
                Path destinationPath = Paths.get(extractDir, entryName).normalize();
                File outputFile = destinationPath.toFile();
                
                // Verify the path is within the destination directory
                if (!outputFile.getCanonicalPath().startsWith(canonicalDestDir)) {
                    System.out.println("Path traversal attempt: " + entryName);
                    continue;
                }
                
                if (entry.isDirectory()) {
                    outputFile.mkdirs();
                } else {
                    outputFile.getParentFile().mkdirs();
                    
                    InputStream in = zipFile.getInputStream(entry);
                    FileOutputStream out = new FileOutputStream(outputFile);
                    
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = in.read(buffer)) >= 0) {
                        out.write(buffer, 0, len);
                    }
                    
                    in.close();
                    out.close();
                }
            }
            
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            String zipFilePath = "package.zip";
            String outputDir = "/opt/webapps/ROOT/";
            
            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath));
            ZipEntry zipEntry;
            byte[] buffer = new byte[2048];
            
            File outputDirectory = new File(outputDir);
            String canonicalOutputDir = outputDirectory.getCanonicalPath() + File.separator;
            
            while ((zipEntry = zis.getNextEntry()) != null) {
                String fileName = zipEntry.getName();
                
                // ok: java-zip-entry-overwrite
                // Validate filename
                if (fileName.contains("..") || fileName.startsWith("/") || fileName.startsWith("\\")) {
                    System.out.println("Potentially malicious entry: " + fileName);
                    continue;
                }
                
                // Create a safe path
                Path targetPath = Paths.get(outputDir, fileName).normalize();
                File newFile = targetPath.toFile();
                
                // Verify the path is within the destination directory
                if (!newFile.getCanonicalPath().startsWith(canonicalOutputDir)) {
                    System.out.println("Path traversal attempt: " + fileName);
                    continue;
                }
                
                if (zipEntry.isDirectory()) {
                    newFile.mkdirs();
                } else {
                    new File(newFile.getParent()).mkdirs();
                    FileOutputStream fos = new FileOutputStream(newFile);
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        fos.write(buffer, 0, len);
                    }
                    fos.close();
                }
                zis.closeEntry();
            }
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(HttpServletRequest request) {
        try {
            String zipFileName = request.getParameter("zipFile");
            String outputPath = "/tmp/uploads/";
            
            File outputDir = new File(outputPath);
            String canonicalOutputPath = outputDir.getCanonicalPath() + File.separator;
            
            try (ZipFile zipFile = new ZipFile(zipFileName)) {
                Enumeration<? extends ZipEntry> entries = zipFile.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String entryName = entry.getName();
                    
                    // ok: java-zip-entry-overwrite
                    // Use FilenameUtils to get a safe name
                    String safeName = FilenameUtils.normalize(entryName);
                    if (safeName == null || safeName.contains("..") || safeName.startsWith("/")) {
                        System.out.println("Potentially malicious entry: " + entryName);
                        continue;
                    }
                    
                    File entryDestination = new File(outputDir, safeName);
                    
                    // Verify the path is within the destination directory
                    if (!entryDestination.getCanonicalPath().startsWith(canonicalOutputPath)) {
                        System.out.println("Path traversal attempt: " + entryName);
                        continue;
                    }
                    
                    if (entry.isDirectory()) {
                        entryDestination.mkdirs();
                    } else {
                        entryDestination.getParentFile().mkdirs();
                        try (InputStream in = zipFile.getInputStream(entry);
                             OutputStream out = new FileOutputStream(entryDestination)) {
                            byte[] buffer = new byte[1024];
                            int length;
                            while ((length = in.read(buffer)) > 0) {
                                out.write(buffer, 0, length);
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            String zipFile = "content.zip";
            String extractFolder = "/var/www/html/";
            
            byte[] buffer = new byte[1024];
            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
            ZipEntry zipEntry = zis.getNextEntry();
            
            File destDir = new File(extractFolder);
            String canonicalDestPath = destDir.getCanonicalPath() + File.separator;
            
            // ok: java-zip-entry-overwrite
            // Define a pattern for safe filenames
            Pattern safePattern = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9_\\-\\.]*(/[a-zA-Z0-9][a-zA-Z0-9_\\-\\.]*)*$");
            
            while (zipEntry != null) {
                String fileName = zipEntry.getName();
                
                // Validate the filename against the safe pattern
                if (!safePattern.matcher(fileName).matches()) {
                    System.out.println("Potentially malicious entry: " + fileName);
                    zipEntry = zis.getNextEntry();
                    continue;
                }
                
                // Create a safe path
                Path targetPath = Paths.get(extractFolder, fileName).normalize();
                File newFile = targetPath.toFile();
                
                // Verify the path is within the destination directory
                if (!newFile.getCanonicalPath().startsWith(canonicalDestPath)) {
                    System.out.println("Path traversal attempt: " + fileName);
                    zipEntry = zis.getNextEntry();
                    continue;
                }
                
                // Create directories for sub directories in zip
                new File(newFile.getParent()).mkdirs();
                
                FileOutputStream fos = new FileOutputStream(newFile);
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
                
                zipEntry = zis.getNextEntry();
            }
            zis.closeEntry();
            zis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14(HttpServletRequest request) {
        try {
            String zipPath = request.getParameter("path");
            String destPath = "/home/user/public_html/";
            
            File destDir = new File(destPath);
            if (!destDir.exists()) {
                destDir.mkdir();
            }
            
            String canonicalDestPath = destDir.getCanonicalPath() + File.separator;
            
            ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipPath));
            ZipEntry entry = zipIn.getNextEntry();
            
            while (entry != null) {
                String entryName = entry.getName();
                
                // ok: java-zip-entry-overwrite
                // Sanitize the entry name
                String sanitizedName = entryName.replaceAll("[\\\\/:*?\"<>|]", "_");
                sanitizedName = sanitizedName.replaceAll("\\.\\.", "_");
                
                File targetFile = new File(destDir, sanitizedName);
                String canonicalTargetPath = targetFile.getCanonicalPath();
                
                // Verify the target file is within the destination directory
                if (!canonicalTargetPath.startsWith(canonicalDestPath)) {
                    System.out.println("Path traversal attempt: " + entryName);
                    entry = zipIn.getNextEntry();
                    continue;
                }
                
                if (!entry.isDirectory()) {
                    // Extract file
                    targetFile.getParentFile().mkdirs();
                    BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(targetFile));
                    byte[] bytesIn = new byte[4096];
                    int read = 0;
                    while ((read = zipIn.read(bytesIn)) != -1) {
                        bos.write(bytesIn, 0, read);
                    }
                    bos.close();
                } else {
                    // Create directory
                    targetFile.mkdirs();
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
            zipIn.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            String zipFilePath = "updates.zip";
            String destDirectory = "/usr/share/app/";
            
            File destDir = new File(destDirectory);
            if (!destDir.exists()) {
                destDir.mkdir();
            }
            
            String canonicalDestPath = destDir.getCanonicalPath() + File.separator;
            
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                
                // ok: java-zip-entry-overwrite
                // Use Path API to safely resolve and normalize paths
                Path destinationPath = Paths.get(destDirectory).resolve(entryName).normalize();
                File entryDestination = destinationPath.toFile();
                
                // Verify the path is within the destination directory
                if (!entryDestination.getCanonicalPath().startsWith(canonicalDestPath)) {
                    System.out.println("Path traversal attempt: " + entryName);
                    continue;
                }
                
                if (entry.isDirectory()) {
                    entryDestination.mkdirs();
                } else {
                    entryDestination.getParentFile().mkdirs();
                    InputStream in = zipFile.getInputStream(entry);
                    OutputStream out = new FileOutputStream(entryDestination);
                    
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = in.read(buffer)) > 0) {
                        out.write(buffer, 0, length);
                    }
                    
                    in.close();
                    out.close();
                }
            }
            
            zipFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}