import java.io.*;
import java.util.*;
import java.nio.file.*;
import javax.servlet.http.*;
import javax.servlet.*;
import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.servlet.*;
import org.apache.commons.fileupload.disk.*;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.*;
import org.springframework.stereotype.*;
import org.springframework.http.*;
import java.util.regex.Pattern;

@Controller
public class FileUploadExamples {

    // True positives (vulnerable code)
    
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) throws Exception {
        if (ServletFileUpload.isMultipartContent(request)) {
            DiskFileItemFactory factory = new DiskFileItemFactory();
            ServletFileUpload upload = new ServletFileUpload(factory);
            
            List<FileItem> items = upload.parseRequest(request);
            for (FileItem item : items) {
                if (!item.isFormField()) {
                    String fileName = item.getName();
                    // ruleid: java-lackoffileextensionvalidation
                    File uploadedFile = new File("/uploads/" + fileName);
                    item.write(uploadedFile);
                }
            }
        }
    }
    
    @PostMapping("/upload2")
    public void bad_case_2(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        // ruleid: java-lackoffileextensionvalidation
        Path path = Paths.get("/uploads/" + fileName);
        Files.write(path, file.getBytes());
    }
    
    public void bad_case_3(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = Paths.get(filePart.getSubmittedFileName()).getFileName().toString();
        
        // ruleid: java-lackoffileextensionvalidation
        try (InputStream inputStream = filePart.getInputStream();
             FileOutputStream outputStream = new FileOutputStream(new File("/uploads/" + fileName))) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }
    
    @PostMapping("/upload4")
    public void bad_case_4(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        File dest = new File("/uploads/");
        if (!dest.exists()) {
            dest.mkdirs();
        }
        
        // ruleid: java-lackoffileextensionvalidation
        File uploadedFile = new File(dest.getAbsolutePath() + File.separator + fileName);
        file.transferTo(uploadedFile);
    }
    
    public void bad_case_5(HttpServletRequest request) throws Exception {
        if (!ServletFileUpload.isMultipartContent(request)) {
            return;
        }
        
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        
        List<FileItem> items = upload.parseRequest(request);
        for (FileItem item : items) {
            if (!item.isFormField()) {
                String fileName = new File(item.getName()).getName();
                // ruleid: java-lackoffileextensionvalidation
                File uploadedFile = new File("/var/www/uploads/" + fileName);
                item.write(uploadedFile);
            }
        }
    }
    
    @PostMapping("/upload6")
    public void bad_case_6(HttpServletRequest request) throws Exception {
        Collection<Part> parts = request.getParts();
        for (Part part : parts) {
            String fileName = part.getSubmittedFileName();
            if (fileName != null && !fileName.isEmpty()) {
                // ruleid: java-lackoffileextensionvalidation
                part.write("/uploads/" + fileName);
            }
        }
    }
    
    public void bad_case_7(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        
        // ruleid: java-lackoffileextensionvalidation
        File file = new File(System.getProperty("user.home") + "/uploads/" + fileName);
        try (InputStream input = filePart.getInputStream();
             OutputStream output = new FileOutputStream(file)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = input.read(buffer)) > 0) {
                output.write(buffer, 0, length);
            }
        }
    }
    
    @PostMapping("/upload8")
    public void bad_case_8(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        
        // Check if file is empty but don't validate extension
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }
        
        // ruleid: java-lackoffileextensionvalidation
        File dest = new File("/uploads/" + fileName);
        file.transferTo(dest);
    }
    
    public void bad_case_9(HttpServletRequest request) throws Exception {
        String uploadPath = "/uploads/";
        File uploadDir = new File(uploadPath);
        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }
        
        for (Part part : request.getParts()) {
            String fileName = part.getSubmittedFileName();
            if (fileName != null) {
                // ruleid: java-lackoffileextensionvalidation
                part.write(uploadPath + File.separator + fileName);
            }
        }
    }
    
    @PostMapping("/upload10")
    public void bad_case_10(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        
        // Check file size but not extension
        if (file.getSize() > 5000000) {
            throw new IllegalArgumentException("File too large");
        }
        
        // ruleid: java-lackoffileextensionvalidation
        Path path = Paths.get("/uploads/" + fileName);
        Files.copy(file.getInputStream(), path, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
    }
    
    public void bad_case_11(HttpServletRequest request) throws Exception {
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        
        List<FileItem> items = upload.parseRequest(request);
        for (FileItem item : items) {
            if (!item.isFormField()) {
                String contentType = item.getContentType();
                // Only checking content type, not file extension
                if (contentType.startsWith("image/")) {
                    String fileName = item.getName();
                    // ruleid: java-lackoffileextensionvalidation
                    File uploadedFile = new File("/uploads/" + fileName);
                    item.write(uploadedFile);
                }
            }
        }
    }
    
    @PostMapping("/upload12")
    public void bad_case_12(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        String contentType = file.getContentType();
        
        // Only checking content type, not file extension
        if (contentType != null && contentType.startsWith("application/pdf")) {
            // ruleid: java-lackoffileextensionvalidation
            Path path = Paths.get("/uploads/" + fileName);
            Files.write(path, file.getBytes());
        }
    }
    
    public void bad_case_13(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        
        // Checking file size but not extension
        if (filePart.getSize() <= 1048576) { // 1MB max
            // ruleid: java-lackoffileextensionvalidation
            File file = new File("/uploads/" + fileName);
            try (InputStream input = filePart.getInputStream();
                 OutputStream output = new FileOutputStream(file)) {
                byte[] buffer = new byte[1024];
                int length;
                while ((length = input.read(buffer)) > 0) {
                    output.write(buffer, 0, length);
                }
            }
        }
    }
    
    @PostMapping("/upload14")
    public void bad_case_14(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        
        // Sanitizing the filename but not validating extension
        fileName = fileName.replaceAll("[^a-zA-Z0-9.-]", "_");
        
        // ruleid: java-lackoffileextensionvalidation
        Path path = Paths.get("/uploads/" + fileName);
        Files.copy(file.getInputStream(), path, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
    }
    
    public void bad_case_15(HttpServletRequest request) throws Exception {
        Collection<Part> parts = request.getParts();
        
        for (Part part : parts) {
            if (part.getContentType() != null) {
                String fileName = part.getSubmittedFileName();
                
                // Adding timestamp to filename but not validating extension
                String timestamp = String.valueOf(System.currentTimeMillis());
                String newFileName = timestamp + "_" + fileName;
                
                // ruleid: java-lackoffileextensionvalidation
                part.write("/uploads/" + newFileName);
            }
        }
    }
    
    // True negatives (secure code)
    
    public void good_case_1(HttpServletRequest request) throws Exception {
        if (ServletFileUpload.isMultipartContent(request)) {
            DiskFileItemFactory factory = new DiskFileItemFactory();
            ServletFileUpload upload = new ServletFileUpload(factory);
            
            List<FileItem> items = upload.parseRequest(request);
            for (FileItem item : items) {
                if (!item.isFormField()) {
                    String fileName = item.getName();
                    String extension = FilenameUtils.getExtension(fileName);
                    
                    // ok: java-lackoffileextensionvalidation
                    if (Arrays.asList("jpg", "jpeg", "png", "gif").contains(extension.toLowerCase())) {
                        File uploadedFile = new File("/uploads/" + fileName);
                        item.write(uploadedFile);
                    }
                }
            }
        }
    }
    
    @PostMapping("/upload2")
    public void good_case_2(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        String extension = FilenameUtils.getExtension(fileName);
        
        // ok: java-lackoffileextensionvalidation
        if (Arrays.asList("pdf", "doc", "docx", "txt").contains(extension.toLowerCase())) {
            Path path = Paths.get("/uploads/" + fileName);
            Files.write(path, file.getBytes());
        } else {
            throw new IllegalArgumentException("Invalid file extension");
        }
    }
    
    public void good_case_3(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = Paths.get(filePart.getSubmittedFileName()).getFileName().toString();
        String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        
        // ok: java-lackoffileextensionvalidation
        if (extension.equals("pdf") || extension.equals("txt")) {
            try (InputStream inputStream = filePart.getInputStream();
                 FileOutputStream outputStream = new FileOutputStream(new File("/uploads/" + fileName))) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
        }
    }
    
    @PostMapping("/upload4")
    public void good_case_4(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        String extension = "";
        
        if (fileName != null && fileName.contains(".")) {
            extension = fileName.substring(fileName.lastIndexOf(".") + 1);
        }
        
        // ok: java-lackoffileextensionvalidation
        Set<String> allowedExtensions = new HashSet<>(Arrays.asList("jpg", "jpeg", "png"));
        if (allowedExtensions.contains(extension.toLowerCase())) {
            File dest = new File("/uploads/");
            if (!dest.exists()) {
                dest.mkdirs();
            }
            
            File uploadedFile = new File(dest.getAbsolutePath() + File.separator + fileName);
            file.transferTo(uploadedFile);
        }
    }
    
    public void good_case_5(HttpServletRequest request) throws Exception {
        if (!ServletFileUpload.isMultipartContent(request)) {
            return;
        }
        
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        
        List<FileItem> items = upload.parseRequest(request);
        for (FileItem item : items) {
            if (!item.isFormField()) {
                String fileName = new File(item.getName()).getName();
                String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                
                // ok: java-lackoffileextensionvalidation
                List<String> allowedExtensions = Arrays.asList("pdf", "doc", "docx", "xls", "xlsx");
                if (allowedExtensions.contains(extension)) {
                    File uploadedFile = new File("/var/www/uploads/" + fileName);
                    item.write(uploadedFile);
                }
            }
        }
    }
    
    @PostMapping("/upload6")
    public void good_case_6(HttpServletRequest request) throws Exception {
        Collection<Part> parts = request.getParts();
        Pattern allowedExtensionPattern = Pattern.compile(".*\\.(jpg|jpeg|png|gif)$", Pattern.CASE_INSENSITIVE);
        
        for (Part part : parts) {
            String fileName = part.getSubmittedFileName();
            if (fileName != null && !fileName.isEmpty()) {
                // ok: java-lackoffileextensionvalidation
                if (allowedExtensionPattern.matcher(fileName).matches()) {
                    part.write("/uploads/" + fileName);
                }
            }
        }
    }
    
    public void good_case_7(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        String extension = "";
        
        if (fileName.lastIndexOf(".") != -1) {
            extension = fileName.substring(fileName.lastIndexOf(".") + 1);
        }
        
        // ok: java-lackoffileextensionvalidation
        if ("csv".equalsIgnoreCase(extension) || "xlsx".equalsIgnoreCase(extension)) {
            File file = new File(System.getProperty("user.home") + "/uploads/" + fileName);
            try (InputStream input = filePart.getInputStream();
                 OutputStream output = new FileOutputStream(file)) {
                byte[] buffer = new byte[1024];
                int length;
                while ((length = input.read(buffer)) > 0) {
                    output.write(buffer, 0, length);
                }
            }
        }
    }
    
    @PostMapping("/upload8")
    public void good_case_8(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }
        
        // ok: java-lackoffileextensionvalidation
        String extension = FilenameUtils.getExtension(fileName);
        List<String> allowedExtensions = Arrays.asList("pdf", "txt", "doc", "docx");
        
        if (allowedExtensions.contains(extension.toLowerCase())) {
            File dest = new File("/uploads/" + fileName);
            file.transferTo(dest);
        } else {
            throw new IllegalArgumentException("Invalid file extension");
        }
    }
    
    public void good_case_9(HttpServletRequest request) throws Exception {
        String uploadPath = "/uploads/";
        File uploadDir = new File(uploadPath);
        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }
        
        // ok: java-lackoffileextensionvalidation
        for (Part part : request.getParts()) {
            String fileName = part.getSubmittedFileName();
            if (fileName != null) {
                String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                if (extension.equals("jpg") || extension.equals("png") || extension.equals("gif")) {
                    part.write(uploadPath + File.separator + fileName);
                }
            }
        }
    }
    
    @PostMapping("/upload10")
    public void good_case_10(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        
        if (file.getSize() > 5000000) {
            throw new IllegalArgumentException("File too large");
        }
        
        // ok: java-lackoffileextensionvalidation
        String fileExtension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        Set<String> validExtensions = new HashSet<>(Arrays.asList("jpg", "jpeg", "png", "gif", "pdf"));
        
        if (validExtensions.contains(fileExtension)) {
            Path path = Paths.get("/uploads/" + fileName);
            Files.copy(file.getInputStream(), path, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
        } else {
            throw new IllegalArgumentException("Invalid file extension");
        }
    }
    
    public void good_case_11(HttpServletRequest request) throws Exception {
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        
        List<FileItem> items = upload.parseRequest(request);
        for (FileItem item : items) {
            if (!item.isFormField()) {
                String fileName = item.getName();
                String contentType = item.getContentType();
                String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                
                // ok: java-lackoffileextensionvalidation
                if (contentType.startsWith("image/") && 
                    (extension.equals("jpg") || extension.equals("jpeg") || 
                     extension.equals("png") || extension.equals("gif"))) {
                    File uploadedFile = new File("/uploads/" + fileName);
                    item.write(uploadedFile);
                }
            }
        }
    }
    
    @PostMapping("/upload12")
    public void good_case_12(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        String contentType = file.getContentType();
        String extension = "";
        
        if (fileName != null && fileName.contains(".")) {
            extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        }
        
        // ok: java-lackoffileextensionvalidation
        if (contentType != null && contentType.startsWith("application/pdf") && extension.equals("pdf")) {
            Path path = Paths.get("/uploads/" + fileName);
            Files.write(path, file.getBytes());
        }
    }
    
    public void good_case_13(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        String extension = "";
        
        if (fileName != null && fileName.lastIndexOf(".") != -1) {
            extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        }
        
        // ok: java-lackoffileextensionvalidation
        if (filePart.getSize() <= 1048576 && // 1MB max
            (extension.equals("txt") || extension.equals("csv") || extension.equals("json"))) {
            File file = new File("/uploads/" + fileName);
            try (InputStream input = filePart.getInputStream();
                 OutputStream output = new FileOutputStream(file)) {
                byte[] buffer = new byte[1024];
                int length;
                while ((length = input.read(buffer)) > 0) {
                    output.write(buffer, 0, length);
                }
            }
        }
    }
    
    @PostMapping("/upload14")
    public void good_case_14(@RequestParam("file") MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        
        // Sanitize the filename
        fileName = fileName.replaceAll("[^a-zA-Z0-9.-]", "_");
        
        // ok: java-lackoffileextensionvalidation
        String extension = FilenameUtils.getExtension(fileName).toLowerCase();
        if (extension.equals("jpg") || extension.equals("jpeg") || extension.equals("png")) {
            Path path = Paths.get("/uploads/" + fileName);
            Files.copy(file.getInputStream(), path, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
        } else {
            throw new IllegalArgumentException("Only JPG, JPEG and PNG files are allowed");
        }
    }
    
    public void good_case_15(HttpServletRequest request) throws Exception {
        Collection<Part> parts = request.getParts();
        
        for (Part part : parts) {
            if (part.getContentType() != null) {
                String fileName = part.getSubmittedFileName();
                String extension = "";
                
                if (fileName != null && fileName.lastIndexOf(".") != -1) {
                    extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                }
                
                // ok: java-lackoffileextensionvalidation
                if (Arrays.asList("pdf", "doc", "docx", "xls", "xlsx").contains(extension)) {
                    String timestamp = String.valueOf(System.currentTimeMillis());
                    String newFileName = timestamp + "_" + fileName;
                    part.write("/uploads/" + newFileName);
                }
            }
        }
    }
}
// {/fact}