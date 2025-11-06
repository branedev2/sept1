import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;
import javax.servlet.*;
import java.util.regex.Pattern;
import org.apache.commons.io.FilenameUtils;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Validator;

public class PathTraversalExamples extends HttpServlet {

    // TRUE POSITIVES (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        
        // ruleid: java-path-traversal
        File file = new File("/var/data/" + fileName);
        FileInputStream fis = new FileInputStream(file);
        
        // Read and return file content
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        fis.close();
    }

    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userDir = request.getParameter("directory");
        String userFile = request.getParameter("filename");
        
        // ruleid: java-path-traversal
        FileWriter fileWriter = new FileWriter(userDir + "/" + userFile);
        fileWriter.write("Some content");
        fileWriter.close();
    }

    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String reportId = request.getParameter("reportId");
        
        // ruleid: java-path-traversal
        BufferedReader reader = new BufferedReader(new FileReader("/reports/" + reportId + ".pdf"));
        String line;
        while ((line = reader.readLine()) != null) {
            response.getWriter().println(line);
        }
        reader.close();
    }

    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String template = request.getHeader("X-Template");
        
        // ruleid: java-path-traversal
        Path path = Paths.get("/templates/" + template);
        byte[] fileContent = Files.readAllBytes(path);
        response.getOutputStream().write(fileContent);
    }

    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String logFile = request.getParameter("logFile");
        
        // ruleid: java-path-traversal
        RandomAccessFile raf = new RandomAccessFile("/var/logs/" + logFile, "r");
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = raf.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        raf.close();
    }

    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String configName = request.getParameter("config");
        
        // ruleid: java-path-traversal
        FileOutputStream fos = new FileOutputStream("/etc/app/config/" + configName);
        fos.write("config data".getBytes());
        fos.close();
    }

    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("id");
        
        // ruleid: java-path-traversal
        File userProfile = new File("/home/users/" + userId + "/profile.json");
        if (userProfile.exists()) {
            FileInputStream fis = new FileInputStream(userProfile);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
            fis.close();
        }
    }

    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String backupFile = request.getParameter("backup");
        String content = request.getParameter("content");
        
        // ruleid: java-path-traversal
        try (PrintWriter writer = new PrintWriter(new FileWriter("/backups/" + backupFile))) {
            writer.println(content);
        }
    }

    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookieValue = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("userFile".equals(cookie.getName())) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        }
        
        if (cookieValue != null) {
            // ruleid: java-path-traversal
            File file = new File("/data/files/" + cookieValue);
            if (file.exists()) {
                response.setContentType("application/octet-stream");
                Files.copy(file.toPath(), response.getOutputStream());
            }
        }
    }

    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String relativePath = request.getParameter("path");
        
        // ruleid: java-path-traversal
        File directory = new File("/var/www/html/" + relativePath);
        if (directory.isDirectory()) {
            String[] files = directory.list();
            for (String file : files) {
                response.getWriter().println(file);
            }
        }
    }

    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String module = request.getParameter("module");
        
        // ruleid: java-path-traversal
        try (InputStream is = new FileInputStream("/opt/app/modules/" + module + ".jar")) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        }
    }

    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        String content = request.getParameter("content");
        
        // ruleid: java-path-traversal
        Files.write(Paths.get("/tmp/uploads/" + fileName), content.getBytes());
        response.getWriter().println("File saved successfully");
    }

    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String imageName = request.getParameter("image");
        
        // ruleid: java-path-traversal
        File imageFile = new File("/var/www/images/" + imageName);
        response.setContentType("image/jpeg");
        try (FileInputStream fis = new FileInputStream(imageFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        }
    }

    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String theme = request.getParameter("theme");
        
        // ruleid: java-path-traversal
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream("/var/www/themes/" + theme + "/style.css")));
        String line;
        response.setContentType("text/css");
        while ((line = reader.readLine()) != null) {
            response.getWriter().println(line);
        }
        reader.close();
    }

    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        
        // ruleid: java-path-traversal
        File userDir = new File("/home/" + username);
        if (userDir.exists() && userDir.isDirectory()) {
            File[] files = userDir.listFiles();
            for (File file : files) {
                response.getWriter().println(file.getName());
            }
        }
    }

    // TRUE NEGATIVES (Secure Code)

    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        
        // Validate filename using whitelist
        // ok: java-path-traversal
        if (fileName != null && (fileName.equals("report.pdf") || fileName.equals("invoice.pdf"))) {
            File file = new File("/var/data/" + fileName);
            FileInputStream fis = new FileInputStream(file);
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
            fis.close();
        }
    }

    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userFile = request.getParameter("filename");
        
        // Canonicalize and validate path
        // ok: java-path-traversal
        File file = new File("/var/data/", userFile);
        String canonicalPath = file.getCanonicalPath();
        if (!canonicalPath.startsWith("/var/data/")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file path");
            return;
        }
        
        FileWriter fileWriter = new FileWriter(file);
        fileWriter.write("Some content");
        fileWriter.close();
    }

    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String reportId = request.getParameter("reportId");
        
        // Validate input is numeric only
        // ok: java-path-traversal
        if (reportId != null && reportId.matches("^[0-9]+$")) {
            BufferedReader reader = new BufferedReader(new FileReader("/reports/" + reportId + ".pdf"));
            String line;
            while ((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
            reader.close();
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid report ID");
        }
    }

    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String template = request.getHeader("X-Template");
        
        // Use FilenameUtils to get base name only
        // ok: java-path-traversal
        String safeTemplate = FilenameUtils.getName(template);
        Path path = Paths.get("/templates/" + safeTemplate);
        byte[] fileContent = Files.readAllBytes(path);
        response.getOutputStream().write(fileContent);
    }

    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String logFile = request.getParameter("logFile");
        
        // Validate against allowed patterns
        // ok: java-path-traversal
        Pattern pattern = Pattern.compile("^[a-zA-Z0-9_-]+\\.log$");
        if (pattern.matcher(logFile).matches()) {
            RandomAccessFile raf = new RandomAccessFile("/var/logs/" + logFile, "r");
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = raf.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
            raf.close();
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid log file name");
        }
    }

    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String configName = request.getParameter("config");
        
        // Use ESAPI validator
        Validator validator = ESAPI.validator();
        // ok: java-path-traversal
        if (validator.isValidFileName("Config", configName, new String[] {".conf", ".config"}, false)) {
            FileOutputStream fos = new FileOutputStream("/etc/app/config/" + configName);
            fos.write("config data".getBytes());
            fos.close();
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid config name");
        }
    }

    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("id");
        
        // Use Path.resolve and normalize
        // ok: java-path-traversal
        Path basePath = Paths.get("/home/users");
        Path userPath = basePath.resolve(userId).normalize();
        
        if (userPath.startsWith(basePath)) {
            Path profilePath = userPath.resolve("profile.json");
            if (Files.exists(profilePath)) {
                Files.copy(profilePath, response.getOutputStream());
            }
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID");
        }
    }

    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String backupFile = request.getParameter("backup");
        String content = request.getParameter("content");
        
        // Use UUID for filename instead of user input
        // ok: java-path-traversal
        String safeFileName = java.util.UUID.randomUUID().toString() + ".bak";
        try (PrintWriter writer = new PrintWriter(new FileWriter("/backups/" + safeFileName))) {
            writer.println(content);
        }
        response.getWriter().println("Backup saved as: " + safeFileName);
    }

    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookieValue = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("userFile".equals(cookie.getName())) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        }
        
        if (cookieValue != null) {
            // Use a map to validate allowed files
            // ok: java-path-traversal
            java.util.Map<String, String> allowedFiles = new java.util.HashMap<>();
            allowedFiles.put("profile", "profile.pdf");
            allowedFiles.put("terms", "terms.pdf");
            allowedFiles.put("privacy", "privacy.pdf");
            
            if (allowedFiles.containsKey(cookieValue)) {
                File file = new File("/data/files/" + allowedFiles.get(cookieValue));
                if (file.exists()) {
                    response.setContentType("application/octet-stream");
                    Files.copy(file.toPath(), response.getOutputStream());
                }
            }
        }
    }

    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String relativePath = request.getParameter("path");
        
        // Restrict to specific subdirectories
        // ok: java-path-traversal
        String[] allowedDirs = {"images", "css", "js"};
        boolean isAllowed = false;
        
        for (String dir : allowedDirs) {
            if (dir.equals(relativePath)) {
                isAllowed = true;
                break;
            }
        }
        
        if (isAllowed) {
            File directory = new File("/var/www/html/" + relativePath);
            if (directory.isDirectory()) {
                String[] files = directory.list();
                for (String file : files) {
                    response.getWriter().println(file);
                }
            }
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        }
    }

    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String module = request.getParameter("module");
        
        // Use a predefined list of modules
        // ok: java-path-traversal
        java.util.Set<String> allowedModules = new java.util.HashSet<>();
        allowedModules.add("core");
        allowedModules.add("admin");
        allowedModules.add("user");
        
        if (allowedModules.contains(module)) {
            try (InputStream is = new FileInputStream("/opt/app/modules/" + module + ".jar")) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    response.getOutputStream().write(buffer, 0, bytesRead);
                }
            }
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid module");
        }
    }

    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String content = request.getParameter("content");
        
        // Generate safe filename instead of using user input
        // ok: java-path-traversal
        String fileName = System.currentTimeMillis() + "_" + 
                          java.util.UUID.randomUUID().toString().substring(0, 8) + ".txt";
        
        Files.write(Paths.get("/tmp/uploads/" + fileName), content.getBytes());
        response.getWriter().println("File saved successfully as: " + fileName);
    }

    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String imageName = request.getParameter("image");
        
        // Validate file extension and use secure path construction
        // ok: java-path-traversal
        if (imageName != null && 
            (imageName.endsWith(".jpg") || imageName.endsWith(".png") || imageName.endsWith(".gif"))) {
            
            File imageDir = new File("/var/www/images");
            File imageFile = new File(imageDir, imageName);
            
            // Ensure the file is within the intended directory
            if (imageFile.getCanonicalPath().startsWith(imageDir.getCanonicalPath())) {
                response.setContentType("image/jpeg");
                try (FileInputStream fis = new FileInputStream(imageFile)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        response.getOutputStream().write(buffer, 0, bytesRead);
                    }
                }
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid image path");
            }
        }
    }

    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String theme = request.getParameter("theme");
        
        // Use a switch statement to validate input against known values
        // ok: java-path-traversal
        String themePath;
        switch (theme) {
            case "light":
                themePath = "/var/www/themes/light/style.css";
                break;
            case "dark":
                themePath = "/var/www/themes/dark/style.css";
                break;
            case "blue":
                themePath = "/var/www/themes/blue/style.css";
                break;
            default:
                themePath = "/var/www/themes/default/style.css";
                break;
        }
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(themePath)));
        String line;
        response.setContentType("text/css");
        while ((line = reader.readLine()) != null) {
            response.getWriter().println(line);
        }
        reader.close();
    }

    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        
        // Validate username format and construct path safely
        // ok: java-path-traversal
        if (username != null && username.matches("^[a-zA-Z0-9]{3,16}$")) {
            File baseDir = new File("/home");
            File userDir = new File(baseDir, username);
            
            // Additional check to ensure we're still in the intended directory
            if (userDir.getCanonicalPath().startsWith(baseDir.getCanonicalPath()) && 
                userDir.exists() && userDir.isDirectory()) {
                
                File[] files = userDir.listFiles();
                for (File file : files) {
                    response.getWriter().println(file.getName());
                }
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "User directory not found");
            }
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid username format");
        }
    }
}
// {/fact}