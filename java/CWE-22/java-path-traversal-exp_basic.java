import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.io.FilenameUtils;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.validators.Validator;

public class PathTraversalExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=path-traversal@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        // ruleid: java-path-traversal-exp
        File file = new File("/var/data/" + fileName);
        FileInputStream fis = new FileInputStream(file);
        // Read and return file content
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userDir = request.getParameter("directory");
        // ruleid: java-path-traversal-exp
        Path path = Paths.get("/home/user/" + userDir);
        byte[] data = Files.readAllBytes(path);
        response.getOutputStream().write(data);
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String reportName = request.getParameter("report");
        // ruleid: java-path-traversal-exp
        FileReader reader = new FileReader("/var/reports/" + reportName);
        BufferedReader br = new BufferedReader(reader);
        String line;
        while ((line = br.readLine()) != null) {
            response.getWriter().println(line);
        }
        br.close();
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String template = request.getHeader("X-Template");
        // ruleid: java-path-traversal-exp
        FileInputStream templateFile = new FileInputStream("templates/" + template);
        byte[] content = new byte[templateFile.available()];
        templateFile.read(content);
        templateFile.close();
        response.getOutputStream().write(content);
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String configFile = request.getParameter("config");
        // ruleid: java-path-traversal-exp
        Properties props = new Properties();
        props.load(new FileInputStream("configs/" + configFile));
        // Use properties
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String logFile = request.getParameter("log");
        // ruleid: java-path-traversal-exp
        RandomAccessFile raf = new RandomAccessFile("/var/logs/" + logFile, "r");
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = raf.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        raf.close();
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String profilePic = request.getParameter("profile");
        // ruleid: java-path-traversal-exp
        File imageFile = new File("/var/www/images/" + profilePic);
        if (imageFile.exists()) {
            FileInputStream fis = new FileInputStream(imageFile);
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
            fis.close();
        }
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String theme = null;
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("theme")) {
                theme = cookie.getValue();
                break;
            }
        }
        if (theme != null) {
            // ruleid: java-path-traversal-exp
            File themeFile = new File("/var/www/themes/" + theme + "/style.css");
            FileInputStream fis = new FileInputStream(themeFile);
            // Read and return file content
        }
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        // ruleid: java-path-traversal-exp
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("/tmp/" + fileName))) {
            writer.write("User data");
        }
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String[]> params = request.getParameterMap();
        String module = params.get("module")[0];
        // ruleid: java-path-traversal-exp
        File moduleFile = new File("/var/modules/" + module + ".jar");
        FileInputStream fis = new FileInputStream(moduleFile);
        // Process the file
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String backupFile = request.getParameter("backup");
        // ruleid: java-path-traversal-exp
        Files.copy(Paths.get("/var/backups/" + backupFile), response.getOutputStream());
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String jspPage = request.getParameter("page");
        // ruleid: java-path-traversal-exp
        request.getRequestDispatcher("/WEB-INF/views/" + jspPage + ".jsp").forward(request, response);
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("user");
        // ruleid: java-path-traversal-exp
        File userProfile = new File(System.getProperty("user.home") + "/profiles/" + username);
        if (userProfile.exists()) {
            // Read user profile
            FileInputStream fis = new FileInputStream(userProfile);
            // Process file
        }
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String resourcePath = request.getParameter("resource");
        // ruleid: java-path-traversal-exp
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath);
        if (is != null) {
            byte[] buffer = new byte[is.available()];
            is.read(buffer);
            response.getOutputStream().write(buffer);
        }
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String relativePath = request.getParameter("path");
        File baseDir = new File("/var/www/data");
        // ruleid: java-path-traversal-exp
        File requestedFile = new File(baseDir, relativePath);
        if (requestedFile.exists() && requestedFile.isFile()) {
            FileInputStream fis = new FileInputStream(requestedFile);
            // Process file
        }
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        // Validate that the filename only contains allowed characters
        // ok: java-path-traversal-exp
        if (fileName.matches("[a-zA-Z0-9_-]+\\.txt")) {
            File file = new File("/var/data/" + fileName);
            FileInputStream fis = new FileInputStream(file);
            // Read and return file content
        }
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userDir = request.getParameter("directory");
        // Normalize and validate path
        // ok: java-path-traversal-exp
        Path normalizedPath = Paths.get("/home/user/").resolve(userDir).normalize();
        if (normalizedPath.startsWith("/home/user/")) {
            byte[] data = Files.readAllBytes(normalizedPath);
            response.getOutputStream().write(data);
        }
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String reportName = request.getParameter("report");
        // Use whitelist of allowed reports
        List<String> allowedReports = Arrays.asList("sales.txt", "inventory.txt", "users.txt");
        // ok: java-path-traversal-exp
        if (allowedReports.contains(reportName)) {
            FileReader reader = new FileReader("/var/reports/" + reportName);
            BufferedReader br = new BufferedReader(reader);
            String line;
            while ((line = br.readLine()) != null) {
                response.getWriter().println(line);
            }
            br.close();
        }
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String template = request.getHeader("X-Template");
        // Use FilenameUtils to get base name only
        // ok: java-path-traversal-exp
        String safeTemplate = FilenameUtils.getName(template);
        FileInputStream templateFile = new FileInputStream("templates/" + safeTemplate);
        byte[] content = new byte[templateFile.available()];
        templateFile.read(content);
        templateFile.close();
        response.getOutputStream().write(content);
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String configFile = request.getParameter("config");
        // ok: java-path-traversal-exp
        File file = new File("configs", configFile);
        String canonicalPath = file.getCanonicalPath();
        File configsDir = new File("configs").getCanonicalFile();
        if (canonicalPath.startsWith(configsDir.getPath())) {
            Properties props = new Properties();
            props.load(new FileInputStream(file));
            // Use properties
        }
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String logFile = request.getParameter("log");
        // Map input to predefined log files
        Map<String, String> logFileMap = new HashMap<>();
        logFileMap.put("system", "system.log");
        logFileMap.put("access", "access.log");
        logFileMap.put("error", "error.log");
        // ok: java-path-traversal-exp
        String actualLogFile = logFileMap.get(logFile);
        if (actualLogFile != null) {
            RandomAccessFile raf = new RandomAccessFile("/var/logs/" + actualLogFile, "r");
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = raf.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
            raf.close();
        }
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String profilePic = request.getParameter("profile");
        // Use ESAPI validator for input validation
        Validator validator = ESAPI.validator();
        // ok: java-path-traversal-exp
        String safePic = validator.getValidFileName("ProfilePicture", profilePic, false);
        File imageFile = new File("/var/www/images/" + safePic);
        if (imageFile.exists()) {
            FileInputStream fis = new FileInputStream(imageFile);
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
            fis.close();
        }
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String theme = null;
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("theme")) {
                theme = cookie.getValue();
                break;
            }
        }
        // Validate theme against whitelist
        Set<String> validThemes = new HashSet<>(Arrays.asList("light", "dark", "blue", "green"));
        // ok: java-path-traversal-exp
        if (theme != null && validThemes.contains(theme)) {
            File themeFile = new File("/var/www/themes/" + theme + "/style.css");
            FileInputStream fis = new FileInputStream(themeFile);
            // Read and return file content
        }
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        // Generate a safe filename using UUID
        // ok: java-path-traversal-exp
        String safeFileName = UUID.randomUUID().toString() + ".txt";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("/tmp/" + safeFileName))) {
            writer.write("User data");
        }
        // Store mapping of user's filename to safe filename if needed
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String[]> params = request.getParameterMap();
        String module = params.get("module")[0];
        // Use a map to validate and translate module names
        Map<String, String> moduleMap = new HashMap<>();
        moduleMap.put("auth", "auth.jar");
        moduleMap.put("users", "users.jar");
        moduleMap.put("admin", "admin.jar");
        // ok: java-path-traversal-exp
        String moduleFile = moduleMap.get(module);
        if (moduleFile != null) {
            FileInputStream fis = new FileInputStream("/var/modules/" + moduleFile);
            // Process the file
        }
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String backupFile = request.getParameter("backup");
        // Validate file extension and characters
        // ok: java-path-traversal-exp
        if (backupFile.matches("[a-zA-Z0-9_-]+\\.bak")) {
            Path path = Paths.get("/var/backups/", backupFile);
            if (Files.exists(path) && !Files.isDirectory(path)) {
                Files.copy(path, response.getOutputStream());
            }
        }
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String jspPage = request.getParameter("page");
        // Map input to allowed pages
        Map<String, String> pageMap = new HashMap<>();
        pageMap.put("home", "home");
        pageMap.put("about", "about");
        pageMap.put("contact", "contact");
        // ok: java-path-traversal-exp
        String safePage = pageMap.get(jspPage);
        if (safePage != null) {
            request.getRequestDispatcher("/WEB-INF/views/" + safePage + ".jsp").forward(request, response);
        } else {
            // Default page
            request.getRequestDispatcher("/WEB-INF/views/home.jsp").forward(request, response);
        }
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("user");
        // Sanitize username to prevent path traversal
        // ok: java-path-traversal-exp
        String safeUsername = username.replaceAll("[^a-zA-Z0-9]", "");
        File userProfile = new File(System.getProperty("user.home") + "/profiles/" + safeUsername);
        if (userProfile.exists()) {
            // Read user profile
            FileInputStream fis = new FileInputStream(userProfile);
            // Process file
        }
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String resourcePath = request.getParameter("resource");
        // Restrict to specific directory with whitelist
        List<String> allowedResources = Arrays.asList(
            "templates/header.html", 
            "templates/footer.html", 
            "templates/sidebar.html"
        );
        // ok: java-path-traversal-exp
        if (allowedResources.contains(resourcePath)) {
            InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath);
            if (is != null) {
                byte[] buffer = new byte[is.available()];
                is.read(buffer);
                response.getOutputStream().write(buffer);
            }
        }
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String relativePath = request.getParameter("path");
        File baseDir = new File("/var/www/data").getCanonicalFile();
        // ok: java-path-traversal-exp
        File requestedFile = new File(baseDir, relativePath).getCanonicalFile();
        if (requestedFile.getPath().startsWith(baseDir.getPath()) && 
            requestedFile.exists() && 
            requestedFile.isFile()) {
            FileInputStream fis = new FileInputStream(requestedFile);
            // Process file
        }
    }
}
// {/fact}