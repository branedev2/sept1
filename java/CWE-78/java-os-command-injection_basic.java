import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.PrintWriter;
import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.apache.commons.lang3.StringUtils;
import org.owasp.encoder.Encode;

public class CommandInjectionExamples {

    // True Positives (Vulnerable Code)

// {fact rule=os-command-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("command");
        
        // ruleid: java-os-command-injection
        Process process = Runtime.getRuntime().exec("ls " + userInput);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        PrintWriter out = response.getWriter();
        while ((line = reader.readLine()) != null) {
            out.println(line);
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("filename");
        
        String[] command = {"cat", filename};
        // ruleid: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("host");
        
        // ruleid: java-os-command-injection
        Process process = Runtime.getRuntime().exec(new String[]{"ping", "-c", "4", host});
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String directory = request.getParameter("dir");
        String command = "ls -la " + directory;
        
        // ruleid: java-os-command-injection
        Process process = Runtime.getRuntime().exec(command);
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            PrintWriter out = response.getWriter();
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        List<String> commands = new ArrayList<>();
        commands.add("sh");
        commands.add("-c");
        commands.add("grep " + username + " /etc/passwd");
        
        // ruleid: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder(commands);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchTerm = request.getParameter("search");
        String filePath = request.getParameter("path");
        
        // ruleid: java-os-command-injection
        Process process = Runtime.getRuntime().exec("grep -r \"" + searchTerm + "\" " + filePath);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String ipAddress = request.getHeader("X-Forwarded-For");
        
        // ruleid: java-os-command-injection
        Process process = Runtime.getRuntime().exec("nslookup " + ipAddress);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        String logFile = "/tmp/user_agents.log";
        
        // ruleid: java-os-command-injection
        Runtime.getRuntime().exec("echo \"" + userAgent + "\" >> " + logFile);
        
        response.getWriter().println("User agent logged");
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        String option = request.getParameter("option");
        
        ProcessBuilder pb = new ProcessBuilder();
        pb.command("sh", "-c", "cat " + fileName + " | grep " + option);
        
        // ruleid: java-os-command-injection
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String command = request.getParameter("cmd");
        if (command != null && !command.isEmpty()) {
            // ruleid: java-os-command-injection
            Process process = new ProcessBuilder("bash", "-c", command).start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
        }
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String script = request.getParameter("script");
        String[] command = {"/bin/bash", "-c", script};
        
        // ruleid: java-os-command-injection
        Process process = Runtime.getRuntime().exec(command);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getParameter("id");
        String[] command = new String[3];
        command[0] = "sh";
        command[1] = "-c";
        command[2] = "id " + userId;
        
        // ruleid: java-os-command-injection
        Process process = Runtime.getRuntime().exec(command);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String path = request.getParameter("path");
        List<String> commandList = new ArrayList<>();
        commandList.add("find");
        commandList.add(path);
        commandList.add("-type");
        commandList.add("f");
        commandList.add("-name");
        commandList.add("*.txt");
        
        // ruleid: java-os-command-injection
        Process process = new ProcessBuilder(commandList).start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cookie = request.getHeader("Cookie");
        if (cookie != null && cookie.contains("debug=")) {
            String debugCommand = cookie.substring(cookie.indexOf("debug=") + 6);
            if (debugCommand.contains(";")) {
                debugCommand = debugCommand.substring(0, debugCommand.indexOf(";"));
            }
            
            // ruleid: java-os-command-injection
            Process process = Runtime.getRuntime().exec(debugCommand);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
        }
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("filename");
        String format = request.getParameter("format");
        
        String command = String.format("convert %s %s", filename, format);
        
        // ruleid: java-os-command-injection
        Process process = Runtime.getRuntime().exec(command);
        
        int exitCode = process.waitFor();
        response.getWriter().println("Conversion " + (exitCode == 0 ? "successful" : "failed"));
    }

    // True Negatives (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("command");
        
        // Validate input against a whitelist
        if (!Pattern.matches("[a-zA-Z0-9_-]+", userInput)) {
            response.getWriter().println("Invalid input");
            return;
        }
        
        // ok: java-os-command-injection
        Process process = Runtime.getRuntime().exec("ls " + userInput);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        PrintWriter out = response.getWriter();
        while ((line = reader.readLine()) != null) {
            out.println(line);
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("filename");
        
        // Use a fixed command and pass arguments as separate array elements
        // ok: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder("cat");
        pb.command().add(filename);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("host");
        
        // Validate IP address format
        if (!isValidIpAddress(host)) {
            response.getWriter().println("Invalid IP address");
            return;
        }
        
        // ok: java-os-command-injection
        Process process = Runtime.getRuntime().exec(new String[]{"ping", "-c", "4", host});
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String directory = request.getParameter("dir");
        
        // Use Java's built-in file operations instead of executing OS commands
        // ok: java-os-command-injection
        Files.list(Paths.get(directory))
            .forEach(path -> {
                try {
                    response.getWriter().println(path.toString());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        
        // Use a whitelist of allowed characters
        if (!username.matches("^[a-zA-Z0-9_]+$")) {
            response.getWriter().println("Invalid username format");
            return;
        }
        
        List<String> commands = new ArrayList<>();
        commands.add("grep");
        commands.add(username);
        commands.add("/etc/passwd");
        
        // ok: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder(commands);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchTerm = request.getParameter("search");
        String filePath = request.getParameter("path");
        
        // Use ProcessBuilder with arguments as separate list items
        List<String> command = new ArrayList<>();
        command.add("grep");
        command.add("-r");
        command.add(searchTerm);
        command.add(filePath);
        
        // ok: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String ipAddress = request.getHeader("X-Forwarded-For");
        
        // Validate IP address format
        if (!ipAddress.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            response.getWriter().println("Invalid IP address format");
            return;
        }
        
        // ok: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder("nslookup", ipAddress);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        String logFile = "/tmp/user_agents.log";
        
        // Use Java's file operations instead of OS commands
        // ok: java-os-command-injection
        Files.write(Paths.get(logFile), (userAgent + "\n").getBytes(), 
                    java.nio.file.StandardOpenOption.CREATE, 
                    java.nio.file.StandardOpenOption.APPEND);
        
        response.getWriter().println("User agent logged");
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        String option = request.getParameter("option");
        
        // Read file using Java APIs and filter in Java code
        // ok: java-os-command-injection
        List<String> lines = Files.readAllLines(Paths.get(fileName));
        List<String> filteredLines = lines.stream()
            .filter(line -> line.contains(option))
            .collect(Collectors.toList());
        
        for (String line : filteredLines) {
            response.getWriter().println(line);
        }
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String command = request.getParameter("cmd");
        
        // Use a whitelist of allowed commands
        List<String> allowedCommands = Arrays.asList("date", "uptime", "whoami");
        
        if (allowedCommands.contains(command)) {
            // ok: java-os-command-injection
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
        } else {
            response.getWriter().println("Command not allowed");
        }
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Use predefined commands instead of user input
        String action = request.getParameter("action");
        String command = null;
        
        switch (action) {
            case "list_users":
                command = "cat /etc/passwd";
                break;
            case "disk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY":
                command = "df -h";
                break;
            case "memory_usage":
                command = "free -m";
                break;
            default:
                response.getWriter().println("Invalid action");
                return;
        }
        
        // ok: java-os-command-injection
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getParameter("id");
        
        // Validate input is numeric
        if (!userId.matches("\\d+")) {
            response.getWriter().println("Invalid user ID");
            return;
        }
        
        // ok: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder("id", userId);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String path = request.getParameter("path");
        
        // Validate path is safe
        if (!isValidPath(path)) {
            response.getWriter().println("Invalid path");
            return;
        }
        
        // ok: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder();
        pb.command("find", path, "-type", "f", "-name", "*.txt");
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cookie = request.getHeader("Cookie");
        if (cookie != null && cookie.contains("debug=")) {
            String debugCommand = cookie.substring(cookie.indexOf("debug=") + 6);
            if (debugCommand.contains(";")) {
                debugCommand = debugCommand.substring(0, debugCommand.indexOf(";"));
            }
            
            // Use a whitelist of allowed debug commands
            Map<String, String[]> allowedCommands = new HashMap<>();
            allowedCommands.put("system_info", new String[]{"uname", "-a"});
            allowedCommands.put("disk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY", new String[]{"df", "-h"});
            allowedCommands.put("memory_info", new String[]{"free", "-m"});
            
            if (allowedCommands.containsKey(debugCommand)) {
                // ok: java-os-command-injection
                Process process = Runtime.getRuntime().exec(allowedCommands.get(debugCommand));
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                response.getWriter().println(reader.lines().collect(Collectors.joining("\n")));
            } else {
                response.getWriter().println("Unknown debug command");
            }
        }
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("filename");
        String format = request.getParameter("format");
        
        // Validate input parameters
        if (!isValidFilename(filename) || !isValidFormat(format)) {
            response.getWriter().println("Invalid input parameters");
            return;
        }
        
        // ok: java-os-command-injection
        ProcessBuilder pb = new ProcessBuilder("convert", filename, format);
        Process process = pb.start();
        
        int exitCode = process.waitFor();
        response.getWriter().println("Conversion " + (exitCode == 0 ? "successful" : "failed"));
    }

    // Helper methods
    private boolean isValidIpAddress(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidPath(String path) {
        // Basic path validation - should be more comprehensive in real code
        if (path == null || path.isEmpty()) {
            return false;
        }
        if (path.contains("..") || path.contains(";") || path.contains("|") || 
            path.contains("&") || path.contains(">") || path.contains("<")) {
            return false;
        }
        return true;
    }

    private boolean isValidFilename(String filename) {
        // Basic filename validation
        return filename != null && filename.matches("^[a-zA-Z0-9_.-]+$");
    }

    private boolean isValidFormat(String format) {
        // Whitelist of allowed formats
        List<String> allowedFormats = Arrays.asList("jpg", "png", "gif", "bmp", "tiff");
        return format != null && allowedFormats.contains(format.toLowerCase());
    }
}
// {/fact}