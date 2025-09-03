import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.apache.commons.lang3.StringEscapeUtils;
import org.owasp.encoder.Encode;

public class OSCommandInjectionExamples {

    // True Positive Examples (Vulnerable Code)

    @WebServlet("/bad1")
    public static class BadCase1 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String fileName = request.getParameter("fileName");
            
            try {
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec("cat " + fileName);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad2")
    public static class BadCase2 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String ipAddress = request.getParameter("ipAddress");
            
            try {
                String command = "ping -c 4 " + ipAddress;
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(command);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad3")
    public static class BadCase3 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String username = request.getParameter("username");
            
            try {
                String[] command = {"sh", "-c", "ls -la /home/" + username};
                // ruleid: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder(command);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad4")
    public static class BadCase4 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String directory = request.getParameter("dir");
            String filename = request.getParameter("file");
            
            try {
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(new String[]{"find", directory, "-name", filename});
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad5")
    public static class BadCase5 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String host = request.getParameter("host");
            
            try {
                // Concatenating commands with user input
                String command = "nslookup " + host + " | grep Address";
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad6")
    public static class BadCase6 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String scriptName = request.getParameter("script");
            String args = request.getParameter("args");
            
            try {
                // ruleid: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("python", scriptName, args);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad7")
    public static class BadCase7 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String command = request.getHeader("X-Command");
            
            try {
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(command);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad8")
    public static class BadCase8 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String filename = request.getParameter("filename");
            String option = request.getParameter("option");
            
            try {
                List<String> commands = new ArrayList<>();
                commands.add("grep");
                commands.add(option);
                commands.add("pattern");
                commands.add(filename);
                
                // ruleid: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder(commands);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad9")
    public static class BadCase9 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userId = request.getParameter("userId");
            
            try {
                String[] command = {"sh", "-c", "id " + userId};
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(command);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad10")
    public static class BadCase10 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String path = request.getParameter("path");
            String option = request.getParameter("option");
            
            try {
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec("ls " + option + " " + path);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad11")
    public static class BadCase11 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String domain = request.getParameter("domain");
            
            try {
                // Some basic transformation but still vulnerable
                domain = domain.trim().toLowerCase();
                String command = "dig +short " + domain;
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad12")
    public static class BadCase12 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String filename = request.getParameter("filename");
            
            try {
                // Attempt to restrict but still vulnerable
                if (filename.contains("..")) {
                    response.getWriter().println("Invalid filename");
                    return;
                }
                
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec("cat /var/www/" + filename);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad13")
    public static class BadCase13 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String searchTerm = request.getParameter("search");
            String filename = request.getParameter("file");
            
            try {
                // ruleid: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("grep", searchTerm, "/var/log/" + filename);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad14")
    public static class BadCase14 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String server = request.getParameter("server");
            
            try {
                // Indirect command injection through string concatenation
                String command = String.format("ssh %s 'uptime'", server);
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad15")
    public static class BadCase15 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String packageName = request.getParameter("package");
            
            try {
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec("dpkg -l | grep " + packageName);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    // True Negative Examples (Safe Code)

    @WebServlet("/good1")
    public static class GoodCase1 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String fileName = request.getParameter("fileName");
            
            // Validate input against a whitelist
            if (!fileName.matches("^[a-zA-Z0-9_.-]+$")) {
                response.getWriter().println("Invalid filename");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("cat", fileName);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good2")
    public static class GoodCase2 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String ipAddress = request.getParameter("ipAddress");
            
            // Validate IP address format
            if (!ipAddress.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
                response.getWriter().println("Invalid IP address");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", ipAddress);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good3")
    public static class GoodCase3 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String username = request.getParameter("username");
            
            // Validate username
            if (!username.matches("^[a-zA-Z0-9_]+$")) {
                response.getWriter().println("Invalid username");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("ls", "-la", "/home/" + username);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good4")
    public static class GoodCase4 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String directory = request.getParameter("dir");
            String filename = request.getParameter("file");
            
            // Validate inputs
            if (!directory.matches("^[a-zA-Z0-9_/.-]+$") || !filename.matches("^[a-zA-Z0-9_.-]+$")) {
                response.getWriter().println("Invalid input");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                List<String> command = new ArrayList<>();
                command.add("find");
                command.add(directory);
                command.add("-name");
                command.add(filename);
                
                ProcessBuilder pb = new ProcessBuilder(command);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good5")
    public static class GoodCase5 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String host = request.getParameter("host");
            
            // Validate hostname format
            if (!host.matches("^[a-zA-Z0-9.-]+$")) {
                response.getWriter().println("Invalid hostname");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("nslookup", host);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good6")
    public static class GoodCase6 extends HttpServlet {
        private static final List<String> ALLOWED_SCRIPTS = Arrays.asList("script1.py", "script2.py", "script3.py");
        
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String scriptName = request.getParameter("script");
            String args = request.getParameter("args");
            
            // Validate script name against whitelist
            if (!ALLOWED_SCRIPTS.contains(scriptName)) {
                response.getWriter().println("Invalid script");
                return;
            }
            
            // Validate arguments
            if (!args.matches("^[a-zA-Z0-9_.-]+$")) {
                response.getWriter().println("Invalid arguments");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("python", scriptName, args);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good7")
    public static class GoodCase7 extends HttpServlet {
        private static final List<String> ALLOWED_COMMANDS = Arrays.asList("uptime", "date", "hostname");
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String command = request.getHeader("X-Command");
            
            // Validate command against whitelist
            if (!ALLOWED_COMMANDS.contains(command)) {
                response.getWriter().println("Invalid command");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(command);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good8")
    public static class GoodCase8 extends HttpServlet {
        private static final List<String> ALLOWED_OPTIONS = Arrays.asList("-i", "-v", "-n");
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String filename = request.getParameter("filename");
            String option = request.getParameter("option");
            
            // Validate filename
            if (!filename.matches("^[a-zA-Z0-9_.-]+$")) {
                response.getWriter().println("Invalid filename");
                return;
            }
            
            // Validate option against whitelist
            if (!ALLOWED_OPTIONS.contains(option)) {
                response.getWriter().println("Invalid option");
                return;
            }
            
            try {
                List<String> commands = new ArrayList<>();
                commands.add("grep");
                commands.add(option);
                commands.add("pattern");
                commands.add(filename);
                
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder(commands);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good9")
    public static class GoodCase9 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userId = request.getParameter("userId");
            
            // Validate userId
            if (!userId.matches("^[a-zA-Z0-9_]+$")) {
                response.getWriter().println("Invalid user ID");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("id", userId);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good10")
    public static class GoodCase10 extends HttpServlet {
        private static final List<String> ALLOWED_OPTIONS = Arrays.asList("-l", "-a", "-h");
        private static final List<String> ALLOWED_PATHS = Arrays.asList("/var/log", "/tmp", "/home/user");
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String path = request.getParameter("path");
            String option = request.getParameter("option");
            
            // Validate path against whitelist
            if (!ALLOWED_PATHS.contains(path)) {
                response.getWriter().println("Invalid path");
                return;
            }
            
            // Validate option against whitelist
            if (!ALLOWED_OPTIONS.contains(option)) {
                response.getWriter().println("Invalid option");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("ls", option, path);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good11")
    public static class GoodCase11 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String domain = request.getParameter("domain");
            
            // Validate domain format
            Pattern pattern = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*\\.[a-zA-Z]{2,}$");
            Matcher matcher = pattern.matcher(domain);
            
            if (!matcher.matches()) {
                response.getWriter().println("Invalid domain name");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("dig", "+short", domain);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good12")
    public static class GoodCase12 extends HttpServlet {
        private static final List<String> ALLOWED_FILES = Arrays.asList("access.log", "error.log", "system.log");
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String filename = request.getParameter("filename");
            
            // Validate filename against whitelist
            if (!ALLOWED_FILES.contains(filename)) {
                response.getWriter().println("Invalid filename");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("cat", "/var/www/" + filename);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good13")
    public static class GoodCase13 extends HttpServlet {
        private static final List<String> ALLOWED_FILES = Arrays.asList("apache.log", "mysql.log", "system.log");
        
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String searchTerm = request.getParameter("search");
            String filename = request.getParameter("file");
            
            // Validate filename against whitelist
            if (!ALLOWED_FILES.contains(filename)) {
                response.getWriter().println("Invalid filename");
                return;
            }
            
            // Validate search term
            if (!searchTerm.matches("^[a-zA-Z0-9_.-]+$")) {
                response.getWriter().println("Invalid search term");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("grep", searchTerm, "/var/log/" + filename);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good14")
    public static class GoodCase14 extends HttpServlet {
        private static final List<String> ALLOWED_SERVERS = Arrays.asList("server1", "server2", "server3");
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String server = request.getParameter("server");
            
            // Validate server against whitelist
            if (!ALLOWED_SERVERS.contains(server)) {
                response.getWriter().println("Invalid server");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("ssh", server, "uptime");
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good15")
    public static class GoodCase15 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String packageName = request.getParameter("package");
            
            // Validate package name
            if (!packageName.matches("^[a-zA-Z0-9_.-]+$")) {
                response.getWriter().println("Invalid package name");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                ProcessBuilder pb = new ProcessBuilder("dpkg", "-l");
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                StringBuilder output = new StringBuilder();
                
                while ((line = reader.readLine()) != null) {
                    if (line.contains(packageName)) {
                        output.append(line).append("\n");
                    }
                }
                
                response.getWriter().println(output.toString());
            } catch (IOException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }
}