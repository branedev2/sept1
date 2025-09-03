import java.io.*;
import java.util.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.exec.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.Context;
import spark.*;
import com.sun.net.httpserver.*;
import org.apache.commons.io.IOUtils;
import java.nio.charset.StandardCharsets;
import org.apache.commons.lang3.StringUtils;
import org.owasp.encoder.Encode;
import org.apache.commons.validator.routines.UrlValidator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.apache.commons.text.StringEscapeUtils;
import com.google.common.net.UrlEscapers;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import java.util.concurrent.TimeUnit;
import org.apache.commons.exec.util.StringUtils;
import java.util.stream.Collectors;
import org.apache.commons.collections4.ListUtils;

// Security Issue: OS Command Injection - Passing user-provided input to operating system command functions without validation or sanitization

// True Positive Examples (Vulnerable/Insecure Code)

@Controller
class bad_case_1 {
    @RequestMapping("/execute")
    public String executeCommand(HttpServletRequest request) {
        try {
            String command = request.getParameter("cmd");
            // ruleid: java-os-command-injection
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}

@RestController
class bad_case_2 {
    @GetMapping("/ping")
    public String pingHost(HttpServletRequest request) {
        try {
            String host = request.getParameter("host");
            String[] command = {"ping", "-c", "4", host};
            // ruleid: java-os-command-injection
            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return reader.lines().collect(Collectors.joining("\n"));
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class bad_case_3 implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String command = "";
        if (query != null) {
            String[] params = query.split("&");
            for (String param : params) {
                if (param.startsWith("cmd=")) {
                    command = param.substring(4);
                    break;
                }
            }
        }
        
        try {
            CommandLine cmdLine = CommandLine.parse("cmd.exe /c " + command);
            DefaultExecutor executor = new DefaultExecutor();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
            executor.setStreamHandler(streamHandler);
            // ruleid: java-os-command-injection
            executor.execute(cmdLine);
            
            String response = outputStream.toString();
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        } catch (Exception e) {
            String response = "Error: " + e.getMessage();
            exchange.sendResponseHeaders(500, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}

class bad_case_4 extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String command = request.getParameter("command");
        try {
            String[] envp = {"PATH=/usr/local/bin:/usr/bin:/bin"};
            File dir = new File("/tmp");
            // ruleid: java-os-command-injection
            Process process = Runtime.getRuntime().exec(command, envp, dir);
            
            InputStream is = process.getInputStream();
            String output = IOUtils.toString(is, StandardCharsets.UTF_8);
            
            response.setContentType("text/plain");
            response.getWriter().write(output);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
}

class bad_case_5 {
    public String handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        Map<String, String> headers = event.getHeaders();
        String command = headers.get("X-Command");
        
        try {
            // ruleid: java-os-command-injection
            Process process = new ProcessBuilder("/bin/sh", "-c", command).start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class bad_case_6 {
    public static void main(String[] args) {
        Spark.post("/execute", (req, res) -> {
            String command = req.queryParams("cmd");
            try {
                // ruleid: java-os-command-injection
                Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return output.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
    }
}

@RestController
class bad_case_7 {
    @PostMapping("/system-info")
    public String getSystemInfo(HttpServletRequest request) {
        String command = request.getHeader("X-Command-To-Run");
        try {
            CommandLine cmdLine = CommandLine.parse(command);
            DefaultExecutor executor = new DefaultExecutor();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
            executor.setStreamHandler(streamHandler);
            // ruleid: java-os-command-injection
            int exitValue = executor.execute(cmdLine);
            
            return "Command executed with exit code: " + exitValue + "\nOutput: " + outputStream.toString();
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}

class bad_case_8 extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String scriptName = request.getParameter("script");
        String param = request.getParameter("param");
        
        try {
            // ruleid: java-os-command-injection
            Process process = Runtime.getRuntime().exec("python " + scriptName + " " + param);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            response.setContentType("text/plain");
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
}

class bad_case_9 {
    public void handleHttpRequest(HttpExchange exchange) throws IOException {
        String requestBody = IOUtils.toString(exchange.getRequestBody(), StandardCharsets.UTF_8);
        Map<String, String> params = parseRequestBody(requestBody);
        String command = params.get("command");
        
        try {
            // ruleid: java-os-command-injection
            Process process = new ProcessBuilder().command("sh", "-c", command).start();
            
            int exitCode = process.waitFor();
            String output = IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
            
            exchange.sendResponseHeaders(200, output.length());
            OutputStream os = exchange.getResponseBody();
            os.write(output.getBytes());
            os.close();
        } catch (Exception e) {
            String response = "Error: " + e.getMessage();
            exchange.sendResponseHeaders(500, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
    
    private Map<String, String> parseRequestBody(String body) {
        Map<String, String> result = new HashMap<>();
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                result.put(keyValue[0], keyValue[1]);
            }
        }
        return result;
    }
}

class bad_case_10 {
    public void executeCommand(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        String target = request.getParameter("target");
        
        try {
            String command = action + " " + target;
            // ruleid: java-os-command-injection
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            response.setContentType("text/plain");
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
}

@RestController
class bad_case_11 {
    @GetMapping("/network-tool")
    public String runNetworkTool(@RequestParam String tool, @RequestParam String host) {
        try {
            String command = tool + " " + host;
            // ruleid: java-os-command-injection
            Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
            
            process.waitFor(10, TimeUnit.SECONDS);
            InputStream is = process.getInputStream();
            String output = IOUtils.toString(is, StandardCharsets.UTF_8);
            
            return output;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class bad_case_12 {
    public String handleLambdaRequest(APIGatewayProxyRequestEvent event, Context context) {
        Map<String, String> queryParams = event.getQueryStringParameters();
        if (queryParams == null) {
            return "No parameters provided";
        }
        
        String command = queryParams.get("cmd");
        try {
            CommandLine cmdLine = CommandLine.parse(command);
            DefaultExecutor executor = new DefaultExecutor();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
            executor.setStreamHandler(streamHandler);
            // ruleid: java-os-command-injection
            executor.execute(cmdLine);
            
            return outputStream.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class bad_case_13 extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String jsonBody = IOUtils.toString(request.getReader());
        // Assume we have a simple JSON parser
        String command = extractCommandFromJson(jsonBody);
        
        try {
            // ruleid: java-os-command-injection
            Process process = new ProcessBuilder().command("cmd.exe", "/c", command).start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            response.setContentType("text/plain");
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    private String extractCommandFromJson(String json) {
        // Simple extraction, in real code would use a proper JSON parser
        if (json.contains("\"command\":")) {
            int start = json.indexOf("\"command\":") + 11;
            int end = json.indexOf("\"", start);
            return json.substring(start, end);
        }
        return "";
    }
}

class bad_case_14 {
    public void handleSparkRequest() {
        Spark.post("/run-script", (req, res) -> {
            String script = req.queryParams("script");
            String args = req.queryParams("args");
            
            try {
                String command = "python " + script + " " + args;
                // ruleid: java-os-command-injection
                Process process = Runtime.getRuntime().exec(command);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                
                return output.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
    }
}

class bad_case_15 {
    public String handleHttpRequest(HttpServletRequest request) {
        try {
            String host = request.getParameter("host");
            String[] command = {"/bin/sh", "-c", "nslookup " + host};
            // ruleid: java-os-command-injection
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// True Negative Examples (Safe/Secure Code)

@Controller
class good_case_1 {
    private static final List<String> ALLOWED_COMMANDS = Arrays.asList("ls", "dir", "echo", "date");
    
    @RequestMapping("/execute-safe")
    public String executeCommand(HttpServletRequest request) {
        try {
            String command = request.getParameter("cmd");
            
            // Validate command against whitelist
            if (!ALLOWED_COMMANDS.contains(command)) {
                return "Command not allowed";
            }
            
            // ok: java-os-command-injection
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}

@RestController
class good_case_2 {
    private static final Pattern VALID_HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$");
    
    @GetMapping("/ping-safe")
    public String pingHost(HttpServletRequest request) {
        try {
            String host = request.getParameter("host");
            
            // Validate host with regex
            if (!VALID_HOST_PATTERN.matcher(host).matches()) {
                return "Invalid hostname";
            }
            
            List<String> command = new ArrayList<>();
            command.add("ping");
            command.add("-c");
            command.add("4");
            command.add(host);
            
            // ok: java-os-command-injection
            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return reader.lines().collect(Collectors.joining("\n"));
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class good_case_3 implements HttpHandler {
    private static final List<String> ALLOWED_COMMANDS = Arrays.asList("echo", "date", "whoami", "hostname");
    
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String command = "";
        if (query != null) {
            String[] params = query.split("&");
            for (String param : params) {
                if (param.startsWith("cmd=")) {
                    command = param.substring(4);
                    break;
                }
            }
        }
        
        try {
            // Validate command
            if (!ALLOWED_COMMANDS.contains(command)) {
                String response = "Command not allowed";
                exchange.sendResponseHeaders(403, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
                return;
            }
            
            CommandLine cmdLine = CommandLine.parse(command);
            DefaultExecutor executor = new DefaultExecutor();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
            executor.setStreamHandler(streamHandler);
            
            // ok: java-os-command-injection
            executor.execute(cmdLine);
            
            String response = outputStream.toString();
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        } catch (Exception e) {
            String response = "Error: " + e.getMessage();
            exchange.sendResponseHeaders(500, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}

class good_case_4 extends HttpServlet {
    private static final Map<String, String[]> COMMAND_MAP = new HashMap<>();
    
    static {
        COMMAND_MAP.put("list", new String[]{"ls", "-la"});
        COMMAND_MAP.put("date", new String[]{"date"});
        COMMAND_MAP.put("whoami", new String[]{"whoami"});
        COMMAND_MAP.put("disk", new String[]{"df", "-h"});
    }
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String commandKey = request.getParameter("command");
        
        if (!COMMAND_MAP.containsKey(commandKey)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid command key");
            return;
        }
        
        try {
            String[] envp = {"PATH=/usr/local/bin:/usr/bin:/bin"};
            File dir = new File("/tmp");
            
            // ok: java-os-command-injection
            Process process = Runtime.getRuntime().exec(COMMAND_MAP.get(commandKey), envp, dir);
            
            InputStream is = process.getInputStream();
            String output = IOUtils.toString(is, StandardCharsets.UTF_8);
            
            response.setContentType("text/plain");
            response.getWriter().write(output);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
}

class good_case_5 {
    private static final Map<String, String> ALLOWED_COMMANDS = new HashMap<>();
    
    static {
        ALLOWED_COMMANDS.put("uptime", "uptime");
        ALLOWED_COMMANDS.put("memory", "free -m");
        ALLOWED_COMMANDS.put("disk", "df -h");
        ALLOWED_COMMANDS.put("network", "netstat -tuln");
    }
    
    public String handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        Map<String, String> headers = event.getHeaders();
        String commandKey = headers.get("X-Command");
        
        if (!ALLOWED_COMMANDS.containsKey(commandKey)) {
            return "Command not allowed";
        }
        
        try {
            // ok: java-os-command-injection
            Process process = new ProcessBuilder("/bin/sh", "-c", ALLOWED_COMMANDS.get(commandKey)).start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class good_case_6 {
    private static final Map<String, String[]> COMMAND_MAP = new HashMap<>();
    
    static {
        COMMAND_MAP.put("list", new String[]{"ls", "-la"});
        COMMAND_MAP.put("date", new String[]{"date"});
        COMMAND_MAP.put("whoami", new String[]{"whoami"});
    }
    
    public static void main(String[] args) {
        Spark.post("/execute-safe", (req, res) -> {
            String commandKey = req.queryParams("cmd");
            
            if (!COMMAND_MAP.containsKey(commandKey)) {
                return "Command not allowed";
            }
            
            try {
                // ok: java-os-command-injection
                Process process = Runtime.getRuntime().exec(COMMAND_MAP.get(commandKey));
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return output.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
    }
}

@RestController
class good_case_7 {
    private static final Map<String, CommandLine> ALLOWED_COMMANDS = new HashMap<>();
    
    static {
        ALLOWED_COMMANDS.put("system-info", CommandLine.parse("systeminfo"));
        ALLOWED_COMMANDS.put("network-info", CommandLine.parse("ipconfig /all"));
        ALLOWED_COMMANDS.put("disk-info", CommandLine.parse("wmic logicaldisk get caption,description,providername"));
    }
    
    @PostMapping("/system-info-safe")
    public String getSystemInfo(HttpServletRequest request) {
        String commandKey = request.getHeader("X-Command-Key");
        
        if (!ALLOWED_COMMANDS.containsKey(commandKey)) {
            return "Command not allowed";
        }
        
        try {
            CommandLine cmdLine = ALLOWED_COMMANDS.get(commandKey);
            DefaultExecutor executor = new DefaultExecutor();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
            executor.setStreamHandler(streamHandler);
            
            // ok: java-os-command-injection
            int exitValue = executor.execute(cmdLine);
            
            return "Command executed with exit code: " + exitValue + "\nOutput: " + outputStream.toString();
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}

class good_case_8 extends HttpServlet {
    private static final Map<String, String> SCRIPT_MAP = new HashMap<>();
    
    static {
        SCRIPT_MAP.put("backup", "backup.py");
        SCRIPT_MAP.put("report", "generate_report.py");
        SCRIPT_MAP.put("cleanup", "cleanup.py");
    }
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String scriptKey = request.getParameter("script");
        String param = request.getParameter("param");
        
        // Validate script key
        if (!SCRIPT_MAP.containsKey(scriptKey)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid script key");
            return;
        }
        
        // Validate param with regex
        if (!param.matches("^[a-zA-Z0-9_-]+$")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid parameter format");
            return;
        }
        
        try {
            List<String> command = new ArrayList<>();
            command.add("python");
            command.add(SCRIPT_MAP.get(scriptKey));
            command.add(param);
            
            // ok: java-os-command-injection
            Process process = new ProcessBuilder(command).start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            response.setContentType("text/plain");
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
}

class good_case_9 {
    private static final List<String> ALLOWED_COMMANDS = Arrays.asList("date", "uptime", "hostname", "whoami");
    
    public void handleHttpRequest(HttpExchange exchange) throws IOException {
        String requestBody = IOUtils.toString(exchange.getRequestBody(), StandardCharsets.UTF_8);
        Map<String, String> params = parseRequestBody(requestBody);
        String command = params.get("command");
        
        if (!ALLOWED_COMMANDS.contains(command)) {
            String response = "Command not allowed";
            exchange.sendResponseHeaders(403, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
            return;
        }
        
        try {
            // ok: java-os-command-injection
            Process process = new ProcessBuilder().command("sh", "-c", command).start();
            
            int exitCode = process.waitFor();
            String output = IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
            
            exchange.sendResponseHeaders(200, output.length());
            OutputStream os = exchange.getResponseBody();
            os.write(output.getBytes());
            os.close();
        } catch (Exception e) {
            String response = "Error: " + e.getMessage();
            exchange.sendResponseHeaders(500, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
    
    private Map<String, String> parseRequestBody(String body) {
        Map<String, String> result = new HashMap<>();
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                result.put(keyValue[0], keyValue[1]);
            }
        }
        return result;
    }
}

class good_case_10 {
    private static final Map<String, String> AC_REDACTED_TWILIO_ID_MAP = new HashMap<>();
    
    static {
        AC_REDACTED_TWILIO_ID_MAP.put("list", "ls");
        AC_REDACTED_TWILIO_ID_MAP.put("find", "find");
        AC_REDACTED_TWILIO_ID_MAP.put("count", "wc -l");
    }
    
    public void executeCommand(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        String target = request.getParameter("target");
        
        // Validate action
        if (!AC_REDACTED_TWILIO_ID_MAP.containsKey(action)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid action");
            return;
        }
        
        // Validate target path
        if (!target.matches("^[a-zA-Z0-9_\\-./]+$") || target.contains("..")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid target path");
            return;
        }
        
        try {
            String command = AC_REDACTED_TWILIO_ID_MAP.get(action) + " " + target;
            // ok: java-os-command-injection
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            response.setContentType("text/plain");
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
}

@RestController
class good_case_11 {
    private static final Map<String, String> TOOL_MAP = new HashMap<>();
    private static final Pattern VALID_HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$");
    
    static {
        TOOL_MAP.put("ping", "ping -c 4");
        TOOL_MAP.put("traceroute", "traceroute");
        TOOL_MAP.put("nslookup", "nslookup");
    }
    
    @GetMapping("/network-tool-safe")
    public String runNetworkTool(@RequestParam String tool, @RequestParam String host) {
        // Validate tool
        if (!TOOL_MAP.containsKey(tool)) {
            return "Invalid tool specified";
        }
        
        // Validate host
        if (!VALID_HOST_PATTERN.matcher(host).matches()) {
            return "Invalid hostname format";
        }
        
        try {
            List<String> commandParts = new ArrayList<>();
            commandParts.add("bash");
            commandParts.add("-c");
            commandParts.add(TOOL_MAP.get(tool) + " " + host);
            
            // ok: java-os-command-injection
            Process process = new ProcessBuilder(commandParts).start();
            
            process.waitFor(10, TimeUnit.SECONDS);
            InputStream is = process.getInputStream();
            String output = IOUtils.toString(is, StandardCharsets.UTF_8);
            
            return output;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class good_case_12 {
    private static final Map<String, String[]> COMMAND_MAP = new HashMap<>();
    
    static {
        COMMAND_MAP.put("list", new String[]{"ls", "-la"});
        COMMAND_MAP.put("disk", new String[]{"df", "-h"});
        COMMAND_MAP.put("memory", new String[]{"free", "-m"});
        COMMAND_MAP.put("network", new String[]{"netstat", "-tuln"});
    }
    
    public String handleLambdaRequest(APIGatewayProxyRequestEvent event, Context context) {
        Map<String, String> queryParams = event.getQueryStringParameters();
        if (queryParams == null) {
            return "No parameters provided";
        }
        
        String commandKey = queryParams.get("cmd");
        
        if (!COMMAND_MAP.containsKey(commandKey)) {
            return "Command not allowed";
        }
        
        try {
            // ok: java-os-command-injection
            Process process = new ProcessBuilder(COMMAND_MAP.get(commandKey)).start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class good_case_13 extends HttpServlet {
    private static final Map<String, String[]> COMMAND_MAP = new HashMap<>();
    
    static {
        COMMAND_MAP.put("dir", new String[]{"cmd.exe", "/c", "dir"});
        COMMAND_MAP.put("echo", new String[]{"cmd.exe", "/c", "echo", "Hello World"});
        COMMAND_MAP.put("time", new String[]{"cmd.exe", "/c", "time", "/t"});
    }
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String jsonBody = IOUtils.toString(request.getReader());
        String commandKey = extractCommandKeyFromJson(jsonBody);
        
        if (!COMMAND_MAP.containsKey(commandKey)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid command key");
            return;
        }
        
        try {
            // ok: java-os-command-injection
            Process process = new ProcessBuilder(COMMAND_MAP.get(commandKey)).start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            response.setContentType("text/plain");
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    private String extractCommandKeyFromJson(String json) {
        // Simple extraction, in real code would use a proper JSON parser
        if (json.contains("\"command\":")) {
            int start = json.indexOf("\"command\":") + 11;
            int end = json.indexOf("\"", start);
            return json.substring(start, end);
        }
        return "";
    }
}

class good_case_14 {
    private static final Map<String, String[]> SCRIPT_MAP = new HashMap<>();
    
    static {
        SCRIPT_MAP.put("backup", new String[]{"python", "backup.py"});
        SCRIPT_MAP.put("report", new String[]{"python", "report.py"});
        SCRIPT_MAP.put("analyze", new String[]{"python", "analyze.py"});
    }
    
    public void handleSparkRequest() {
        Spark.post("/run-script-safe", (req, res) -> {
            String scriptKey = req.queryParams("script");
            String args = req.queryParams("args");
            
            if (!SCRIPT_MAP.containsKey(scriptKey)) {
                return "Invalid script key";
            }
            
            // Validate args with regex
            if (args != null && !args.matches("^[a-zA-Z0-9_\\-. ]+$")) {
                return "Invalid arguments format";
            }
            
            try {
                List<String> command = new ArrayList<>(Arrays.asList(SCRIPT_MAP.get(scriptKey)));
                if (args != null && !args.isEmpty()) {
                    command.addAll(Arrays.asList(args.split(" ")));
                }
                
                // ok: java-os-command-injection
                Process process = new ProcessBuilder(command).start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                
                return output.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
    }
}

class good_case_15 {
    private static final Pattern VALID_HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$");
    
    public String handleHttpRequest(HttpServletRequest request) {
        try {
            String host = request.getParameter("host");
            
            // Validate host format
            if (!VALID_HOST_PATTERN.matcher(host).matches()) {
                return "Invalid hostname format";
            }
            
            List<String> command = new ArrayList<>();
            command.add("/bin/sh");
            command.add("-c");
            command.add("nslookup " + host);
            
            // ok: java-os-command-injection
            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}