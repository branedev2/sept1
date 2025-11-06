import java.io.*;
import java.util.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.exec.*;
import org.apache.commons.io.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.jcraft.jsch.*;
import org.zeroturnaround.exec.*;
import groovy.lang.GroovyShell;
import org.python.util.PythonInterpreter;
import com.google.cloud.functions.*;
import com.azure.core.http.*;
import com.azure.core.http.rest.*;
import com.microsoft.azure.functions.*;
import com.microsoft.azure.functions.annotation.*;
import org.apache.commons.lang3.StringEscapeUtils;
import org.owasp.encoder.Encode;
import java.util.regex.Pattern;
import java.util.concurrent.TimeUnit;

// Security Issue: OS Command Injection through various Java libraries and frameworks

// True Positive Examples (Vulnerable/Insecure Code)

@Controller
public class OsCommandInjectionExamples {

    // Example 1: Using Runtime.exec with user input from Spring MVC
// {fact rule=os-command-injection@v1.0 defects=1}
    @RequestMapping("/bad1")
    @ResponseBody
    public String bad_case_1(@RequestParam String command) {
        try {
            // ruleid: java-os-command-injection-exp
            Process process = Runtime.getRuntime().exec("ls " + command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 2: Using ProcessBuilder with user input from Servlet API
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("filename");
        List<String> commands = new ArrayList<>();
        commands.add("find");
        commands.add("/tmp");
        commands.add("-name");
        // ruleid: java-os-command-injection-exp
        commands.add(userInput);
        
        ProcessBuilder pb = new ProcessBuilder(commands);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        PrintWriter out = response.getWriter();
        while ((line = reader.readLine()) != null) {
            out.println(line);
        }
    }

    // Example 3: Using Apache Commons Exec with user input from Spring REST
    @PostMapping("/execute")
    public ResponseEntity<String> bad_case_3(@RequestBody Map<String, String> payload) {
        String command = payload.get("command");
        CommandLine cmdLine = CommandLine.parse("grep");
        // ruleid: java-os-command-injection-exp
        cmdLine.addArgument(command);
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
        
        DefaultExecutor executor = new DefaultExecutor();
        executor.setStreamHandler(streamHandler);
        
        try {
            executor.execute(cmdLine);
            return ResponseEntity.ok(outputStream.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    // Example 4: Using JSch (SSH) with user input from Spring RequestParam
    @GetMapping("/ssh")
    public String bad_case_4(@RequestParam String command) {
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("user", "host", 22);
            session.setPassword("password");
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            Channel channel = session.openChannel("exec");
            // ruleid: java-os-command-injection-exp
            ((ChannelExec) channel).setCommand("ls " + command);
            
            channel.setInputStream(null);
            InputStream output = channel.getInputStream();
            channel.connect();
            
            StringBuilder result = new StringBuilder();
            byte[] tmp = new byte[1024];
            while (true) {
                while (output.available() > 0) {
                    int i = output.read(tmp, 0, 1024);
                    if (i < 0) break;
                    result.append(new String(tmp, 0, i));
                }
                if (channel.isClosed()) break;
            }
            
            channel.disconnect();
            session.disconnect();
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 5: Using ZeroTurnaround's Process Executor with user input from HTTP headers
    @GetMapping("/process")
    public String bad_case_5(@RequestHeader("X-Command") String command) {
        try {
            // ruleid: java-os-command-injection-exp
            String output = new ProcessExecutor().command("bash", "-c", command)
                    .readOutput(true).execute()
                    .outputUTF8();
            return output;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 6: Using Groovy Shell with user input from Spring PathVariable
    @GetMapping("/groovy/{script}")
    public String bad_case_6(@PathVariable String script) {
        GroovyShell shell = new GroovyShell();
        // ruleid: java-os-command-injection-exp
        Object result = shell.evaluate("\"${Runtime.getRuntime().exec('" + script + "').text}\"");
        return result.toString();
    }

    // Example 7: Using Jython with user input from Spring RequestParam
    @GetMapping("/python")
    public String bad_case_7(@RequestParam String pyCommand) {
        PythonInterpreter interpreter = new PythonInterpreter();
        // ruleid: java-os-command-injection-exp
        interpreter.exec("import os; result = os.popen('" + pyCommand + "').read()");
        String result = interpreter.get("result").toString();
        return result;
    }

    // Example 8: AWS Lambda function with API Gateway input
    public static class LambdaHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            String command = input.getQueryStringParameters().get("cmd");
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            
            try {
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                String output = IOUtils.toString(process.getInputStream(), "UTF-8");
                response.setStatusCode(200);
                response.setBody(output);
            } catch (Exception e) {
                response.setStatusCode(500);
                response.setBody("Error: " + e.getMessage());
            }
            
            return response;
        }
    }

    // Example 9: Google Cloud Function with HTTP request
    public static class CloudFunction implements HttpFunction {
        @Override
        public void service(HttpRequest request, HttpResponse response) throws Exception {
            String command = request.getFirstQueryParameter("cmd").orElse("");
            
            try {
                // ruleid: java-os-command-injection-exp
                Process process = new ProcessBuilder("bash", "-c", command).start();
                String output = IOUtils.toString(process.getInputStream(), "UTF-8");
                response.getWriter().write(output);
            } catch (Exception e) {
                response.setStatusCode(500);
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
    }

    // Example 10: Azure Functions with HTTP trigger
    public static class AzureFunction {
        @FunctionName("commandExecutor")
        public HttpResponseMessage run(
                @HttpTrigger(name = "req", methods = {"get", "post"}, authLevel = AuthorizationLevel.ANONYMOUS) 
                HttpRequestMessage<Optional<String>> request,
                final ExecutionContext context) {
            
            String command = request.getQueryParameters().get("cmd");
            
            try {
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return request.createResponseBuilder(HttpStatus.OK).body(output.toString()).build();
            } catch (Exception e) {
                return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error: " + e.getMessage()).build();
            }
        }
    }

    // Example 11: Using Apache HttpClient to execute commands based on HTTP response
    @GetMapping("/http-client")
    public String bad_case_11(@RequestParam String url) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            String responseBody = httpClient.execute(request, response -> {
                String command = EntityUtils.toString(response.getEntity());
                // ruleid: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return output.toString();
            });
            return responseBody;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 12: Using Java NIO with user input from HTTP request
    @PostMapping("/nio-exec")
    public String bad_case_12(@RequestBody Map<String, String> payload) {
        String command = payload.get("command");
        try {
            // ruleid: java-os-command-injection-exp
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            Process p = pb.start();
            
            java.nio.file.Path outputPath = java.nio.file.Files.createTempFile("output", ".txt");
            pb.redirectOutput(outputPath.toFile());
            p.waitFor(10, TimeUnit.SECONDS);
            
            String content = new String(java.nio.file.Files.readAllBytes(outputPath));
            java.nio.file.Files.delete(outputPath);
            return content;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 13: Using Java ServiceLoader with command from HTTP request
    @GetMapping("/service-exec")
    public String bad_case_13(HttpServletRequest request) {
        String command = request.getParameter("cmd");
        try {
            // Create a temporary service file with the command
            File tempDir = new File(System.getProperty("java.io.tmpdir"));
            File serviceFile = new File(tempDir, "command.sh");
            FileWriter writer = new FileWriter(serviceFile);
            writer.write("#!/bin/sh\n");
            // ruleid: java-os-command-injection-exp
            writer.write(command);
            writer.close();
            serviceFile.setExecutable(true);
            
            // Execute the service file
            Process process = Runtime.getRuntime().exec(serviceFile.getAbsolutePath());
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            serviceFile.delete();
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 14: Using Java Reflection to execute commands from HTTP request
    @GetMapping("/reflection-exec")
    public String bad_case_14(@RequestParam String className, @RequestParam String methodName, 
                             @RequestParam String command) {
        try {
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            
            // ruleid: java-os-command-injection-exp
            Method method = clazz.getMethod(methodName, String.class);
            String result = (String) method.invoke(instance, "sh -c " + command);
            
            return result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 15: Using Java ScriptEngine to execute commands from HTTP request
    @GetMapping("/script-exec")
    public String bad_case_15(@RequestParam String script) {
        try {
            javax.script.ScriptEngineManager manager = new javax.script.ScriptEngineManager();
            javax.script.ScriptEngine engine = manager.getEngineByName("js");
            
            // ruleid: java-os-command-injection-exp
            String command = "var result = Java.type('java.lang.Runtime').getRuntime().exec('" + script + "');" +
                             "var reader = new Java.type('java.io.BufferedReader')(new Java.type('java.io.InputStreamReader')(result.getInputStream()));" +
                             "var line; var output = '';" +
                             "while ((line = reader.readLine()) !== null) { output += line + '\\n'; }" +
                             "output;";
            
            Object result = engine.eval(command);
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Example 1: Using Runtime.exec with validated input from Spring MVC
    @RequestMapping("/good1")
    @ResponseBody
    public String good_case_1(@RequestParam String command) {
        try {
            // Validate input against a whitelist
            List<String> allowedCommands = Arrays.asList("ls", "pwd", "date");
            if (!allowedCommands.contains(command)) {
                return "Command not allowed";
            }
            
            // ok: java-os-command-injection-exp
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 2: Using ProcessBuilder with sanitized input from Servlet API
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("filename");
        
        // Sanitize input - only allow alphanumeric and some special characters
        if (!Pattern.matches("[a-zA-Z0-9_\\-\\.]+", userInput)) {
            response.getWriter().println("Invalid filename");
            return;
        }
        
        List<String> commands = new ArrayList<>();
        commands.add("find");
        commands.add("/tmp");
        commands.add("-name");
        // ok: java-os-command-injection-exp
        commands.add(userInput);
        
        ProcessBuilder pb = new ProcessBuilder(commands);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        PrintWriter out = response.getWriter();
        while ((line = reader.readLine()) != null) {
            out.println(line);
        }
    }

    // Example 3: Using Apache Commons Exec with command arguments array instead of string concatenation
    @PostMapping("/execute-safe")
    public ResponseEntity<String> good_case_3(@RequestBody Map<String, String> payload) {
        String pattern = payload.get("pattern");
        
        // Validate input
        if (!Pattern.matches("[a-zA-Z0-9_\\-\\.]+", pattern)) {
            return ResponseEntity.badRequest().body("Invalid pattern");
        }
        
        CommandLine cmdLine = new CommandLine("grep");
        // ok: java-os-command-injection-exp
        cmdLine.addArgument(pattern, false);  // false means don't handle quoting
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
        
        DefaultExecutor executor = new DefaultExecutor();
        executor.setStreamHandler(streamHandler);
        
        try {
            executor.execute(cmdLine);
            return ResponseEntity.ok(outputStream.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    // Example 4: Using JSch (SSH) with parameterized commands and validation
    @GetMapping("/ssh-safe")
    public String good_case_4(@RequestParam String filename) {
        // Validate filename
        if (!Pattern.matches("[a-zA-Z0-9_\\-\\.]+", filename)) {
            return "Invalid filename";
        }
        
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("user", "host", 22);
            session.setPassword("password");
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            Channel channel = session.openChannel("exec");
            // ok: java-os-command-injection-exp
            ((ChannelExec) channel).setCommand("ls -la " + Encode.forCommandLine(filename));
            
            channel.setInputStream(null);
            InputStream output = channel.getInputStream();
            channel.connect();
            
            StringBuilder result = new StringBuilder();
            byte[] tmp = new byte[1024];
            while (true) {
                while (output.available() > 0) {
                    int i = output.read(tmp, 0, 1024);
                    if (i < 0) break;
                    result.append(new String(tmp, 0, i));
                }
                if (channel.isClosed()) break;
            }
            
            channel.disconnect();
            session.disconnect();
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 5: Using ZeroTurnaround's Process Executor with validated input
    @GetMapping("/process-safe")
    public String good_case_5(@RequestHeader("X-Command") String command) {
        // Whitelist of allowed commands
        Map<String, String[]> allowedCommands = new HashMap<>();
        allowedCommands.put("list", new String[]{"ls", "-la"});
        allowedCommands.put("date", new String[]{"date"});
        allowedCommands.put("pwd", new String[]{"pwd"});
        
        if (!allowedCommands.containsKey(command)) {
            return "Command not allowed";
        }
        
        try {
            // ok: java-os-command-injection-exp
            String output = new ProcessExecutor().command(allowedCommands.get(command))
                    .readOutput(true).execute()
                    .outputUTF8();
            return output;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 6: Using Groovy Shell with safe execution strategy
    @GetMapping("/groovy-safe/{operation}")
    public String good_case_6(@PathVariable String operation, @RequestParam String value) {
        // Validate operation
        if (!Pattern.matches("[a-zA-Z]+", operation)) {
            return "Invalid operation";
        }
        
        // Validate value
        if (!Pattern.matches("[0-9]+", value)) {
            return "Invalid value";
        }
        
        GroovyShell shell = new GroovyShell();
        // ok: java-os-command-injection-exp
        Object result = shell.evaluate("def " + operation + "(x) { return x.toInteger() * 2 }; " + operation + "(" + value + ")");
        return result.toString();
    }

    // Example 7: Using Jython with safe execution strategy
    @GetMapping("/python-safe")
    public String good_case_7(@RequestParam String operation, @RequestParam int value) {
        // Validate operation
        List<String> allowedOperations = Arrays.asList("square", "double", "half");
        if (!allowedOperations.contains(operation)) {
            return "Operation not allowed";
        }
        
        PythonInterpreter interpreter = new PythonInterpreter();
        // Define safe operations
        interpreter.exec(
            "def square(x): return x * x\n" +
            "def double(x): return x * 2\n" +
            "def half(x): return x / 2\n"
        );
        
        // ok: java-os-command-injection-exp
        interpreter.exec("result = " + operation + "(" + value + ")");
        String result = interpreter.get("result").toString();
        return result;
    }

    // Example 8: AWS Lambda function with API Gateway input - safe version
    public static class SafeLambdaHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            String command = input.getQueryStringParameters().get("cmd");
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            
            // Validate command against whitelist
            Map<String, String[]> allowedCommands = new HashMap<>();
            allowedCommands.put("list", new String[]{"ls", "-la"});
            allowedCommands.put("date", new String[]{"date"});
            
            if (!allowedCommands.containsKey(command)) {
                response.setStatusCode(400);
                response.setBody("Command not allowed");
                return response;
            }
            
            try {
                // ok: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(allowedCommands.get(command));
                String output = IOUtils.toString(process.getInputStream(), "UTF-8");
                response.setStatusCode(200);
                response.setBody(output);
            } catch (Exception e) {
                response.setStatusCode(500);
                response.setBody("Error: " + e.getMessage());
            }
            
            return response;
        }
    }

    // Example 9: Google Cloud Function with HTTP request - safe version
    public static class SafeCloudFunction implements HttpFunction {
        @Override
        public void service(HttpRequest request, HttpResponse response) throws Exception {
            String operation = request.getFirstQueryParameter("operation").orElse("");
            
            // Validate operation
            Map<String, String[]> allowedOperations = new HashMap<>();
            allowedOperations.put("list", new String[]{"ls", "-la"});
            allowedOperations.put("date", new String[]{"date"});
            allowedOperations.put("pwd", new String[]{"pwd"});
            
            if (!allowedOperations.containsKey(operation)) {
                response.setStatusCode(400);
                response.getWriter().write("Operation not allowed");
                return;
            }
            
            try {
                // ok: java-os-command-injection-exp
                Process process = new ProcessBuilder(allowedOperations.get(operation)).start();
                String output = IOUtils.toString(process.getInputStream(), "UTF-8");
                response.getWriter().write(output);
            } catch (Exception e) {
                response.setStatusCode(500);
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
    }

    // Example 10: Azure Functions with HTTP trigger - safe version
    public static class SafeAzureFunction {
        @FunctionName("safeCommandExecutor")
        public HttpResponseMessage run(
                @HttpTrigger(name = "req", methods = {"get", "post"}, authLevel = AuthorizationLevel.ANONYMOUS) 
                HttpRequestMessage<Optional<String>> request,
                final ExecutionContext context) {
            
            String command = request.getQueryParameters().get("cmd");
            
            // Validate command against whitelist
            Map<String, String[]> allowedCommands = new HashMap<>();
            allowedCommands.put("list", new String[]{"ls", "-la"});
            allowedCommands.put("date", new String[]{"date"});
            
            if (!allowedCommands.containsKey(command)) {
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                        .body("Command not allowed").build();
            }
            
            try {
                // ok: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(allowedCommands.get(command));
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return request.createResponseBuilder(HttpStatus.OK).body(output.toString()).build();
            } catch (Exception e) {
                return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error: " + e.getMessage()).build();
            }
        }
    }

    // Example 11: Using Apache HttpClient to execute commands safely based on HTTP response
    @GetMapping("/http-client-safe")
    public String good_case_11(@RequestParam String url) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            String responseBody = httpClient.execute(request, response -> {
                String command = EntityUtils.toString(response.getEntity());
                
                // Validate command against whitelist
                Map<String, String[]> allowedCommands = new HashMap<>();
                allowedCommands.put("list", new String[]{"ls", "-la"});
                allowedCommands.put("date", new String[]{"date"});
                
                if (!allowedCommands.containsKey(command)) {
                    return "Command not allowed";
                }
                
                // ok: java-os-command-injection-exp
                Process process = Runtime.getRuntime().exec(allowedCommands.get(command));
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return output.toString();
            });
            return responseBody;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 12: Using Java NIO with validated user input from HTTP request
    @PostMapping("/nio-exec-safe")
    public String good_case_12(@RequestBody Map<String, String> payload) {
        String command = payload.get("command");
        
        // Validate command against whitelist
        Map<String, String[]> allowedCommands = new HashMap<>();
        allowedCommands.put("list", new String[]{"ls", "-la"});
        allowedCommands.put("date", new String[]{"date"});
        
        if (!allowedCommands.containsKey(command)) {
            return "Command not allowed";
        }
        
        try {
            // ok: java-os-command-injection-exp
            ProcessBuilder pb = new ProcessBuilder(allowedCommands.get(command));
            Process p = pb.start();
            
            java.nio.file.Path outputPath = java.nio.file.Files.createTempFile("output", ".txt");
            pb.redirectOutput(outputPath.toFile());
            p.waitFor(10, TimeUnit.SECONDS);
            
            String content = new String(java.nio.file.Files.readAllBytes(outputPath));
            java.nio.file.Files.delete(outputPath);
            return content;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 13: Using Java ServiceLoader with validated command from HTTP request
    @GetMapping("/service-exec-safe")
    public String good_case_13(HttpServletRequest request) {
        String command = request.getParameter("cmd");
        
        // Validate command against whitelist
        Map<String, String> allowedCommands = new HashMap<>();
        allowedCommands.put("list", "ls -la");
        allowedCommands.put("date", "date");
        
        if (!allowedCommands.containsKey(command)) {
            return "Command not allowed";
        }
        
        try {
            // Create a temporary service file with the validated command
            File tempDir = new File(System.getProperty("java.io.tmpdir"));
            File serviceFile = new File(tempDir, "command.sh");
            FileWriter writer = new FileWriter(serviceFile);
            writer.write("#!/bin/sh\n");
            // ok: java-os-command-injection-exp
            writer.write(allowedCommands.get(command));
            writer.close();
            serviceFile.setExecutable(true);
            
            // Execute the service file
            Process process = Runtime.getRuntime().exec(serviceFile.getAbsolutePath());
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            serviceFile.delete();
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 14: Using Java Reflection to execute commands safely from HTTP request
    @GetMapping("/reflection-exec-safe")
    public String good_case_14(@RequestParam String className, @RequestParam String methodName, 
                             @RequestParam String command) {
        try {
            // Validate command against whitelist
            Map<String, String> allowedCommands = new HashMap<>();
            allowedCommands.put("list", "ls -la");
            allowedCommands.put("date", "date");
            
            if (!allowedCommands.containsKey(command)) {
                return "Command not allowed";
            }
            
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            
            // ok: java-os-command-injection-exp
            Method method = clazz.getMethod(methodName, String.class);
            String result = (String) method.invoke(instance, allowedCommands.get(command));
            
            return result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 15: Using Java ScriptEngine to execute commands safely from HTTP request
    @GetMapping("/script-exec-safe")
    public String good_case_15(@RequestParam String operation) {
        try {
            // Validate operation against whitelist
            Map<String, String> allowedOperations = new HashMap<>();
            allowedOperations.put("date", "new java.util.Date().toString()");
            allowedOperations.put("random", "Math.random()");
            allowedOperations.put("uuid", "java.util.UUID.randomUUID().toString()");
            
            if (!allowedOperations.containsKey(operation)) {
                return "Operation not allowed";
            }
            
            javax.script.ScriptEngineManager manager = new javax.script.ScriptEngineManager();
            javax.script.ScriptEngine engine = manager.getEngineByName("js");
            
            // ok: java-os-command-injection-exp
            Object result = engine.eval(allowedOperations.get(operation));
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
// {/fact}