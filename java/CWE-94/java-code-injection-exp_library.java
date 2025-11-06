import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.jexl3.*;
import org.mvel2.MVEL;
import org.codehaus.groovy.control.CompilerConfiguration;
import groovy.lang.GroovyShell;
import groovy.lang.Binding;
import org.python.util.PythonInterpreter;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import com.googlecode.aviator.AviatorEvaluator;
import bsh.Interpreter;
import org.apache.commons.el.ExpressionEvaluatorImpl;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;
import javax.el.ELContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.apache.commons.lang3.StringUtils;

// Security Issue: Code Injection through dynamic evaluation of user-controlled input

// True Positive Examples (Vulnerable/Insecure Code)

public class CodeInjectionExamples {

    // Using javax.script.ScriptEngine to evaluate user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String userScript = request.getParameter("script");
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            // ruleid: java-code-injection-exp
            Object result = engine.eval(userScript);
            System.out.println("Result: " + result);
        } catch (ScriptException e) {
            e.printStackTrace();
        }
    }

    // Using JEXL to evaluate expressions from HTTP input
    public void bad_case_2(HttpServletRequest request) {
        String userExpression = request.getParameter("expr");
        JexlEngine jexl = new JexlBuilder().create();
        JexlExpression expression = jexl.createExpression(userExpression);
        JexlContext context = new MapContext();
        
        // ruleid: java-code-injection-exp
        Object result = expression.evaluate(context);
        System.out.println("JEXL Result: " + result);
    }

    // Using MVEL to evaluate user-provided expressions
    public void bad_case_3(HttpServletRequest request) {
        String userExpression = request.getParameter("mvelExpr");
        Map<String, Object> vars = new HashMap<>();
        vars.put("name", "user");
        
        // ruleid: java-code-injection-exp
        Object result = MVEL.eval(userExpression, vars);
        System.out.println("MVEL Result: " + result);
    }

    // Using GroovyShell to evaluate user input
    public void bad_case_4(HttpServletRequest request) {
        String userScript = request.getParameter("groovyScript");
        Binding binding = new Binding();
        binding.setVariable("x", 10);
        GroovyShell shell = new GroovyShell(binding);
        
        // ruleid: java-code-injection-exp
        Object result = shell.evaluate(userScript);
        System.out.println("Groovy Result: " + result);
    }

    // Using Jython to evaluate Python code from user input
    public void bad_case_5(HttpServletRequest request) {
        String pythonCode = request.getParameter("pythonCode");
        PythonInterpreter interpreter = new PythonInterpreter();
        
        // ruleid: java-code-injection-exp
        interpreter.exec(pythonCode);
        System.out.println("Python code executed");
    }

    // Using Rhino JavaScript engine with direct user input
    public void bad_case_6(HttpServletRequest request) {
        String jsCode = request.getParameter("jsCode");
        Context context = Context.enter();
        try {
            Scriptable scope = context.initStandardObjects();
            
            // ruleid: java-code-injection-exp
            Object result = context.evaluateString(scope, jsCode, "UserScript", 1, null);
            System.out.println("JS Result: " + result);
        } finally {
            Context.exit();
        }
    }

    // Using Spring Expression Language (SpEL) with user input
    public void bad_case_7(HttpServletRequest request) {
        String spelExpr = request.getParameter("spelExpr");
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("user", "admin");
        
        // ruleid: java-code-injection-exp
        Expression exp = parser.parseExpression(spelExpr);
        Object result = exp.getValue(context);
        System.out.println("SpEL Result: " + result);
    }

    // Using Aviator expression engine with user input
    public void bad_case_8(HttpServletRequest request) {
        String aviatorExpr = request.getParameter("aviatorExpr");
        Map<String, Object> env = new HashMap<>();
        env.put("x", 100);
        
        // ruleid: java-code-injection-exp
        Object result = AviatorEvaluator.execute(aviatorExpr, env);
        System.out.println("Aviator Result: " + result);
    }

    // Using BeanShell interpreter with user input
    public void bad_case_9(HttpServletRequest request) {
        String bshScript = request.getParameter("bshScript");
        try {
            Interpreter interpreter = new Interpreter();
            interpreter.set("x", 42);
            
            // ruleid: java-code-injection-exp
            Object result = interpreter.eval(bshScript);
            System.out.println("BeanShell Result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Using EL (Expression Language) evaluator with user input
    public void bad_case_10(HttpServletRequest request) {
        String elExpr = request.getParameter("elExpr");
        try {
            ExpressionEvaluatorImpl evaluator = new ExpressionEvaluatorImpl();
            
            // ruleid: java-code-injection-exp
            Object result = evaluator.evaluate(elExpr, Object.class, null, null);
            System.out.println("EL Result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Using JSR-223 for Groovy script evaluation with user input
    public void bad_case_11(HttpServletRequest request) {
        String groovyCode = request.getParameter("groovyCode");
        try {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("groovy");
            
            // ruleid: java-code-injection-exp
            Object result = engine.eval(groovyCode);
            System.out.println("Groovy JSR-223 Result: " + result);
        } catch (ScriptException e) {
            e.printStackTrace();
        }
    }

    // Using JSP EL with user input
    public void bad_case_12(HttpServletRequest request) {
        String elExpr = request.getParameter("jspEl");
        try {
            ExpressionFactory factory = ExpressionFactory.newInstance();
            ELContext context = new javax.el.StandardELContext(factory);
            
            // ruleid: java-code-injection-exp
            ValueExpression valueExpression = factory.createValueExpression(context, "${" + elExpr + "}", Object.class);
            Object result = valueExpression.getValue(context);
            System.out.println("JSP EL Result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Using RestTemplate to fetch and evaluate a script
    public void bad_case_13(HttpServletRequest request) {
        String scriptUrl = request.getParameter("scriptUrl");
        try {
            RestTemplate restTemplate = new RestTemplate();
            String fetchedScript = restTemplate.getForObject(scriptUrl, String.class);
            
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            // ruleid: java-code-injection-exp
            Object result = engine.eval(fetchedScript);
            System.out.println("Fetched Script Result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Using OkHttp to fetch and evaluate a script
    public void bad_case_14(HttpServletRequest request) {
        String scriptUrl = request.getParameter("scriptUrl");
        try {
            OkHttpClient client = new OkHttpClient();
            Request okRequest = new Request.Builder()
                .url(scriptUrl)
                .build();
                
            try (Response response = client.newCall(okRequest).execute()) {
                String fetchedScript = response.body().string();
                
                ScriptEngineManager manager = new ScriptEngineManager();
                ScriptEngine engine = manager.getEngineByName("JavaScript");
                
                // ruleid: java-code-injection-exp
                Object result = engine.eval(fetchedScript);
                System.out.println("OkHttp Fetched Script Result: " + result);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Using Java 11 HttpClient to fetch and evaluate a script
    public void bad_case_15(HttpServletRequest request) {
        String scriptUrl = request.getParameter("scriptUrl");
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(scriptUrl))
                .build();
                
            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            String fetchedScript = response.body();
            
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            // ruleid: java-code-injection-exp
            Object result = engine.eval(fetchedScript);
            System.out.println("Java 11 HttpClient Fetched Script Result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Using ScriptEngine with whitelisted expressions
    public void good_case_1(HttpServletRequest request) {
        try {
            String userScript = request.getParameter("script");
            // Whitelist of allowed expressions
            List<String> allowedScripts = List.of("1+1", "Math.max(5,10)", "new Date().getTime()");
            
            if (allowedScripts.contains(userScript)) {
                ScriptEngineManager manager = new ScriptEngineManager();
                ScriptEngine engine = manager.getEngineByName("JavaScript");
                
                // ok: java-code-injection-exp
                Object result = engine.eval(userScript);
                System.out.println("Safe Result: " + result);
            } else {
                System.out.println("Script not allowed");
            }
        } catch (ScriptException e) {
            e.printStackTrace();
        }
    }

    // Using JEXL with sanitized input
    public void good_case_2(HttpServletRequest request) {
        String userExpression = request.getParameter("expr");
        // Only allow alphanumeric characters and basic math operators
        if (Pattern.matches("[a-zA-Z0-9+\\-*/()\\s.]*", userExpression)) {
            JexlEngine jexl = new JexlBuilder().create();
            JexlExpression expression = jexl.createExpression(userExpression);
            JexlContext context = new MapContext();
            
            // ok: java-code-injection-exp
            Object result = expression.evaluate(context);
            System.out.println("Safe JEXL Result: " + result);
        } else {
            System.out.println("Invalid expression");
        }
    }

    // Using MVEL with predefined templates
    public void good_case_3(HttpServletRequest request) {
        String templateId = request.getParameter("templateId");
        Map<String, String> templates = new HashMap<>();
        templates.put("greeting", "\"Hello \" + name");
        templates.put("calculation", "price * quantity");
        
        if (templates.containsKey(templateId)) {
            String safeExpression = templates.get(templateId);
            Map<String, Object> vars = new HashMap<>();
            vars.put("name", "user");
            vars.put("price", 10);
            vars.put("quantity", 5);
            
            // ok: java-code-injection-exp
            Object result = MVEL.eval(safeExpression, vars);
            System.out.println("Safe MVEL Result: " + result);
        } else {
            System.out.println("Template not found");
        }
    }

    // Using GroovyShell with CompilerConfiguration for sandboxing
    public void good_case_4(HttpServletRequest request) {
        String userScript = request.getParameter("groovyScript");
        
        // Create a secure compiler configuration
        CompilerConfiguration config = new CompilerConfiguration();
        // Disallow method definitions, imports, package definitions
        config.setScriptBaseClass("groovy.lang.Script");
        
        // Validate input before execution
        if (Pattern.matches("[a-zA-Z0-9+\\-*/()\\s.]*", userScript)) {
            Binding binding = new Binding();
            binding.setVariable("x", 10);
            GroovyShell shell = new GroovyShell(binding, config);
            
            // ok: java-code-injection-exp
            Object result = shell.evaluate(userScript);
            System.out.println("Safe Groovy Result: " + result);
        } else {
            System.out.println("Invalid Groovy script");
        }
    }

    // Using PythonInterpreter with restricted environment
    public void good_case_5(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        // Use a map of predefined safe operations
        Map<String, String> safeOperations = new HashMap<>();
        safeOperations.put("add", "result = a + b");
        safeOperations.put("subtract", "result = a - b");
        safeOperations.put("multiply", "result = a * b");
        
        if (safeOperations.containsKey(operation)) {
            String pythonCode = safeOperations.get(operation);
            PythonInterpreter interpreter = new PythonInterpreter();
            interpreter.set("a", 10);
            interpreter.set("b", 5);
            
            // ok: java-code-injection-exp
            interpreter.exec(pythonCode);
            System.out.println("Safe Python Result: " + interpreter.get("result"));
        } else {
            System.out.println("Operation not supported");
        }
    }

    // Using Rhino JavaScript engine with input validation
    public void good_case_6(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        String param1 = request.getParameter("param1");
        String param2 = request.getParameter("param2");
        
        // Validate inputs are numeric
        if (Pattern.matches("\\d+", param1) && Pattern.matches("\\d+", param2)) {
            // Construct a safe script
            String safeScript = "var a = " + param1 + "; var b = " + param2 + "; ";
            
            if ("add".equals(operation)) {
                safeScript += "a + b";
            } else if ("subtract".equals(operation)) {
                safeScript += "a - b";
            } else if ("multiply".equals(operation)) {
                safeScript += "a * b";
            } else {
                System.out.println("Unsupported operation");
                return;
            }
            
            Context context = Context.enter();
            try {
                Scriptable scope = context.initStandardObjects();
                
                // ok: java-code-injection-exp
                Object result = context.evaluateString(scope, safeScript, "SafeScript", 1, null);
                System.out.println("Safe JS Result: " + result);
            } finally {
                Context.exit();
            }
        } else {
            System.out.println("Invalid parameters");
        }
    }

    // Using Spring Expression Language (SpEL) with a whitelist approach
    public void good_case_7(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        
        // Whitelist of allowed operations
        Map<String, String> allowedExpressions = new HashMap<>();
        allowedExpressions.put("userGreeting", "'Hello, ' + #user");
        allowedExpressions.put("currentTime", "T(java.time.LocalTime).now()");
        allowedExpressions.put("randomNumber", "T(java.lang.Math).random()");
        
        if (allowedExpressions.containsKey(operation)) {
            String safeExpr = allowedExpressions.get(operation);
            ExpressionParser parser = new SpelExpressionParser();
            StandardEvaluationContext context = new StandardEvaluationContext();
            context.setVariable("user", "admin");
            
            // ok: java-code-injection-exp
            Expression exp = parser.parseExpression(safeExpr);
            Object result = exp.getValue(context);
            System.out.println("Safe SpEL Result: " + result);
        } else {
            System.out.println("Operation not allowed");
        }
    }

    // Using Aviator with input validation
    public void good_case_8(HttpServletRequest request) {
        String formula = request.getParameter("formula");
        
        // Validate formula contains only allowed characters
        if (Pattern.matches("[0-9x+\\-*/()\\s.]*", formula)) {
            Map<String, Object> env = new HashMap<>();
            env.put("x", 100);
            
            // ok: java-code-injection-exp
            Object result = AviatorEvaluator.execute(formula, env);
            System.out.println("Safe Aviator Result: " + result);
        } else {
            System.out.println("Invalid formula");
        }
    }

    // Using BeanShell with predefined commands
    public void good_case_9(HttpServletRequest request) {
        String commandId = request.getParameter("commandId");
        
        // Predefined safe commands
        Map<String, String> safeCommands = new HashMap<>();
        safeCommands.put("calculateArea", "return width * height;");
        safeCommands.put("formatName", "return firstName + \" \" + lastName;");
        
        if (safeCommands.containsKey(commandId)) {
            try {
                String safeScript = safeCommands.get(commandId);
                Interpreter interpreter = new Interpreter();
                interpreter.set("width", 10);
                interpreter.set("height", 20);
                interpreter.set("firstName", "John");
                interpreter.set("lastName", "Doe");
                
                // ok: java-code-injection-exp
                Object result = interpreter.eval(safeScript);
                System.out.println("Safe BeanShell Result: " + result);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Command not found");
        }
    }

    // Using EL (Expression Language) with parameter binding
    public void good_case_10(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        String value1Str = request.getParameter("value1");
        String value2Str = request.getParameter("value2");
        
        // Validate inputs are numeric
        if (Pattern.matches("\\d+", value1Str) && Pattern.matches("\\d+", value2Str)) {
            int value1 = Integer.parseInt(value1Str);
            int value2 = Integer.parseInt(value2Str);
            
            try {
                ExpressionEvaluatorImpl evaluator = new ExpressionEvaluatorImpl();
                Map<String, Object> context = new HashMap<>();
                context.put("a", value1);
                context.put("b", value2);
                
                String safeExpression;
                if ("add".equals(operation)) {
                    safeExpression = "${a + b}";
                } else if ("subtract".equals(operation)) {
                    safeExpression = "${a - b}";
                } else if ("multiply".equals(operation)) {
                    safeExpression = "${a * b}";
                } else {
                    System.out.println("Unsupported operation");
                    return;
                }
                
                // ok: java-code-injection-exp
                Object result = evaluator.evaluate(safeExpression, Object.class, resolver -> {
                    Object value = context.get(resolver.getExpressionString());
                    return value != null ? value : "";
                }, null);
                System.out.println("Safe EL Result: " + result);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid numeric inputs");
        }
    }

    // Using JSR-223 for Groovy with input sanitization
    public void good_case_11(HttpServletRequest request) {
        String input = request.getParameter("input");
        String operation = request.getParameter("operation");
        
        // Sanitize input
        String sanitizedInput = StringEscapeUtils.escapeJava(input);
        
        try {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("groovy");
            
            // Prepare safe script based on operation
            String safeScript;
            if ("uppercase".equals(operation)) {
                safeScript = "\"" + sanitizedInput + "\".toUpperCase()";
            } else if ("lowercase".equals(operation)) {
                safeScript = "\"" + sanitizedInput + "\".toLowerCase()";
            } else if ("length".equals(operation)) {
                safeScript = "\"" + sanitizedInput + "\".length()";
            } else {
                System.out.println("Unsupported operation");
                return;
            }
            
            // ok: java-code-injection-exp
            Object result = engine.eval(safeScript);
            System.out.println("Safe Groovy JSR-223 Result: " + result);
        } catch (ScriptException e) {
            e.printStackTrace();
        }
    }

    // Using JSP EL with safe predefined expressions
    public void good_case_12(HttpServletRequest request) {
        String expressionId = request.getParameter("expressionId");
        
        // Predefined safe expressions
        Map<String, String> safeExpressions = new HashMap<>();
        safeExpressions.put("currentDate", "${T(java.time.LocalDate).now()}");
        safeExpressions.put("randomUUID", "${T(java.util.UUID).randomUUID()}");
        
        if (safeExpressions.containsKey(expressionId)) {
            try {
                String safeExpr = safeExpressions.get(expressionId);
                ExpressionFactory factory = ExpressionFactory.newInstance();
                ELContext context = new javax.el.StandardELContext(factory);
                
                // ok: java-code-injection-exp
                ValueExpression valueExpression = factory.createValueExpression(context, safeExpr, Object.class);
                Object result = valueExpression.getValue(context);
                System.out.println("Safe JSP EL Result: " + result);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Expression not found");
        }
    }

    // Using RestTemplate with content validation before evaluation
    public void good_case_13(HttpServletRequest request) {
        String scriptUrl = request.getParameter("scriptUrl");
        // Whitelist of trusted URLs
        List<String> trustedUrls = List.of(
            "https://trusted-scripts.example.com/safe-script-1.js",
            "https://trusted-scripts.example.com/safe-script-2.js"
        );
        
        if (trustedUrls.contains(scriptUrl)) {
            try {
                RestTemplate restTemplate = new RestTemplate();
                String fetchedScript = restTemplate.getForObject(scriptUrl, String.class);
                
                // Validate content before execution
                if (isScriptSafe(fetchedScript)) {
                    ScriptEngineManager manager = new ScriptEngineManager();
                    ScriptEngine engine = manager.getEngineByName("JavaScript");
                    
                    // ok: java-code-injection-exp
                    Object result = engine.eval(fetchedScript);
                    System.out.println("Safe Fetched Script Result: " + result);
                } else {
                    System.out.println("Script content not safe");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("URL not trusted");
        }
    }

    // Using OkHttp with script signature verification
    public void good_case_14(HttpServletRequest request) {
        String scriptUrl = request.getParameter("scriptUrl");
        String expectedSignature = request.getParameter("signature");
        
        try {
            OkHttpClient client = new OkHttpClient();
            Request okRequest = new Request.Builder()
                .url(scriptUrl)
                .build();
                
            try (Response response = client.newCall(okRequest).execute()) {
                String fetchedScript = response.body().string();
                
                // Verify script signature (simplified example)
                String calculatedSignature = calculateSignature(fetchedScript);
                if (expectedSignature != null && expectedSignature.equals(calculatedSignature)) {
                    ScriptEngineManager manager = new ScriptEngineManager();
                    ScriptEngine engine = manager.getEngineByName("JavaScript");
                    
                    // ok: java-code-injection-exp
                    Object result = engine.eval(fetchedScript);
                    System.out.println("Safe OkHttp Verified Script Result: " + result);
                } else {
                    System.out.println("Script signature verification failed");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Using Java 11 HttpClient with content type verification and sandboxing
    public void good_case_15(HttpServletRequest request) {
        String scriptUrl = request.getParameter("scriptUrl");
        
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(scriptUrl))
                .build();
                
            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            
            // Verify content type
            String contentType = response.headers().firstValue("Content-Type").orElse("");
            if (contentType.contains("application/javascript")) {
                String fetchedScript = response.body();
                
                // Use a sandbox environment
                ScriptEngineManager manager = new ScriptEngineManager();
                ScriptEngine engine = manager.getEngineByName("JavaScript");
                
                // Set up sandbox restrictions
                engine.eval("var System = undefined; var java = undefined;");
                
                // ok: java-code-injection-exp
                Object result = engine.eval(fetchedScript);
                System.out.println("Safe Java 11 HttpClient Sandboxed Script Result: " + result);
            } else {
                System.out.println("Invalid content type");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper methods
    private boolean isScriptSafe(String script) {
        // Check for dangerous patterns
        String[] dangerousPatterns = {
            "System", "Runtime", "ProcessBuilder", "exec", "File", "delete", "rm", "format"
        };
        
        for (String pattern : dangerousPatterns) {
            if (script.contains(pattern)) {
                return false;
            }
        }
        return true;
    }
    
    private String calculateSignature(String content) {
        // Simplified example - in real world use proper cryptographic signature
        return String.valueOf(content.hashCode());
    }
}
// {/fact}